package proxy

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-test/deep"
	"github.com/miekg/dns"
)

func TestCacheSanity(t *testing.T) {
	testCache := cache{}
	request := dns.Msg{}
	request.SetQuestion("google.com.", dns.TypeA)
	val, expired, key := testCache.Get(&request)
	assert.Nil(t, val, "empty cache replied with positive response")
	assert.False(t, expired)
	assert.Nil(t, key)
}

func TestServeCached(t *testing.T) {
	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.CacheEnabled = true // just one request per second is allowed

	// Start listening
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// Fill the cache
	reply := dns.Msg{}
	reply.SetQuestion("google.com.", dns.TypeA)
	reply.Response = true
	reply.Answer = []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}
	reply.SetEdns0(defaultUDPBufSize, false)
	dnsProxy.cache.Set(&reply)

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	// Create a DNS request
	request := dns.Msg{}
	request.Id = dns.Id()
	request.RecursionDesired = true
	request.SetQuestion("google.com.", dns.TypeA)
	request.SetEdns0(defaultUDPBufSize, false)

	r, _, err := client.Exchange(&request, addr.String())
	if err != nil {
		t.Fatalf("error in the first request: %s", err)
	}

	if diff := deepEqualMsg(r, &reply); diff != nil {
		t.Error(diff)
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func TestCache_expired(t *testing.T) {
	const host = "google.com."

	ans := &dns.A{
		Hdr: dns.RR_Header{
			Name:   host,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
		},
		A: net.IP{8, 8, 8, 8},
	}
	reply := (&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response: true,
		},
		Answer: []dns.RR{ans},
	}).SetQuestion(host, dns.TypeA)

	testCases := []struct {
		name       string
		ttl        uint32
		wantTTL    uint32
		optimistic bool
	}{{
		name:       "realistic_hit",
		ttl:        defaultTestTTL,
		wantTTL:    defaultTestTTL,
		optimistic: false,
	}, {
		name:       "realistic_miss",
		ttl:        0,
		wantTTL:    0,
		optimistic: false,
	}, {
		name:       "optimistic_hit",
		ttl:        defaultTestTTL,
		wantTTL:    defaultTestTTL,
		optimistic: true,
	}, {
		name:       "optimistic_expired",
		ttl:        0,
		wantTTL:    optimisticTTL,
		optimistic: true,
	}}

	testCache := &cache{
		items: glcache.New(glcache.Config{
			MaxSize:   defaultCacheSize,
			EnableLRU: true,
		}),
	}
	for _, tc := range testCases {
		ans.Hdr.Ttl = tc.ttl
		req := (&dns.Msg{}).SetQuestion(host, dns.TypeA)

		t.Run(tc.name, func(t *testing.T) {
			if tc.optimistic {
				testCache.optimistic = true
			}
			t.Cleanup(func() { testCache.optimistic = false })

			key := msgToKey(reply)
			data := packResponse(reply)
			testCache.items.Set(key, data)
			t.Cleanup(testCache.items.Clear)

			r, expired, key := testCache.Get(req)
			assert.Equal(t, msgToKey(req), key)
			assert.Equal(t, tc.ttl == 0, expired)
			if tc.wantTTL != 0 {
				require.NotNil(t, r)

				assert.Equal(t, tc.wantTTL, r.Answer[0].Header().Ttl)
			} else {
				require.Nil(t, r)
			}
		})
	}
}

func TestCacheDO(t *testing.T) {
	testCache := &cache{}

	// Fill the cache
	reply := dns.Msg{}
	reply.SetQuestion("google.com.", dns.TypeA)
	reply.Response = true
	reply.SetEdns0(4096, true)
	reply.Answer = []dns.RR{
		newRR("google.com. 3600 IN A 8.8.8.8"),
	}

	// Store in cache
	testCache.Set(&reply)

	// Create a DNS request
	request := dns.Msg{}
	request.Id = dns.Id()
	request.RecursionDesired = true
	request.SetQuestion("google.com.", dns.TypeA)

	// Try requesting without DO.
	r, expired, key := testCache.Get(&request)
	assert.False(t, expired)
	assert.Equal(t, msgToKey(&request), key)
	assert.NotNil(t, r)

	// Now add DO and re-test.
	request.SetEdns0(4096, true)
	r, expired, key = testCache.Get(&request)
	assert.False(t, expired)
	assert.Equal(t, msgToKey(&request), key)
	assert.NotNil(t, r)
}

func TestCacheCNAME(t *testing.T) {
	testCache := &cache{}

	// Fill the cache
	reply := dns.Msg{}
	reply.SetQuestion("google.com.", dns.TypeA)
	reply.Response = true
	reply.Answer = []dns.RR{
		newRR("google.com. 3600 IN CNAME test.google.com."),
	}

	// Create a DNS request
	request := dns.Msg{}
	request.Id = dns.Id()
	request.RecursionDesired = true
	request.SetQuestion("google.com.", dns.TypeA)

	// We are testing that CNAME response with no A records is not cached
	testCache.Set(&reply)
	r, expired, key := testCache.Get(&request)
	assert.False(t, expired)
	assert.Nil(t, key)
	assert.Nil(t, r)

	// Now let's test a proper CNAME response

	// Fill the cache
	reply = dns.Msg{}
	reply.SetQuestion("google.com.", dns.TypeA)
	reply.Response = true
	reply.Answer = []dns.RR{
		newRR("google.com. 3600 IN CNAME test.google.com."),
		newRR("google.com. 3600 IN A 8.8.8.8"),
	}

	// We are testing that a proper CNAME response gets cached
	testCache.Set(&reply)
	r, expired, key = testCache.Get(&request)
	assert.False(t, expired)
	assert.Equal(t, key, msgToKey(&request))
	assert.NotNil(t, r)
}

func TestCacheSERVFAIL(t *testing.T) {
	testCache := &cache{}

	// Fill the cache
	reply := dns.Msg{}
	reply.SetQuestion("google.com.", dns.TypeA)
	reply.Response = true
	reply.Rcode = dns.RcodeServerFailure

	// Create a DNS request
	request := dns.Msg{}
	request.Id = dns.Id()
	request.RecursionDesired = true
	request.SetQuestion("google.com.", dns.TypeA)

	// We are testing that SERVFAIL responses aren't cached
	testCache.Set(&reply)
	r, expired, key := testCache.Get(&request)
	assert.False(t, expired)
	assert.Nil(t, key)
	assert.Nil(t, r)
}

func TestCacheRace(t *testing.T) {
	testCache := &cache{}

	hosts := make(map[string]string)
	hosts["yandex.com."] = "213.180.204.62"
	hosts["google.com."] = "8.8.8.8"
	hosts["www.google.com."] = "8.8.4.4"
	hosts["youtube.com."] = "173.194.221.198"
	hosts["car.ru."] = "37.220.161.35"
	hosts["cat.ru."] = "192.56.231.67"

	g := &sync.WaitGroup{}
	g.Add(len(hosts))
	for k, v := range hosts {
		go setAndGetCache(t, testCache, g, k, v)
	}

	g.Wait()
}

func TestCacheExpiration(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.CacheEnabled = true
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// Create dns messages with 1 second TTL
	googleReply := dns.Msg{}
	googleReply.SetQuestion("google.com.", dns.TypeA)
	googleReply.Response = true
	googleReply.Answer = []dns.RR{newRR("google.com. 1 IN A 8.8.8.8")}

	yandexReply := dns.Msg{}
	yandexReply.SetQuestion("yandex.com.", dns.TypeA)
	yandexReply.Response = true
	yandexReply.Answer = []dns.RR{newRR("yandex.com. 1 IN A 213.180.204.62")}

	youtubeReply := dns.Msg{}
	youtubeReply.SetQuestion("youtube.com.", dns.TypeA)
	youtubeReply.Response = true
	youtubeReply.Answer = []dns.RR{newRR("youtube.com 1 IN A 173.194.221.198")}

	dnsProxy.cache.Set(&youtubeReply)
	dnsProxy.cache.Set(&googleReply)
	dnsProxy.cache.Set(&yandexReply)

	r, expired, key := dnsProxy.cache.Get(&youtubeReply)
	if diff := deepEqualMsg(r, &youtubeReply); diff != nil {
		t.Error(diff)
	}
	assert.False(t, expired)
	assert.Equal(t, msgToKey(&youtubeReply), key)

	r, expired, key = dnsProxy.cache.Get(&googleReply)
	if diff := deepEqualMsg(r, &googleReply); diff != nil {
		t.Error(diff)
	}
	assert.False(t, expired)
	assert.Equal(t, msgToKey(&googleReply), key)
	r, expired, key = dnsProxy.cache.Get(&yandexReply)
	if diff := deepEqualMsg(r, &yandexReply); diff != nil {
		t.Error(diff)
	}
	assert.False(t, expired)
	assert.Equal(t, msgToKey(&yandexReply), key)

	// Wait for cache items expiration
	time.Sleep(1100 * time.Millisecond)

	// Both messages should be already removed from the cache
	dnsProxy.cache.Get(&yandexReply)
	dnsProxy.cache.Get(&googleReply)

	// New answer with zero TTL
	yandexReply.Answer = []dns.RR{newRR("yandex.com. 0 IN A 213.180.204.62")}
	dnsProxy.cache.Set(&yandexReply)
	dnsProxy.cache.Get(&yandexReply)

	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func TestCacheExpirationWithTTLOverride(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.CacheEnabled = true
	dnsProxy.CacheMinTTL = 20
	dnsProxy.CacheMaxTTL = 40
	u := testUpstream{}
	dnsProxy.UpstreamConfig.Upstreams = []upstream.Upstream{&u}
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// 1st request with TTL=10 -> replaced with CacheMinTTL
	d := DNSContext{}
	d.Req = createHostTestMessage("host")
	d.Addr = &net.TCPAddr{}
	u.aResp = new(dns.A)
	u.aResp.Hdr.Rrtype = dns.TypeA
	u.aResp.Hdr.Name = "host."
	u.aResp.A = net.IP{4, 3, 2, 1}
	u.aResp.Hdr.Ttl = 10
	err = dnsProxy.Resolve(&d)
	assert.Nil(t, err)

	// get from cache - check min TTL
	r, expired, key := dnsProxy.cache.Get(d.Req)
	assert.False(t, expired)
	assert.Equal(t, msgToKey(d.Req), key)
	assert.Equal(t, dnsProxy.CacheMinTTL, r.Answer[0].Header().Ttl)

	// 2nd request with TTL=60 -> replaced with CacheMaxTTL
	d.Req = createHostTestMessage("host2")
	d.Addr = &net.TCPAddr{}
	u.aResp = new(dns.A)
	u.aResp.Hdr.Rrtype = dns.TypeA
	u.aResp.Hdr.Name = "host2."
	u.aResp.A = net.IP{4, 3, 2, 1}
	u.aResp.Hdr.Ttl = 60
	err = dnsProxy.Resolve(&d)
	assert.Nil(t, err)

	// get from cache - check max TTL
	r, expired, key = dnsProxy.cache.Get(d.Req)
	assert.False(t, expired)
	assert.Equal(t, msgToKey(d.Req), key)
	assert.Equal(t, dnsProxy.CacheMaxTTL, r.Answer[0].Header().Ttl)

	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func TestCache(t *testing.T) {
	tests := testCases{
		cache: []testEntry{
			{q: "google.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}},
		},
		cases: []testCase{
			{q: "google.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}, ok: true},
			{q: "google.com.", t: dns.TypeMX, ok: false},
		},
	}
	runTests(t, tests)
}

func TestCacheMixedCase(t *testing.T) {
	tests := testCases{
		cache: []testEntry{
			{q: "gOOgle.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}},
		},
		cases: []testCase{
			{q: "gOOgle.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}, ok: true},
			{q: "google.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}, ok: true},
			{q: "GOOGLE.COM.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}, ok: true},
			{q: "gOOgle.com.", t: dns.TypeMX, ok: false},
			{q: "google.com.", t: dns.TypeMX, ok: false},
			{q: "GOOGLE.COM.", t: dns.TypeMX, ok: false},
		},
	}
	runTests(t, tests)
}

func TestZeroTTL(t *testing.T) {
	tests := testCases{
		cache: []testEntry{
			{q: "gOOgle.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 0 IN A 8.8.8.8")}},
		},
		cases: []testCase{
			{q: "google.com.", t: dns.TypeA, ok: false},
			{q: "google.com.", t: dns.TypeA, ok: false},
			{q: "google.com.", t: dns.TypeA, ok: false},
			{q: "google.com.", t: dns.TypeMX, ok: false},
			{q: "google.com.", t: dns.TypeMX, ok: false},
			{q: "google.com.", t: dns.TypeMX, ok: false},
		},
	}
	runTests(t, tests)
}

func runTests(t *testing.T, tests testCases) {
	// t.Helper()
	testCache := cache{}
	for _, tc := range tests.cache {
		reply := dns.Msg{}
		reply.SetQuestion(tc.q, tc.t)
		reply.Response = true
		reply.Answer = tc.a
		testCache.Set(&reply)
	}
	for _, tc := range tests.cases {
		request := dns.Msg{}
		request.SetQuestion(tc.q, tc.t)
		val, expired, _ := testCache.Get(&request)
		assert.False(t, expired)
		require.Equal(t, tc.ok, val != nil)
		if tc.a != nil {
			if val == nil {
				continue
			}
			reply := dns.Msg{}
			reply.SetQuestion(tc.q, tc.t)
			reply.Response = true
			reply.Answer = tc.a
			testCache.Set(&reply)
			if diff := deepEqualMsg(val, &reply); diff != nil {
				t.Error(diff)
			} else {
				if diff := deep.Equal(val, reply); diff == nil {
					t.Error("different message ID were not caught")
				}
			}
		}
	}
}

type testCases struct {
	cache []testEntry
	cases []testCase
}

type testEntry struct {
	q string
	t uint16
	a []dns.RR
}

type testCase struct {
	q  string
	t  uint16
	a  []dns.RR
	ok bool
}

func newRR(rr string) dns.RR {
	r, err := dns.NewRR(rr)
	if err != nil {
		panic(err)
	}
	return r
}

// deepEqual is same as deep.Equal, except:
//  * ignores Id when comparing
//  * ignores Rdlength
//  * question names are not case sensitive
func deepEqualMsg(left *dns.Msg, right *dns.Msg) []string {
	temp := *left
	temp.Id = right.Id
	if len(temp.Answer) == 1 && len(right.Answer) == 1 {
		temp.Answer[0].Header().Rdlength = right.Answer[0].Header().Rdlength
	}
	for _, rr := range right.Answer {
		if a, ok := rr.(*dns.A); ok {
			if a.A.To4() != nil {
				a.A = a.A.To4()
			}
		}
	}
	for i := range left.Question {
		left.Question[i].Name = strings.ToLower(left.Question[i].Name)
	}
	for i := range right.Question {
		right.Question[i].Name = strings.ToLower(right.Question[i].Name)
	}
	return deep.Equal(&temp, right)
}

func setAndGetCache(t *testing.T, c *cache, g *sync.WaitGroup, host, ip string) {
	defer func() {
		g.Done()
	}()
	dnsMsg := dns.Msg{}
	dnsMsg.SetQuestion(host, dns.TypeA)
	dnsMsg.Response = true
	answer := fmt.Sprintf("%s 1 IN A %s", host, ip)
	dnsMsg.Answer = []dns.RR{newRR(answer)}
	c.Set(&dnsMsg)

	r, expired, key := c.Get(&dnsMsg)
	require.NotNil(t, r, "no cache found for %s", host)
	assert.False(t, expired)
	assert.Equal(t, msgToKey(&dnsMsg), key)
	if diff := deepEqualMsg(r, &dnsMsg); diff != nil {
		t.Error(diff)

		return
	}

	r, expired, key = c.Get(&dnsMsg)
	require.NotNil(t, r, "no cache found for %s", host)
	assert.False(t, expired)
	assert.Equal(t, msgToKey(&dnsMsg), key)
	if diff := deepEqualMsg(r, &dnsMsg); diff != nil {
		t.Error(diff)

		return
	}

	time.Sleep(1100 * time.Millisecond)
	r, _, _ = c.Get(&dnsMsg)
	require.Nil(t, r, "cache for %s should be already removed", host)
}

func TestSubnet(t *testing.T) {
	c := &cache{}
	var a *dns.A
	ip1234, ip2234, ip3234 := net.IP{1, 2, 3, 4}, net.IP{2, 2, 3, 4}, net.IP{3, 2, 3, 4}

	// search - not found
	req := dns.Msg{}
	req.SetQuestion("example.com.", dns.TypeA)
	resp, expired, key := c.GetWithSubnet(&req, ip1234, 24)
	assert.False(t, expired)
	assert.Nil(t, key)
	require.Nil(t, resp)

	// add a response entry with subnet
	resp = &dns.Msg{}
	resp.Response = true
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Answer = []dns.RR{newRR("example.com. 1 IN A 1.1.1.1")}
	c.SetWithSubnet(resp, ip1234, 16)

	// search for the entry (with another client IP) - not found
	resp, expired, key = c.GetWithSubnet(&req, ip2234, 24)
	assert.False(t, expired)
	assert.Equal(t, msgToKeyWithSubnet(&req, ip2234, 0), key)
	require.Nil(t, resp)

	// add a response entry with subnet #2
	resp = &dns.Msg{}
	resp.Response = true
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Answer = []dns.RR{newRR("example.com. 1 IN A 2.2.2.2")}
	c.SetWithSubnet(resp, ip2234, 16)

	// add a response entry without subnet
	resp = &dns.Msg{}
	resp.Response = true
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Answer = []dns.RR{newRR("example.com. 1 IN A 3.3.3.3")}
	c.SetWithSubnet(resp, net.IP{}, 0)

	// get the entry (with the client IP #1)
	resp, expired, key = c.GetWithSubnet(&req, ip1234, 24)
	assert.False(t, expired)
	assert.Equal(t, msgToKeyWithSubnet(&req, ip1234, 16), key)
	require.NotNil(t, resp)
	a = resp.Answer[0].(*dns.A)
	assert.True(t, a.A.String() == "1.1.1.1")

	// get the entry (with the client IP #2)
	resp, expired, key = c.GetWithSubnet(&req, ip2234, 24)
	assert.False(t, expired)
	assert.Equal(t, msgToKeyWithSubnet(&req, ip2234, 16), key)
	require.NotNil(t, resp)
	a = resp.Answer[0].(*dns.A)
	assert.True(t, a.A.String() == "2.2.2.2")

	// get the entry (with the client IP #3)
	resp, expired, key = c.GetWithSubnet(&req, ip3234, 24)
	assert.False(t, expired)
	assert.Equal(t, msgToKeyWithSubnet(&req, ip3234, 0), key)
	require.NotNil(t, resp)
	a = resp.Answer[0].(*dns.A)
	assert.True(t, a.A.String() == "3.3.3.3")
}

func TestCache_IsCacheable_negative(t *testing.T) {
	msgHdr := func(rcode int) (hdr dns.MsgHdr) { return dns.MsgHdr{Id: dns.Id(), Rcode: rcode} }
	aQuestions := func(name string) []dns.Question {
		return []dns.Question{{
			Name:   name,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}}
	}

	cnameAns := func(name, cname string) (rr dns.RR) {
		return &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Target: cname,
		}
	}

	soaAns := func(name, ns, mbox string) (rr dns.RR) {
		return &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns:   ns,
			Mbox: mbox,
		}
	}

	nsAns := func(name, ns string) (rr dns.RR) {
		return &dns.NS{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns: ns,
		}
	}

	aAns := func(name string, a net.IP) (rr dns.RR) {
		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: a,
		}
	}

	const (
		hostname        = "AN.EXAMPLE."
		anotherHostname = "ANOTHER.EXAMPLE."
		cname           = "TRIPPLE.XX."
		mbox            = "HOSTMASTER.NS1.XX."
		ns1, ns2        = "NS1.XX.", "NS2.XX."
		xx              = "XX."
	)

	// See https://datatracker.ietf.org/doc/html/rfc2308.
	testCases := []struct {
		req  *dns.Msg
		want assert.BoolAssertionFunc
		name string
	}{{
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeNameError),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
			Ns: []dns.RR{
				soaAns(xx, ns1, mbox),
				nsAns(xx, ns1),
				nsAns(xx, ns2),
			},
			Extra: []dns.RR{
				aAns(ns1, net.IP{127, 0, 0, 2}),
				aAns(ns2, net.IP{127, 0, 0, 3}),
			},
		},
		want: assert.False,
		name: "rfc2308_nxdomain_response_type_1",
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeNameError),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
			Ns:       []dns.RR{soaAns("XX.", ns1, mbox)},
		},
		want: assert.True,
		name: "rfc2308_nxdomain_response_type_2",
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeNameError),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
		},
		want: assert.False,
		name: "rfc2308_nxdomain_response_type_3",
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeNameError),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
			Ns: []dns.RR{
				nsAns(xx, ns1),
				nsAns(xx, ns2),
			},
			Extra: []dns.RR{
				aAns(ns1, net.IP{127, 0, 0, 2}),
				aAns(ns2, net.IP{127, 0, 0, 3}),
			},
		},
		want: assert.False,
		name: "rfc2308_nxdomain_response_type_4",
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeSuccess),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
			Ns: []dns.RR{
				nsAns(xx, ns1),
				nsAns(xx, ns2),
			},
			Extra: []dns.RR{
				aAns(ns1, net.IP{127, 0, 0, 2}),
				aAns(ns2, net.IP{127, 0, 0, 3}),
			},
		},
		want: assert.False,
		name: "rfc2308_nxdomain_referral_response",
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeSuccess),
			Question: aQuestions(anotherHostname),
			Ns: []dns.RR{
				soaAns(xx, ns1, mbox),
				nsAns(xx, ns1),
				nsAns(xx, ns2),
			},
			Extra: []dns.RR{
				aAns(ns1, net.IP{127, 0, 0, 2}),
				aAns(ns2, net.IP{127, 0, 0, 3}),
			},
		},
		name: "rfc2308_nodata_response_type_1",
		want: assert.False,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeSuccess),
			Question: aQuestions(anotherHostname),
			Ns:       []dns.RR{soaAns(xx, ns1, mbox)},
		},
		name: "rfc2308_nodata_response_type_2",
		want: assert.True,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeSuccess),
			Question: aQuestions(anotherHostname),
		},
		name: "rfc2308_nodata_response_type_3",
		want: assert.False,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeSuccess),
			Question: aQuestions(anotherHostname),
			Ns: []dns.RR{
				nsAns(xx, ns1),
				nsAns(xx, ns2),
			},
			Extra: []dns.RR{
				aAns(ns1, net.IP{127, 0, 0, 2}),
				aAns(ns2, net.IP{127, 0, 0, 3}),
			},
		},
		name: "rfc2308_nodata_referral_response",
		want: assert.False,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.want(t, isCacheable(tc.req))
		})
	}
}
