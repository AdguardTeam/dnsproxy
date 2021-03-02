package proxy

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/stretchr/testify/assert"

	"github.com/go-test/deep"
	"github.com/miekg/dns"
)

func TestCacheSanity(t *testing.T) {
	testCache := cache{}
	request := dns.Msg{}
	request.SetQuestion("google.com.", dns.TypeA)
	_, ok := testCache.Get(&request)
	if ok {
		t.Fatal("empty cache replied with positive response")
	}
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
	r, ok := testCache.Get(&request)
	assert.NotNil(t, r)
	assert.True(t, ok)

	// Now add DO and re-test.
	request.SetEdns0(4096, true)
	r, ok = testCache.Get(&request)
	assert.NotNil(t, r)
	assert.True(t, ok)
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
	r, ok := testCache.Get(&request)
	assert.Nil(t, r)
	assert.False(t, ok)

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
	r, ok = testCache.Get(&request)
	assert.NotNil(t, r)
	assert.True(t, ok)
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
	r, ok := testCache.Get(&request)
	assert.Nil(t, r)
	assert.False(t, ok)
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

	r, ok := dnsProxy.cache.Get(&youtubeReply)
	if !ok {
		t.Fatalf("No cache found for %s", youtubeReply.Question[0].Name)
	}
	if diff := deepEqualMsg(r, &youtubeReply); diff != nil {
		t.Error(diff)
	}

	r, ok = dnsProxy.cache.Get(&googleReply)
	if !ok {
		t.Fatalf("No cache found for %s", googleReply.Question[0].Name)
	}
	if diff := deepEqualMsg(r, &googleReply); diff != nil {
		t.Error(diff)
	}
	r, ok = dnsProxy.cache.Get(&yandexReply)
	if !ok {
		t.Fatalf("No cache found for %s", yandexReply.Question[0].Name)
	}
	if diff := deepEqualMsg(r, &yandexReply); diff != nil {
		t.Error(diff)
	}

	// Wait for cache items expiration
	time.Sleep(1100 * time.Millisecond)

	// Both messages should be already removed from the cache
	_, ok = dnsProxy.cache.Get(&yandexReply)
	if ok {
		t.Fatalf("cache for %s was not removed from the cache", yandexReply.Question[0].Name)
	}
	_, ok = dnsProxy.cache.Get(&googleReply)
	if ok {
		t.Fatalf("cache for %s was not removed from the cache", googleReply.Question[0].Name)
	}

	// New answer with zero TTL
	yandexReply.Answer = []dns.RR{newRR("yandex.com. 0 IN A 213.180.204.62")}
	dnsProxy.cache.Set(&yandexReply)
	_, ok = dnsProxy.cache.Get(&yandexReply)
	if ok {
		t.Fatalf("cache for %s with zero ttl was placed to the cache", yandexReply.Question[0].Name)
	}

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
	r, ok := dnsProxy.cache.Get(d.Req)
	assert.True(t, ok)
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
	r, ok = dnsProxy.cache.Get(d.Req)
	assert.True(t, ok)
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
	t.Helper()
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
		val, ok := testCache.Get(&request)
		if diff := deep.Equal(ok, tc.ok); diff != nil {
			t.Error(diff)
		}
		if tc.a != nil {
			if !ok {
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

	r, ok := c.Get(&dnsMsg)
	if !ok {
		t.Fatalf("No cache found for %s", host)
	}

	if diff := deepEqualMsg(r, &dnsMsg); diff != nil {
		t.Error(diff)
	}

	r, ok = c.Get(&dnsMsg)
	if !ok {
		t.Fatalf("No cache found for %s", host)
	}

	if diff := deepEqualMsg(r, &dnsMsg); diff != nil {
		t.Error(diff)
	}

	time.Sleep(1100 * time.Millisecond)
	_, ok = c.Get(&dnsMsg)
	if ok {
		t.Fatalf("Cache for %s should be already removed", host)
	}
}

func TestSubnet(t *testing.T) {
	c := &cacheSubnet{}
	var a *dns.A

	// search - not found
	req := dns.Msg{}
	req.SetQuestion("example.com.", dns.TypeA)
	resp, _ := c.GetWithSubnet(&req, net.IP{1, 2, 3, 4}, 24)
	assert.True(t, resp == nil)

	// add a response entry with subnet
	resp = &dns.Msg{}
	resp.Response = true
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Answer = []dns.RR{newRR("example.com. 1 IN A 1.1.1.1")}
	c.SetWithSubnet(resp, net.IP{1, 2, 3, 4}, 16)

	// search for the entry (with another client IP) - not found
	resp, _ = c.GetWithSubnet(&req, net.IP{2, 2, 3, 4}, 24)
	assert.True(t, resp == nil)

	// add a response entry with subnet #2
	resp = &dns.Msg{}
	resp.Response = true
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Answer = []dns.RR{newRR("example.com. 1 IN A 2.2.2.2")}
	c.SetWithSubnet(resp, net.IP{2, 2, 3, 4}, 16)

	// add a response entry without subnet
	resp = &dns.Msg{}
	resp.Response = true
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Answer = []dns.RR{newRR("example.com. 1 IN A 3.3.3.3")}
	c.SetWithSubnet(resp, net.IP{}, 0)

	// get the entry (with the client IP #1)
	resp, _ = c.GetWithSubnet(&req, net.IP{1, 2, 3, 4}, 24)
	assert.True(t, resp != nil)
	a = resp.Answer[0].(*dns.A)
	assert.True(t, a.A.String() == "1.1.1.1")

	// get the entry (with the client IP #2)
	resp, _ = c.GetWithSubnet(&req, net.IP{2, 2, 3, 4}, 24)
	assert.True(t, resp != nil)
	a = resp.Answer[0].(*dns.A)
	assert.True(t, a.A.String() == "2.2.2.2")

	// get the entry (with the client IP #3)
	resp, _ = c.GetWithSubnet(&req, net.IP{3, 2, 3, 4}, 24)
	assert.True(t, resp != nil)
	a = resp.Answer[0].(*dns.A)
	assert.True(t, a.A.String() == "3.3.3.3")
}
