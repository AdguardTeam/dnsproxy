package proxy

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/miekg/dns"
)

// testCacheSize is the maximum size of cache for tests.
const testCacheSize = 4096

const testUpsAddr = "https://upstream.address"

var upstreamWithAddr = &funcUpstream{
	exchangeFunc: func(m *dns.Msg) (resp *dns.Msg, err error) { panic("not implemented") },
	addressFunc:  func() (addr string) { return testUpsAddr },
}

func TestServeCached(t *testing.T) {
	// Prepare the proxy server.
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.CacheEnabled = true // just one request per second is allowed

	// Start listening.
	err := dnsProxy.Start()
	require.NoErrorf(t, err, "cannot start the DNS proxy: %s", err)
	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

	// Fill the cache.
	reply := (&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response: true,
		},
		Answer: []dns.RR{newRR(t, "google.com.", dns.TypeA, 3600, net.IP{8, 8, 8, 8})},
	}).SetQuestion("google.com.", dns.TypeA)
	reply.SetEdns0(defaultUDPBufSize, false)

	dnsProxy.cache.set(reply, upstreamWithAddr)

	// Create a DNS-over-UDP client connection.
	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	// Create a DNS request.
	request := (&dns.Msg{}).SetQuestion("google.com.", dns.TypeA)
	request.SetEdns0(defaultUDPBufSize, false)

	r, _, err := client.Exchange(request, addr.String())
	require.NoErrorf(t, err, "error in the first request: %s", err)

	requireEqualMsgs(t, r, reply)
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

	testCache := newCache(testCacheSize, false, false)
	for _, tc := range testCases {
		ans.Hdr.Ttl = tc.ttl
		req := (&dns.Msg{}).SetQuestion(host, dns.TypeA)

		t.Run(tc.name, func(t *testing.T) {
			if tc.optimistic {
				testCache.optimistic = true
				t.Cleanup(func() { testCache.optimistic = false })
			}

			key := msgToKey(reply)
			data := (&cacheItem{
				m:   reply,
				u:   testUpsAddr,
				ttl: tc.ttl,
			}).pack()
			testCache.items.Set(key, data)
			t.Cleanup(testCache.items.Clear)

			r, expired, key := testCache.get(req)
			assert.Equal(t, msgToKey(req), key)
			assert.Equal(t, tc.ttl == 0, expired)

			if tc.wantTTL != 0 {
				require.NotNil(t, r)

				assert.Equal(t, tc.wantTTL, r.m.Answer[0].Header().Ttl)
				assert.Equal(t, testUpsAddr, r.u)
			} else {
				require.Nil(t, r)
			}
		})
	}
}

func TestCacheDO(t *testing.T) {
	testCache := newCache(testCacheSize, false, false)

	// Fill the cache.
	reply := (&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response: true,
		},
		Answer: []dns.RR{newRR(t, "google.com.", dns.TypeA, 3600, net.IP{8, 8, 8, 8})},
	}).SetQuestion("google.com.", dns.TypeA)
	reply.SetEdns0(4096, true)

	// Store in cache.
	testCache.set(reply, upstreamWithAddr)

	// Make a request.
	request := (&dns.Msg{}).SetQuestion("google.com.", dns.TypeA)

	t.Run("without_do", func(t *testing.T) {
		ci, expired, key := testCache.get(request)
		assert.False(t, expired)
		assert.Equal(t, msgToKey(request), key)
		assert.NotNil(t, ci)
	})

	t.Run("with_do", func(t *testing.T) {
		reqClone := request.Copy()
		t.Cleanup(func() {
			request = reqClone
		})

		request.SetEdns0(4096, true)

		ci, expired, key := testCache.get(request)
		assert.False(t, expired)
		assert.Equal(t, msgToKey(request), key)

		require.NotNil(t, ci)

		assert.Equal(t, testUpsAddr, ci.u)
	})
}

func TestCacheCNAME(t *testing.T) {
	testCache := newCache(testCacheSize, false, false)

	// Fill the cache
	reply := (&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response: true,
		},
		Answer: []dns.RR{newRR(t, "google.com.", dns.TypeCNAME, 3600, "test.google.com.")},
	}).SetQuestion("google.com.", dns.TypeA)
	testCache.set(reply, upstreamWithAddr)

	// Create a DNS request.
	request := (&dns.Msg{}).SetQuestion("google.com.", dns.TypeA)

	t.Run("no_cnames", func(t *testing.T) {
		r, expired, _ := testCache.get(request)
		assert.Nil(t, r)
		assert.False(t, expired)
	})

	// Now fill the cache with a cacheable CNAME response.
	reply.Answer = append(reply.Answer, newRR(t, "google.com.", dns.TypeA, 3600, net.IP{8, 8, 8, 8}))
	testCache.set(reply, upstreamWithAddr)

	// We are testing that a proper CNAME response gets cached
	t.Run("cnames_exist", func(t *testing.T) {
		r, expired, key := testCache.get(request)
		assert.False(t, expired)
		assert.Equal(t, key, msgToKey(request))

		require.NotNil(t, r)

		assert.Equal(t, testUpsAddr, r.u)
	})
}

func TestCache_uncacheable(t *testing.T) {
	testCache := newCache(testCacheSize, false, false)

	// Create a DNS request.
	request := (&dns.Msg{}).SetQuestion("google.com.", dns.TypeA)
	// Fill the cache.
	reply := (&dns.Msg{}).SetRcode(request, dns.RcodeBadAlg)

	// We are testing that SERVFAIL responses aren't cached
	testCache.set(reply, upstreamWithAddr)

	r, expired, _ := testCache.get(request)
	assert.Nil(t, r)
	assert.False(t, expired)
}

func TestCache_concurrent(t *testing.T) {
	testCache := newCache(testCacheSize, false, false)

	hosts := map[string]string{
		dns.Fqdn("yandex.com"):     "213.180.204.62",
		dns.Fqdn("google.com"):     "8.8.8.8",
		dns.Fqdn("www.google.com"): "8.8.4.4",
		dns.Fqdn("youtube.com"):    "173.194.221.198",
		dns.Fqdn("car.ru"):         "37.220.161.35",
		dns.Fqdn("cat.ru"):         "192.56.231.67",
	}

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
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

	// Create dns messages with TTL of 1 second.
	rrs := []dns.RR{
		newRR(t, "youtube.com.", dns.TypeA, 1, net.IP{173, 194, 221, 198}),
		newRR(t, "google.com.", dns.TypeA, 1, net.IP{8, 8, 8, 8}),
		newRR(t, "yandex.com.", dns.TypeA, 1, net.IP{213, 180, 204, 62}),
	}
	replies := make([]*dns.Msg, len(rrs))
	for i, rr := range rrs {
		rep := (&dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response: true,
			},
			Answer: []dns.RR{dns.Copy(rr)},
		}).SetQuestion(rr.Header().Name, dns.TypeA)
		dnsProxy.cache.set(rep, upstreamWithAddr)
		replies[i] = rep
	}

	for _, r := range replies {
		ci, expired, key := dnsProxy.cache.get(r)
		require.NotNil(t, ci)

		assert.False(t, expired)
		assert.Equal(t, msgToKey(ci.m), key)

		requireEqualMsgs(t, ci.m, r)
	}

	assert.Eventually(t, func() bool {
		for _, r := range replies {
			if ci, _, _ := dnsProxy.cache.get(r); ci != nil {
				return false
			}
		}

		return true
	}, 1100*time.Millisecond, 100*time.Millisecond)
}

func TestCacheExpirationWithTTLOverride(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.CacheEnabled = true
	dnsProxy.CacheMinTTL = 20
	dnsProxy.CacheMaxTTL = 40

	u := testUpstream{}
	dnsProxy.UpstreamConfig.Upstreams = []upstream.Upstream{&u}

	err := dnsProxy.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

	d := &DNSContext{}

	t.Run("replace_min", func(t *testing.T) {
		d.Req = createHostTestMessage("host")
		d.Addr = netip.AddrPort{}

		u.ans = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Rrtype: dns.TypeA,
				Name:   "host.",
				Ttl:    10,
			},
			A: net.IP{4, 3, 2, 1},
		}}

		err = dnsProxy.Resolve(d)
		require.NoError(t, err)

		ci, expired, key := dnsProxy.cache.get(d.Req)
		assert.False(t, expired)
		assert.Equal(t, msgToKey(d.Req), key)

		require.NotNil(t, ci)
		assert.Equal(t, dnsProxy.CacheMinTTL, ci.m.Answer[0].Header().Ttl)
	})

	t.Run("replace_max", func(t *testing.T) {
		d.Req = createHostTestMessage("host2")
		d.Addr = netip.AddrPort{}

		u.ans = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Rrtype: dns.TypeA,
				Name:   "host2.",
				Ttl:    60,
			},
			A: net.IP{4, 3, 2, 1},
		}}

		err = dnsProxy.Resolve(d)
		assert.Nil(t, err)

		ci, expired, key := dnsProxy.cache.get(d.Req)
		assert.False(t, expired)
		assert.Equal(t, msgToKey(d.Req), key)

		require.NotNil(t, ci)
		assert.Equal(t, dnsProxy.CacheMaxTTL, ci.m.Answer[0].Header().Ttl)
	})
}

type testEntry struct {
	q string
	a []dns.RR
	t uint16
}

type testCase struct {
	ok require.BoolAssertionFunc
	q  string
	a  []dns.RR
	t  uint16
}

type testCases struct {
	cache []testEntry
	cases []testCase
}

func TestCache(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		testCases{
			cache: []testEntry{{
				q: "google.com.",
				a: []dns.RR{newRR(t, "google.com.", dns.TypeA, 3600, net.IP{8, 8, 8, 8})},
				t: dns.TypeA,
			}},
			cases: []testCase{{
				ok: require.True,
				q:  "google.com.",
				a:  []dns.RR{newRR(t, "google.com.", dns.TypeA, 3600, net.IP{8, 8, 8, 8})},
				t:  dns.TypeA,
			}, {
				ok: require.False,
				q:  "google.com.",
				t:  dns.TypeMX,
			}},
		}.run(t)
	})

	t.Run("mixed_case", func(t *testing.T) {
		testCases{
			cache: []testEntry{{
				q: "gOOgle.com.",
				a: []dns.RR{newRR(t, "google.com.", dns.TypeA, 3600, net.IP{8, 8, 8, 8})},
				t: dns.TypeA,
			}},
			cases: []testCase{{
				ok: require.True,
				q:  "gOOgle.com.",
				a:  []dns.RR{newRR(t, "google.com.", dns.TypeA, 3600, net.IP{8, 8, 8, 8})},
				t:  dns.TypeA,
			}, {
				ok: require.True,
				q:  "google.com.",
				a:  []dns.RR{newRR(t, "google.com.", dns.TypeA, 3600, net.IP{8, 8, 8, 8})},
				t:  dns.TypeA,
			}, {
				ok: require.True,
				q:  "GOOGLE.COM.",
				a:  []dns.RR{newRR(t, "google.com.", dns.TypeA, 3600, net.IP{8, 8, 8, 8})},
				t:  dns.TypeA,
			}, {
				q:  "gOOgle.com.",
				t:  dns.TypeMX,
				ok: require.False,
			}, {
				ok: require.False,
				q:  "google.com.",
				t:  dns.TypeMX,
			}, {
				ok: require.False,
				q:  "GOOGLE.COM.",
				t:  dns.TypeMX,
			}},
		}.run(t)
	})

	t.Run("zero_ttl", func(t *testing.T) {
		testCases{
			cache: []testEntry{{
				q: "gOOgle.com.",
				a: []dns.RR{newRR(t, "google.com.", dns.TypeA, 0, net.IP{8, 8, 8, 8})},
				t: dns.TypeA,
			}},
			cases: []testCase{{
				ok: require.False,
				q:  "google.com.",
				t:  dns.TypeA,
			}, {
				ok: require.False,
				q:  "google.com.",
				t:  dns.TypeA,
			}, {
				ok: require.False,
				q:  "google.com.",
				t:  dns.TypeA,
			}, {
				ok: require.False,
				q:  "google.com.",
				t:  dns.TypeMX,
			}, {
				ok: require.False,
				q:  "google.com.",
				t:  dns.TypeMX,
			}, {
				ok: require.False,
				q:  "google.com.",
				t:  dns.TypeMX,
			}},
		}.run(t)
	})
}

func (tests testCases) run(t *testing.T) {
	testCache := newCache(testCacheSize, false, false)

	for _, res := range tests.cache {
		reply := (&dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response: true,
			},
			Answer: res.a,
		}).SetQuestion(res.q, res.t)
		testCache.set(reply, upstreamWithAddr)
	}

	for _, tc := range tests.cases {
		request := (&dns.Msg{}).SetQuestion(tc.q, tc.t)

		ci, expired, _ := testCache.get(request)
		assert.False(t, expired)
		tc.ok(t, ci != nil)

		if tc.a == nil {
			return
		} else if ci == nil {
			continue
		}

		reply := (&dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response: true,
			},
			Answer: tc.a,
		}).SetQuestion(tc.q, tc.t)

		testCache.set(reply, upstreamWithAddr)

		requireEqualMsgs(t, ci.m, reply)
	}
}

// requireEqualMsgs asserts the messages are equal except their ID, Rdlength, and
// the case of questions.
func requireEqualMsgs(t *testing.T, expected, actual *dns.Msg) {
	t.Helper()

	temp := *expected
	temp.Id = actual.Id

	require.Equal(t, len(temp.Answer), len(actual.Answer))
	for i, ans := range actual.Answer {
		temp.Answer[i].Header().Rdlength = ans.Header().Rdlength
	}
	for _, rr := range actual.Answer {
		if a, ok := rr.(*dns.A); ok {
			if a4 := a.A.To4(); a4 != nil {
				a.A = a4
			}
		}
	}
	for i := range temp.Question {
		temp.Question[i].Name = strings.ToLower(temp.Question[i].Name)
	}
	for i := range actual.Question {
		actual.Question[i].Name = strings.ToLower(actual.Question[i].Name)
	}

	assert.Equal(t, &temp, actual)
}

func setAndGetCache(t *testing.T, c *cache, g *sync.WaitGroup, host, ip string) {
	defer g.Done()

	ipAddr := net.ParseIP(ip)

	dnsMsg := (&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response: true,
		},
		Answer: []dns.RR{newRR(t, host, dns.TypeA, 1, ipAddr)},
	}).SetQuestion(host, dns.TypeA)

	c.set(dnsMsg, upstreamWithAddr)

	for i := 0; i < 2; i++ {
		ci, expired, key := c.get(dnsMsg)
		require.NotNilf(t, ci, "no cache found for %s", host)

		assert.False(t, expired)
		assert.Equal(t, msgToKey(dnsMsg), key)

		requireEqualMsgs(t, ci.m, dnsMsg)
	}

	assert.Eventuallyf(t, func() bool {
		ci, _, _ := c.get(dnsMsg)

		return ci == nil
	}, 1100*time.Millisecond, 100*time.Millisecond, "cache for %s should already be removed", host)
}

func TestCache_getWithSubnet(t *testing.T) {
	const testFQDN = "example.com."

	ip1234, ip2234, ip3234 := net.IP{1, 2, 3, 4}, net.IP{2, 2, 3, 4}, net.IP{3, 2, 3, 4}
	req := (&dns.Msg{}).SetQuestion(testFQDN, dns.TypeA)
	mask16 := net.CIDRMask(16, netutil.IPv4BitLen)
	mask24 := net.CIDRMask(24, netutil.IPv4BitLen)

	c := newCache(testCacheSize, true, false)

	t.Run("empty", func(t *testing.T) {
		ci, expired, _ := c.getWithSubnet(req, &net.IPNet{IP: ip1234, Mask: mask24})
		assert.Nil(t, ci)
		assert.False(t, expired)
	})

	// Add a response with subnet.
	resp := (&dns.Msg{
		Answer: []dns.RR{newRR(t, testFQDN, dns.TypeA, 1, net.IP{1, 1, 1, 1})},
	}).SetReply(req)
	c.setWithSubnet(resp, upstreamWithAddr, &net.IPNet{IP: ip1234, Mask: mask16})

	t.Run("different_ip", func(t *testing.T) {
		ci, expired, key := c.getWithSubnet(req, &net.IPNet{IP: ip2234, Mask: mask24})
		assert.False(t, expired)
		assert.Equal(t, msgToKeyWithSubnet(req, ip2234, 0), key)
		assert.Nil(t, ci)
	})

	// Add a response entry with subnet #2.
	resp = (&dns.Msg{
		Answer: []dns.RR{newRR(t, testFQDN, dns.TypeA, 1, net.IP{2, 2, 2, 2})},
	}).SetReply(req)
	c.setWithSubnet(resp, upstreamWithAddr, &net.IPNet{IP: ip2234, Mask: mask16})

	// Add a response entry without subnet.
	resp = (&dns.Msg{
		Answer: []dns.RR{newRR(t, testFQDN, dns.TypeA, 1, net.IP{3, 3, 3, 3})},
	}).SetReply(req)
	c.setWithSubnet(resp, upstreamWithAddr, &net.IPNet{IP: nil, Mask: nil})

	t.Run("with_subnet_1", func(t *testing.T) {
		ci, expired, key := c.getWithSubnet(req, &net.IPNet{IP: ip1234, Mask: mask24})
		assert.False(t, expired)
		assert.Equal(t, msgToKeyWithSubnet(req, ip1234.Mask(mask16), 16), key)

		require.NotNil(t, ci)
		require.NotNil(t, ci.m)
		require.NotEmpty(t, ci.m.Answer)

		a := testutil.RequireTypeAssert[*dns.A](t, ci.m.Answer[0])
		assert.True(t, a.A.Equal(net.IP{1, 1, 1, 1}))
	})

	t.Run("with_subnet_2", func(t *testing.T) {
		ci, expired, key := c.getWithSubnet(req, &net.IPNet{IP: ip2234, Mask: mask24})
		assert.False(t, expired)
		assert.Equal(t, msgToKeyWithSubnet(req, ip2234.Mask(mask16), 16), key)

		require.NotNil(t, ci)
		require.NotNil(t, ci.m)
		require.NotEmpty(t, ci.m.Answer)

		a := testutil.RequireTypeAssert[*dns.A](t, ci.m.Answer[0])
		assert.True(t, a.A.Equal(net.IP{2, 2, 2, 2}))
	})

	t.Run("with_subnet_3", func(t *testing.T) {
		ci, expired, key := c.getWithSubnet(req, &net.IPNet{IP: ip3234, Mask: mask24})
		assert.False(t, expired)
		assert.Equal(t, msgToKeyWithSubnet(req, ip1234, 0), key)

		require.NotNil(t, ci)
		require.NotNil(t, ci.m)
		require.NotEmpty(t, ci.m.Answer)

		a := testutil.RequireTypeAssert[*dns.A](t, ci.m.Answer[0])
		assert.True(t, a.A.Equal(net.IP{3, 3, 3, 3}))
	})
}

func TestCache_getWithSubnet_mask(t *testing.T) {
	const testFQDN = "example.com."

	testIP := net.IP{176, 112, 191, 0}
	noMatchIP := net.IP{177, 112, 191, 0}

	// cachedIP/cidrMask network contains the testIP.
	const cidrMaskOnes = 20
	cidrMask := net.CIDRMask(cidrMaskOnes, netutil.IPv4BitLen)
	cachedIP := net.IP{176, 112, 176, 0}

	ansIP := net.IP{4, 4, 4, 4}

	c := newCache(testCacheSize, true, true)

	req := (&dns.Msg{}).SetQuestion(testFQDN, dns.TypeA)
	resp := (&dns.Msg{
		Answer: []dns.RR{newRR(t, testFQDN, dns.TypeA, 300, ansIP)},
	}).SetReply(req)

	// Cache IP network that contains the testIP.
	c.setWithSubnet(
		resp,
		upstreamWithAddr,
		&net.IPNet{IP: cachedIP, Mask: cidrMask},
	)

	t.Run("mask_matched", func(t *testing.T) {
		ci, expired, key := c.getWithSubnet(req, &net.IPNet{
			IP:   testIP,
			Mask: net.CIDRMask(24, netutil.IPv4BitLen),
		})
		assert.False(t, expired)
		assert.Equal(t, msgToKeyWithSubnet(req, testIP.Mask(cidrMask), cidrMaskOnes), key)

		require.NotNil(t, ci)
		require.NotNil(t, ci.m)
		require.NotEmpty(t, ci.m.Answer)

		a := testutil.RequireTypeAssert[*dns.A](t, ci.m.Answer[0])
		assert.True(t, a.A.Equal(ansIP))
	})

	t.Run("no_mask_matched", func(t *testing.T) {
		ci, expired, key := c.getWithSubnet(req, &net.IPNet{
			IP:   noMatchIP,
			Mask: net.CIDRMask(24, netutil.IPv4BitLen),
		})
		assert.False(t, expired)
		assert.Equal(t, msgToKeyWithSubnet(req, noMatchIP, 0), key)
		assert.Nil(t, ci)
	})
}

func TestCache_IsCacheable_negative(t *testing.T) {
	const someTTL = 3600

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
				Ttl:    someTTL,
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
				Ttl:    someTTL,
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
				Ttl:    someTTL,
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
				Ttl:    someTTL,
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
		req     *dns.Msg
		name    string
		wantTTL uint32
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
		name:    "rfc2308_nxdomain_response_type_1",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeNameError),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
			Ns:       []dns.RR{soaAns("XX.", ns1, mbox)},
		},
		name:    "rfc2308_nxdomain_response_type_2",
		wantTTL: someTTL,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeNameError),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
		},
		name:    "rfc2308_nxdomain_response_type_3",
		wantTTL: 0,
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
		name:    "rfc2308_nxdomain_response_type_4",
		wantTTL: 0,
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
		name:    "rfc2308_nxdomain_referral_response",
		wantTTL: 0,
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
		name:    "rfc2308_nodata_response_type_1",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeSuccess),
			Question: aQuestions(anotherHostname),
			Ns:       []dns.RR{soaAns(xx, ns1, mbox)},
		},
		name:    "rfc2308_nodata_response_type_2",
		wantTTL: someTTL,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeSuccess),
			Question: aQuestions(anotherHostname),
		},
		name:    "rfc2308_nodata_response_type_3",
		wantTTL: 0,
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
		name:    "rfc2308_nodata_referral_response",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeServerFailure),
			Question: aQuestions(anotherHostname),
		},
		name:    "servfail_response",
		wantTTL: ServFailMaxCacheTTL,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantTTL, cacheTTL(tc.req))
		})
	}
}
