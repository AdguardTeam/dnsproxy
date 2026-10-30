package proxy

import (
	"cmp"
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/miekg/dns"
)

const (
	// testUpsAddr is the mock upstream address for tests.
	testUpsAddr = "https://" + dnsproxytest.Host

	// testTTL is a common time-to-live value for tests.
	testTTL = 3600

	// cacheTick is a cache check period.
	testCacheTick = 100 * time.Millisecond

	// cacheTimeout is the timeout of cache check.
	testCacheTimeout = 20 * testCacheTick
)

// Common IP address strings for cache tests.
const (
	testCacheIPStr1 = "192.0.2.65"
	testCacheIPStr2 = "192.0.2.129"
	testCacheIPStr3 = "198.51.100.1"
)

// Common parsed IP addresses for cache tests.
var (
	testCacheIP1 net.IP = netip.MustParseAddr(testCacheIPStr1).AsSlice()
	testCacheIP2 net.IP = netip.MustParseAddr(testCacheIPStr2).AsSlice()
	testCacheIP3 net.IP = netip.MustParseAddr(testCacheIPStr3).AsSlice()
)

// upstreamWithAddr is a [dnsproxytest.Upstream] that is only expected to be
// used to get its address.
var upstreamWithAddr = &testUpstream{
	OnExchange: func(ctx context.Context, m *dns.Msg) (_ *dns.Msg, _ error) {
		panic(testutil.UnexpectedCall(ctx, m))
	},
	OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	OnAddress: func() (addr string) { return testUpsAddr },
}

// newTestCache is a helper that returns new cache and fills its config with
// given values.  If conf is nil, the default configuration will be used.
func newTestCache(tb testing.TB, conf *cacheConfig) (c *cache) {
	tb.Helper()

	conf = cmp.Or(conf, &cacheConfig{size: dnsproxytest.CacheSize})

	return newCache(&cacheConfig{
		size:             conf.size,
		optimisticTTL:    conf.optimisticTTL,
		optimisticMaxAge: conf.optimisticMaxAge,
		withECS:          conf.withECS,
		optimistic:       conf.optimistic,
	})
}

func TestProxy_ServeDNS_cached(t *testing.T) {
	dnsProxy := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(t)},
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		DNSSECEnabled:  false,
		CacheEnabled:   true,
	})

	servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

	request := dnsproxytest.NewTestRequest()
	request.SetEdns0(defaultUDPBufSize, false)

	reply := (&dns.Msg{
		Answer: []dns.RR{
			dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeA, testTTL, dnsproxytest.IPv4.To4()),
		},
	}).SetReply(request)
	reply.SetEdns0(defaultUDPBufSize, false)

	dnsProxy.cache.set(request, reply, upstreamWithAddr, testLogger)

	addr := dnsProxy.Addr(ProtoTCP)
	client := &dns.Client{
		Net:     string(ProtoTCP),
		Timeout: dnsproxytest.Timeout,
	}

	r, _, err := client.Exchange(request, addr.String())
	require.NoError(t, err)

	requireEqualMsgs(t, r, reply)
}

func TestCache_expired(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		optimisticMaxAge time.Duration
		ttl              uint32
		wantTTL          uint32
		optimistic       bool
	}{{
		name:             "regular_expired",
		optimisticMaxAge: 0,
		ttl:              0,
		wantTTL:          0,
		optimistic:       false,
	}, {
		name:             "optimistic_hit",
		optimisticMaxAge: testOptimisticMaxAge,
		ttl:              defaultTestTTL,
		wantTTL:          defaultTestTTL,
		optimistic:       true,
	}, {
		name:             "optimistic_expired",
		optimisticMaxAge: testOptimisticMaxAge,
		ttl:              0,
		wantTTL:          uint32(testOptimisticTTL.Seconds()),
		optimistic:       true,
	}, {
		name:             "optimistic_max_age_exceeded",
		optimisticMaxAge: -time.Hour,
		ttl:              0,
		wantTTL:          0,
		optimistic:       true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testCache := newTestCache(t, &cacheConfig{
				optimisticTTL:    testOptimisticTTL,
				optimisticMaxAge: tc.optimisticMaxAge,
				optimistic:       tc.optimistic,
			})
			assertExpiredCache(t, testCache, tc.ttl, tc.wantTTL)
		})
	}
}

// assertExpiredCache checks cache expiration and the returned TTL.
func assertExpiredCache(tb testing.TB, c *cache, ttl, wantTTL uint32) {
	req := dnsproxytest.NewTestRequest()
	reply := dnsproxytest.NewTestResponse(req)
	reply.Answer[0].Header().Ttl = ttl
	data := (&cacheItem{
		m:   reply,
		u:   testUpsAddr,
		ttl: ttl,
	}).pack()
	c.items.Set(msgToKey(req), data)

	r, expired, key := c.get(req)
	assert.Equal(tb, msgToKey(req), key)
	assert.Equal(tb, ttl == 0, expired)
	if wantTTL == 0 {
		assert.Nil(tb, r)

		return
	}

	require.NotNil(tb, r)
	require.Len(tb, r.m.Answer, 1)

	assert.Equal(tb, wantTTL, r.m.Answer[0].Header().Ttl)
	assert.Equal(tb, testUpsAddr, r.u)
}

func TestCache_do(t *testing.T) {
	testCache := newTestCache(t, nil)

	request := dnsproxytest.NewTestRequest()
	reply := (&dns.Msg{
		Response: true,
		Answer: []dns.RR{
			dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeA, testTTL, dnsproxytest.IPv4.To4()),
		},
	}).SetQuestion(dnsproxytest.FQDN, dns.TypeA)
	reply.SetEdns0(4096, false)

	testCache.set(request, reply, upstreamWithAddr, testLogger)

	require.True(t, t.Run("without_do", func(t *testing.T) {
		ci, expired, _ := testCache.get(request)
		assert.False(t, expired)
		assert.NotNil(t, ci)
	}))

	require.True(t, t.Run("with_do", func(t *testing.T) {
		reqClone := request.Copy()
		t.Cleanup(func() {
			request = reqClone
		})

		request.SetEdns0(4096, true)

		ci, expired, _ := testCache.get(request)
		require.Nil(t, ci)
		assert.False(t, expired)
	}))
}

func TestCache_cname(t *testing.T) {
	t.Parallel()

	testCache := newTestCache(t, nil)

	request := dnsproxytest.NewTestRequest()

	answ := dnsproxytest.NewRR(
		t,
		dnsproxytest.FQDN,
		dns.TypeCNAME,
		testTTL,
		"alias."+dnsproxytest.FQDN,
	)
	reply := (&dns.Msg{
		Response: true,
		Answer:   []dns.RR{answ},
	}).SetQuestion(dnsproxytest.FQDN, dns.TypeA)
	testCache.set(request, reply, upstreamWithAddr, testLogger)

	require.True(t, t.Run("no_cnames", func(t *testing.T) {
		r, expired, _ := testCache.get(request)
		assert.Nil(t, r)
		assert.False(t, expired)
	}))

	reply.Answer = append(
		reply.Answer,
		dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeA, testTTL, dnsproxytest.IPv4.To4()),
	)
	testCache.set(request, reply, upstreamWithAddr, testLogger)

	require.True(t, t.Run("cnames_exist", func(t *testing.T) {
		r, expired, key := testCache.get(request)
		assert.False(t, expired)
		assert.Equal(t, key, msgToKey(request))

		require.NotNil(t, r)

		assert.Equal(t, testUpsAddr, r.u)
	}))
}

func TestCache_uncacheable(t *testing.T) {
	testCache := newTestCache(t, nil)

	request := dnsproxytest.NewTestRequest()
	reply := (&dns.Msg{}).SetRcode(request, dns.RcodeBadAlg)

	testCache.set(request, reply, upstreamWithAddr, testLogger)

	r, expired, _ := testCache.get(request)
	assert.Nil(t, r)
	assert.False(t, expired)
}

func TestCache_concurrent(t *testing.T) {
	testCache := newTestCache(t, nil)

	hosts := map[string]string{
		dnsproxytest.FQDN:            dnsproxytest.IPv4.String(),
		"two." + dnsproxytest.FQDN:   testCacheIPStr1,
		"three." + dnsproxytest.FQDN: testCacheIPStr2,
		"four." + dnsproxytest.FQDN:  dnsproxytest.IPv4.String(),
		"five." + dnsproxytest.FQDN:  testCacheIPStr1,
		"six." + dnsproxytest.FQDN:   testCacheIPStr2,
	}

	g := &sync.WaitGroup{}
	g.Add(len(hosts))

	for k, v := range hosts {
		go setAndGetCache(t, testCache, g, k, v)
	}

	g.Wait()
}

func TestCache_expiration(t *testing.T) {
	t.Parallel()

	dnsProxy := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(t)},
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		CacheEnabled:   true,
	})

	servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

	// Create dns messages with TTL of 1 second.
	rrs := []dns.RR{
		dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeA, 1, dnsproxytest.IPv4.To4()),
		dnsproxytest.NewRR(t, "two."+dnsproxytest.FQDN, dns.TypeA, 1, testCacheIP1),
		dnsproxytest.NewRR(t, "three."+dnsproxytest.FQDN, dns.TypeA, 1, testCacheIP2),
	}
	requests := make([]*dns.Msg, 0, len(rrs))
	responses := make([]*dns.Msg, 0, len(rrs))
	for _, rr := range rrs {
		req := dnsproxytest.NewTestRequestWithHost(rr.Header().Name)
		requests = append(requests, req)

		resp := (&dns.Msg{}).SetReply(req)
		resp.Answer = append(resp.Answer, rr)
		responses = append(responses, resp)

		dnsProxy.cache.set(req, resp, upstreamWithAddr, testLogger)
	}

	for i, r := range requests {
		ci, expired, key := dnsProxy.cache.get(r)
		require.NotNil(t, ci)

		assert.False(t, expired)
		assert.Equal(t, msgToKey(ci.m), key)

		requireEqualMsgs(t, ci.m, responses[i])
	}

	assert.Eventually(t, func() bool {
		for _, r := range requests {
			if ci, _, _ := dnsProxy.cache.get(r); ci != nil {
				return false
			}
		}

		return true
	}, testCacheTimeout, testCacheTick)
}

func TestCache_ttlOverride(t *testing.T) {
	t.Parallel()

	t.Run("min", func(t *testing.T) {
		t.Parallel()

		assertCacheTTLOverride(t, 10, 20)
	})

	t.Run("max", func(t *testing.T) {
		t.Parallel()

		assertCacheTTLOverride(t, 60, 40)
	})
}

// assertCacheTTLOverride runs a separate proxy instance and checks the TTL of a
// cached response after an override.
func assertCacheTTLOverride(tb testing.TB, ttl, wantTTL uint32) {
	ans := []dns.RR{
		dnsproxytest.NewRR(tb, dnsproxytest.FQDN, dns.TypeA, ttl, dnsproxytest.IPv4.To4()),
	}

	onExchange := newECSReplyHandler(&ans, nil, nil)
	u := newTestUpstreamWithExchange(tb, onExchange)

	dnsProxy := mustNew(tb, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{u},
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		CacheEnabled:   true,
		DNSSECEnabled:  true,
		CacheMinTTL:    20,
		CacheMaxTTL:    40,
	})

	servicetest.RequireRun(tb, dnsProxy, dnsproxytest.Timeout)

	d := &DNSContext{
		Req:  dnsproxytest.NewTestRequest(),
		Addr: netip.AddrPort{},
	}
	err := dnsProxy.Resolve(testutil.ContextWithTimeout(tb, defaultTimeout), d)
	require.NoError(tb, err)

	ci, expired, key := dnsProxy.cache.get(d.Req)
	require.NotNil(tb, ci)
	require.Len(tb, ci.m.Answer, 1)

	assert.False(tb, expired)
	assert.Equal(tb, msgToKey(d.Req), key)
	assert.Equal(tb, wantTTL, ci.m.Answer[0].Header().Ttl)
}

func TestCache_simple(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		qtype   uint16
		wantHit bool
	}{{
		name:    "hit",
		qtype:   dns.TypeA,
		wantHit: true,
	}, {
		name:    "different_type",
		qtype:   dns.TypeMX,
		wantHit: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := (&dns.Msg{}).SetQuestion(dnsproxytest.FQDN, tc.qtype)
			assertResponseCache(t, dnsproxytest.FQDN, dnsproxytest.TTL, req, tc.wantHit)
		})
	}
}

// assertResponseCache caches an A response for host with the given ttl and
// checks whether req produces a cache hit with the expected response.
func assertResponseCache(tb testing.TB, host string, ttl uint32, req *dns.Msg, wantHit bool) {
	testCache := newTestCache(tb, nil)
	request := dnsproxytest.NewTestRequestWithHost(host)
	reply := (&dns.Msg{
		Answer: []dns.RR{
			dnsproxytest.NewRR(tb, host, dns.TypeA, ttl, dnsproxytest.IPv4.To4()),
		},
	}).SetReply(request)
	testCache.set(request, reply, upstreamWithAddr, testLogger)

	ci, expired, _ := testCache.get(req)
	assert.False(tb, expired)
	if !wantHit {
		assert.Nil(tb, ci)

		return
	}

	require.NotNil(tb, ci)

	reply.SetReply(req)
	requireEqualMsgs(tb, reply, ci.m)
}

func TestCache_mixedCase(t *testing.T) {
	t.Parallel()

	const mixedCaseHost = "teST.ExAmPlE."
	testCases := []struct {
		name string
		host string
	}{{
		name: "mixed_case",
		host: mixedCaseHost,
	}, {
		name: "lower_case",
		host: dnsproxytest.FQDN,
	}, {
		name: "upper_case",
		host: strings.ToUpper(dnsproxytest.FQDN),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := dnsproxytest.NewTestRequestWithHost(tc.host)
			assertResponseCache(t, mixedCaseHost, dnsproxytest.TTL, req, true)
		})
	}
}

func TestCache_zeroTTL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		qtype uint16
	}{{
		name:  "same_type",
		qtype: dns.TypeA,
	}, {
		name:  "different_type",
		qtype: dns.TypeMX,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := (&dns.Msg{}).SetQuestion(dnsproxytest.FQDN, tc.qtype)
			assertResponseCache(t, dnsproxytest.FQDN, 0, req, false)
		})
	}
}

func TestCache_getWithSubnetEmpty(t *testing.T) {
	t.Parallel()

	c := newTestCache(t, &cacheConfig{withECS: true})
	req := dnsproxytest.NewTestRequest()

	ci, expired, _ := c.getWithSubnet(req, &net.IPNet{
		IP:   dnsproxytest.IPv4,
		Mask: net.CIDRMask(28, netutil.IPv4BitLen),
	})
	assert.Nil(t, ci)
	assert.False(t, expired)
}

func TestCache_getWithSubnetMiss(t *testing.T) {
	t.Parallel()

	c := newTestCache(t, &cacheConfig{withECS: true})
	req := dnsproxytest.NewTestRequest()
	resp := dnsproxytest.NewTestResponse(req)
	c.setWithSubnet(req, resp, upstreamWithAddr, &net.IPNet{
		IP:   dnsproxytest.IPv4,
		Mask: net.CIDRMask(26, netutil.IPv4BitLen),
	}, testLogger)

	ci, expired, key := c.getWithSubnet(req, &net.IPNet{
		IP:   testCacheIP1,
		Mask: net.CIDRMask(28, netutil.IPv4BitLen),
	})
	assert.False(t, expired)
	assert.Equal(t, msgToKeyWithSubnet(req, testCacheIP1, 0), key)
	assert.Nil(t, ci)
}

func TestCache_getWithSubnetHit(t *testing.T) {
	t.Parallel()

	c := newTestCache(t, &cacheConfig{withECS: true})
	mask26 := net.CIDRMask(26, netutil.IPv4BitLen)
	req := dnsproxytest.NewTestRequest()
	testCases := []struct {
		name string
		ip   net.IP
		mask int
	}{{
		name: "with_subnet_1",
		ip:   dnsproxytest.IPv4,
		mask: 26,
	}, {
		name: "with_subnet_2",
		ip:   testCacheIP1,
		mask: 26,
	}, {
		name: "without_subnet",
		ip:   testCacheIP2,
		mask: 0,
	}}

	for _, tc := range testCases {
		resp := (&dns.Msg{
			Answer: []dns.RR{
				dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeA, dnsproxytest.TTL, tc.ip),
			},
		}).SetReply(req)
		c.setWithSubnet(req, resp, upstreamWithAddr, &net.IPNet{
			IP:   tc.ip,
			Mask: net.CIDRMask(tc.mask, netutil.IPv4BitLen),
		}, testLogger)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ci, expired, key := c.getWithSubnet(req, &net.IPNet{
				IP:   tc.ip,
				Mask: net.CIDRMask(28, netutil.IPv4BitLen),
			})
			assert.False(t, expired)
			assert.Equal(t, msgToKeyWithSubnet(req, tc.ip.Mask(mask26), tc.mask), key)

			require.NotNil(t, ci)
			require.NotNil(t, ci.m)
			require.NotEmpty(t, ci.m.Answer)

			a := testutil.RequireTypeAssert[*dns.A](t, ci.m.Answer[0])
			assert.True(t, a.A.Equal(tc.ip))
		})
	}
}

func TestCache_getWithSubnetMask(t *testing.T) {
	noMatchIP := testCacheIP1
	testIP := testCacheIP3

	// cachedIP/cidrMask network contains the testIP.
	const cidrMaskOnes = 20
	cidrMask := net.CIDRMask(cidrMaskOnes, netutil.IPv4BitLen)
	cachedIP := testCacheIP3.Mask(cidrMask)

	ansIP := testCacheIP2

	c := newTestCache(t, &cacheConfig{
		withECS:    true,
		optimistic: true,
	})

	req := dnsproxytest.NewTestRequestWithHost(dnsproxytest.FQDN)
	resp := (&dns.Msg{
		Answer: []dns.RR{dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeA, 300, ansIP)},
	}).SetReply(req)

	// Cache IP network that contains the testIP.
	c.setWithSubnet(
		req,
		resp,
		upstreamWithAddr,
		&net.IPNet{IP: cachedIP, Mask: cidrMask},
		testLogger,
	)

	require.True(t, t.Run("mask_matched", func(t *testing.T) {
		ci, expired, key := c.getWithSubnet(req, &net.IPNet{
			IP:   testCacheIP3,
			Mask: net.CIDRMask(24, netutil.IPv4BitLen),
		})
		assert.False(t, expired)
		assert.Equal(t, msgToKeyWithSubnet(req, testIP.Mask(cidrMask), cidrMaskOnes), key)

		require.NotNil(t, ci)
		require.NotNil(t, ci.m)
		require.NotEmpty(t, ci.m.Answer)

		a := testutil.RequireTypeAssert[*dns.A](t, ci.m.Answer[0])
		assert.True(t, a.A.Equal(ansIP))
	}))

	require.True(t, t.Run("no_mask_matched", func(t *testing.T) {
		ci, expired, key := c.getWithSubnet(req, &net.IPNet{
			IP:   noMatchIP,
			Mask: net.CIDRMask(24, netutil.IPv4BitLen),
		})
		assert.False(t, expired)
		assert.Equal(t, msgToKeyWithSubnet(req, noMatchIP, 0), key)
		assert.Nil(t, ci)
	}))
}

func TestCacheTTL_isCacheableNegative(t *testing.T) {
	t.Parallel()

	question := []dns.Question{{
		Name:   dnsproxytest.FQDN,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}

	cnameRR := dnsproxytest.NewRR(
		t,
		dnsproxytest.FQDN,
		dns.TypeCNAME,
		testTTL,
		"alias."+dnsproxytest.FQDN,
	)
	soa := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeSOA, testTTL, nil)
	nsRR1 := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeNS, testTTL, "ns1."+dnsproxytest.FQDN)
	nsRR2 := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeNS, testTTL, "ns2."+dnsproxytest.FQDN)
	extra := []dns.RR{
		dnsproxytest.NewRR(t, "ns1."+dnsproxytest.FQDN, dns.TypeA, testTTL, testCacheIP1),
		dnsproxytest.NewRR(t, "ns2."+dnsproxytest.FQDN, dns.TypeA, testTTL, testCacheIP2),
	}

	// See https://datatracker.ietf.org/doc/html/rfc2308.
	testCases := []struct {
		req     *dns.Msg
		name    string
		wantTTL uint32
	}{{
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeNameError},
			Question: question,
			Answer:   []dns.RR{cnameRR},
			Ns:       []dns.RR{soa, nsRR1, nsRR2},
			Extra:    extra,
		},
		name:    "rfc2308_nxdomain_response_type_1",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeNameError},
			Question: question,
			Answer:   []dns.RR{cnameRR},
			Ns:       []dns.RR{soa},
		},
		name:    "rfc2308_nxdomain_response_type_2",
		wantTTL: testTTL,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeNameError},
			Question: question,
			Answer:   []dns.RR{cnameRR},
		},
		name:    "rfc2308_nxdomain_response_type_3",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeNameError},
			Question: question,
			Answer:   []dns.RR{cnameRR},
			Ns:       []dns.RR{nsRR1, nsRR2},
			Extra:    extra,
		},
		name:    "rfc2308_nxdomain_response_type_4",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Question: question,
			Answer:   []dns.RR{cnameRR},
			Ns:       []dns.RR{nsRR1, nsRR2},
			Extra:    extra,
		},
		name:    "rfc2308_nxdomain_referral_response",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeServerFailure},
			Question: question,
		},
		name:    "servfail_response",
		wantTTL: ServFailMaxCacheTTL,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.wantTTL, cacheTTL(tc.req, testLogger))
		})
	}
}

func TestCacheTTL_isCacheableNegativeNoData(t *testing.T) {
	t.Parallel()

	question := dnsproxytest.NewTestRequest().Question
	soa := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeSOA, testTTL, nil)
	nsRR1 := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeNS, testTTL, "ns1."+dnsproxytest.FQDN)
	nsRR2 := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeNS, testTTL, "ns2."+dnsproxytest.FQDN)
	extra := []dns.RR{
		dnsproxytest.NewRR(t, "ns1."+dnsproxytest.FQDN, dns.TypeA, testTTL, testCacheIP1),
		dnsproxytest.NewRR(t, "ns2."+dnsproxytest.FQDN, dns.TypeA, testTTL, testCacheIP2),
	}

	// See https://datatracker.ietf.org/doc/html/rfc2308.
	testCases := []struct {
		req     *dns.Msg
		name    string
		wantTTL uint32
	}{{
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Question: question,
			Ns: []dns.RR{
				soa, nsRR1, nsRR2,
			},
			Extra: extra,
		},
		name:    "rfc2308_nodata_response_type_1",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Question: question,
			Ns:       []dns.RR{soa},
		},
		name:    "rfc2308_nodata_response_type_2",
		wantTTL: testTTL,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Question: question,
		},
		name:    "rfc2308_nodata_response_type_3",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Question: question,
			Ns:       []dns.RR{nsRR1, nsRR2},
			Extra:    extra,
		},
		name:    "rfc2308_nodata_referral_response",
		wantTTL: 0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.wantTTL, cacheTTL(tc.req, testLogger))
		})
	}
}

// setAndGetCache is a helper that checks cache storage, retrieval, and
// expiration for host.  It is intended to be used as a goroutine.
func setAndGetCache(tb testing.TB, c *cache, g *sync.WaitGroup, host, ip string) {
	tb.Helper()

	defer g.Done()

	pt := testutil.NewPanicT(tb)

	ipAddr := net.ParseIP(ip)

	req := dnsproxytest.NewTestRequestWithHost(host)

	dnsMsg := (&dns.Msg{
		Response: true,
		Answer:   []dns.RR{dnsproxytest.NewRR(tb, host, dns.TypeA, 1, ipAddr)},
	}).SetQuestion(host, dns.TypeA)

	c.set(req, dnsMsg, upstreamWithAddr, testLogger)

	for range 2 {
		ci, expired, key := c.get(dnsMsg)
		require.NotNilf(pt, ci, "no cache found for %s", host)

		assert.False(pt, expired)
		assert.Equal(pt, msgToKey(req), key)

		requireEqualMsgs(pt, ci.m, dnsMsg)
	}

	assert.Eventuallyf(pt, func() bool {
		ci, _, _ := c.get(req)

		return ci == nil
	}, testCacheTimeout, testCacheTick, "cache for %s should already be removed", host)
}

// requireEqualMsgs asserts the messages are equal.  It only compares rcodes,
// question and answer names, and A record values.
func requireEqualMsgs(t testutil.RequireT, expected, got *dns.Msg) {
	t.Helper()

	require.Equal(t, expected.Rcode, got.Rcode)
	require.Len(t, got.Question, len(expected.Question))

	for i := range expected.Question {
		want, got := expected.Question[i], got.Question[i]
		require.True(t, strings.EqualFold(want.Name, got.Name))
		assert.Equal(t, want.Qtype, got.Qtype)
	}

	require.Len(t, got.Answer, len(expected.Answer))
	for i, want := range expected.Answer {
		wantA := testutil.RequireTypeAssert[*dns.A](t, want)
		gotA := testutil.RequireTypeAssert[*dns.A](t, got.Answer[i])

		assert.Equal(t, wantA.A, gotA.A.To4())
	}
}
