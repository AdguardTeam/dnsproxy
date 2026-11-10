package proxy

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/contextutil"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/mathutil/randutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	listenIP = "127.0.0.1"

	// defaultTestTTL used to guarantee caching.
	defaultTestTTL = 1000

	// testCacheMinTTL is the minimum cache TTL for tests.
	testCacheMinTTL = 20

	// testCacheMaxTTL is the maximum cache TTL for tests.
	testCacheMaxTTL = 40

	// testOptimisticTTL is a common optimistic cache ttl value for tests.
	testOptimisticTTL = 10 * time.Second

	// testOptimisticMaxAge is a common optimistic max age value for tests.
	testOptimisticMaxAge = 12 * time.Hour
)

// testLogger is a common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// Common IP addr strings for tests.
//
// TODO(f.setrakov): Use TEST-NET-1 addresses.
const (
	testECSPort = ":1234"

	testECSIPSubnet1Str = "1.2.3.0"
	testECSIPSubnet2Str = "2.2.3.0"
)

// Common IP addrs for tests.
var (
	testECSIPSubnet1 = net.ParseIP(testECSIPSubnet1Str).To4()
	testECSIPSubnet2 = net.ParseIP(testECSIPSubnet2Str).To4()
)

// mustNew wraps [New] function failing the test on error.
//
// TODO(e.burkov):  Move into the proxytest package.
//
// TODO(e.burkov):  Put default values into configuration.
func mustNew(tb testing.TB, conf *Config) (p *Proxy) {
	tb.Helper()

	p, err := New(conf)
	require.NoError(tb, err)

	return p
}

// firstIP returns the first IP address from the DNS response.
func firstIP(resp *dns.Msg) (ip net.IP) {
	for _, ans := range resp.Answer {
		a, ok := ans.(*dns.A)
		if !ok {
			continue
		}

		return a.A
	}

	return nil
}

// newTestUpstream returns default upstream mock, which responds with single A
// record with [dnsproxytest.IPv4] value to all requests.  Other upstream
// methods will be replaced with stub implementations.
func newTestUpstream(tb testing.TB) (uc upstream.Upstream) {
	tb.Helper()

	onExchange := func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		return dnsproxytest.NewTestResponse(req), nil
	}

	return newTestUpstreamWithExchange(tb, onExchange)
}

// newTestUpstreamWithExchange returns upstream mock which uses given callback
// for [upstream.Upstream.Exchange] implementation.  Other upstream methods will
// be replaced with stub implementations.
func newTestUpstreamWithExchange(
	tb testing.TB,
	onExchange func(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error),
) (uc upstream.Upstream) {
	tb.Helper()

	return &testUpstream{
		OnAddress:  func() (addr string) { return "" },
		OnExchange: onExchange,
		OnClose:    func() (err error) { return nil },
	}
}

// newDNSContext returns new DNS request message context with Proto set to
// [ProtoUDP].  Constructs request message from the given parameters.
func newDNSContext(
	domain string,
	qtype uint16,
	qclass uint16,
	edns bool,
	udpsize uint16,
) (dctx *DNSContext) {
	req := newReq(domain, qtype, qclass)
	if edns {
		req.SetEdns0(udpsize, true)
	}

	return &DNSContext{
		Req:   req,
		Proto: ProtoUDP,
	}
}

// newReq returns new request message for provided parameters.
func newReq(domain string, qtype, qclass uint16) (req *dns.Msg) {
	return &dns.Msg{
		Id:       dns.Id(),
		Compress: true,
		Question: []dns.Question{{
			Name:   dns.Fqdn(domain),
			Qtype:  qtype,
			Qclass: qclass,
		}},
	}
}

func TestProxy_Resolve_dnssecCacheA(t *testing.T) {
	t.Parallel()

	a := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeA, 0, dnsproxytest.IPv4.To4())
	p, rrsig := setupProxyResolveDNSSECCache(t, a)

	require.True(t, t.Run("no_edns", func(t *testing.T) {
		testProxyResolveDNSSECCache(t, p, a, rrsig, 1, false)
	}))

	require.True(t, t.Run("edns", func(t *testing.T) {
		testProxyResolveDNSSECCache(t, p, a, rrsig, 2, true)
	}))
}

func TestProxy_Resolve_dnssecCacheTXT(t *testing.T) {
	t.Parallel()

	const (
		txtDataLen      = 1024
		txtDataChunkLen = 255
	)

	rng := rand.New(rand.NewChaCha8([32]byte{}))
	txtData := randutil.StringASCII(rng, txtDataLen)
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dnsproxytest.FQDN,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
		},
	}
	for chunk := range slices.Chunk([]byte(txtData), txtDataChunkLen) {
		txt.Txt = append(txt.Txt, string(chunk))
	}

	p, rrsig := setupProxyResolveDNSSECCache(t, txt)

	require.True(t, t.Run("no_edns", func(t *testing.T) {
		testProxyResolveDNSSECCache(t, p, txt, rrsig, 1, false)
	}))

	require.True(t, t.Run("edns", func(t *testing.T) {
		testProxyResolveDNSSECCache(t, p, txt, rrsig, 0, true)
	}))
}

func TestProxy_Resolve_dnssecCacheDS(t *testing.T) {
	t.Parallel()

	const digest = "736f6d652064656c65676174696f6e207369676e6572"

	ds := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   dnsproxytest.FQDN,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
		},
		Digest: digest,
	}

	p, rrsig := setupProxyResolveDNSSECCache(t, ds)

	require.True(t, t.Run("no_edns", func(t *testing.T) {
		testProxyResolveDNSSECCache(t, p, ds, rrsig, 1, false)
	}))

	require.True(t, t.Run("edns", func(t *testing.T) {
		testProxyResolveDNSSECCache(t, p, ds, rrsig, 2, true)
	}))
}

// testProxyResolveDNSSECCache checks response and cache for wantAns and rrsig.
// wantLen must be 0 (truncated), 1 (answer only), or 2 (answer and signature).
func testProxyResolveDNSSECCache(
	tb testing.TB,
	p *Proxy,
	wantAns dns.RR,
	rrsig *dns.RRSIG,
	wantLen int,
	edns bool,
) {
	tb.Cleanup(p.cache.items.Clear)

	ansHdr := wantAns.Header()
	assert.Equal(tb, ansHdr.Rrtype, rrsig.TypeCovered)

	dctx := newDNSContext(ansHdr.Name, ansHdr.Rrtype, ansHdr.Class, edns, dns.MinMsgSize)
	err := p.Resolve(testutil.ContextWithTimeout(tb, defaultTimeout), dctx)
	require.NoError(tb, err)

	res := dctx.Res
	require.NotNil(tb, res)

	require.Len(tb, res.Answer, wantLen, res.Answer)
	switch wantLen {
	case 0:
		assert.True(tb, res.Truncated)
	case 1:
		res.Answer[0].Header().Ttl = defaultTestTTL
		assert.Equal(tb, wantAns, res.Answer[0])
	case 2:
		res.Answer[0].Header().Ttl = defaultTestTTL
		assert.Equal(tb, wantAns, res.Answer[0])
		assert.Equal(tb, rrsig, res.Answer[1])
	default:
		tb.Fatalf("wanted length has unexpected value %d", wantLen)
	}

	cached, expired, key := p.cache.get(dctx.Req)
	require.NotNil(tb, cached)
	require.Len(tb, cached.m.Answer, 2)

	assert.False(tb, expired)
	assert.Equal(tb, key, msgToKey(dctx.Req))

	cached.m.Answer[0].Header().Ttl = defaultTestTTL
	assert.Equal(tb, wantAns.String(), cached.m.Answer[0].String())
	assert.Equal(tb, rrsig.String(), cached.m.Answer[1].String())
}

// setupProxyResolveDNSSECCache is a helper that creates a caching proxy and
// signature for wantAns.
func setupProxyResolveDNSSECCache(tb testing.TB, wantAns dns.RR) (p *Proxy, rrsig *dns.RRSIG) {
	tb.Helper()

	const signature = "c29tZSBycnNpZyByZWxhdGVkIHN0dWZm"

	ansHdr := wantAns.Header()
	rrsig = &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   ansHdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    defaultTestTTL,
		},
		TypeCovered: ansHdr.Rrtype,
		Algorithm:   8,
		Labels:      uint8(dns.CountLabel(ansHdr.Name)),
		SignerName:  ansHdr.Name,
		Signature:   signature,
	}

	u := &testUpstream{
		OnExchange: func(_ context.Context, m *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(m)

			if m.Question[0].Qtype == ansHdr.Rrtype {
				resp.Answer = append(resp.Answer, wantAns)
				ansHdr.Ttl = defaultTestTTL
			}

			if o := m.IsEdns0(); o != nil {
				resp.Answer = append(resp.Answer, rrsig)
				resp.SetEdns0(defaultUDPBufSize, o.Do())
			}

			return resp, nil
		},
		OnAddress: func() (addr string) { return "" },
		OnClose:   func() (err error) { return nil },
	}

	p = mustNew(tb, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr:  []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		CacheEnabled:   true,
		DNSSECEnabled:  true,
		CacheSizeBytes: dnsproxytest.CacheSize,
	})

	return p, rrsig
}

func TestProxy_Resolve_exchangeCustomUpstreamConfig(t *testing.T) {
	p := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(t)},
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	})

	servicetest.RequireRun(t, p, dnsproxytest.Timeout)

	ans := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeA,
			Name:   dns.Fqdn(dnsproxytest.Host),
			Ttl:    60,
		},
		A: dnsproxytest.IPv4,
	}}

	onExchange := newECSReplyHandler(&ans, nil, nil)
	u := newTestUpstreamWithExchange(t, onExchange)

	d := &DNSContext{
		CustomUpstreamConfig: NewCustomUpstreamConfig(
			&UpstreamConfig{Upstreams: []upstream.Upstream{u}},
			false,
			0,
			false,
		),
		Req:  dnsproxytest.NewTestRequest(),
		Addr: netip.MustParseAddrPort("192.0.2.0:1234"),
	}

	err := p.Resolve(testutil.ContextWithTimeout(t, defaultTimeout), d)
	require.NoError(t, err)

	assert.Equal(t, dnsproxytest.IPv4, firstIP(d.Res))
}

func TestProxy_Resolve_customUpstreamConfigCache(t *testing.T) {
	prx := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(t)},
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		CacheEnabled:   true,
		DNSSECEnabled:  true,
	})

	servicetest.RequireRun(t, prx, dnsproxytest.Timeout)

	var count int

	exchangeFunc := func(_ context.Context, m *dns.Msg) (resp *dns.Msg, err error) {
		resp = &dns.Msg{}
		resp.SetReply(m)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Class:  dns.ClassINET,
				Rrtype: dns.TypeA,
				Ttl:    defaultTestTTL,
			},
			A: dnsproxytest.IPv4,
		})

		count++

		return resp, nil
	}
	u := &testUpstream{
		OnExchange: exchangeFunc,
		OnAddress:  func() (addr string) { return "stub" },
		OnClose:    func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	customUpstreamConfig := NewCustomUpstreamConfig(
		&UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		true,
		dnsproxytest.CacheSize,
		prx.enableEDNSClientSubnet,
	)

	d := &DNSContext{
		CustomUpstreamConfig: customUpstreamConfig,
		Req:                  dnsproxytest.NewTestRequestWithHost("host"),
		Addr:                 netip.MustParseAddrPort("192.0.2.0:1234"),
	}

	ctx := testutil.ContextWithTimeout(t, defaultTimeout)
	err := prx.Resolve(ctx, d)
	require.NoError(t, err)

	require.Equal(t, 1, count)
	assert.Equal(t, dnsproxytest.IPv4, firstIP(d.Res).To16())

	err = prx.Resolve(ctx, d)
	require.NoError(t, err)

	assert.Equal(t, 1, count)
	assert.Equal(t, dnsproxytest.IPv4, firstIP(d.Res).To16())

	customUpstreamConfig.ClearCache()

	err = prx.Resolve(ctx, d)
	require.NoError(t, err)

	assert.Equal(t, 2, count)
	assert.Equal(t, dnsproxytest.IPv4, firstIP(d.Res).To16())
}

func TestSetECS(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		ip := net.IP{1, 2, 3, 4}

		m := &dns.Msg{}
		subnet := setECS(m, ip, 16)

		ones, _ := subnet.Mask.Size()
		assert.Equal(t, 24, ones)

		var scope int
		subnet, scope = ecsFromMsg(m)
		assert.Equal(t, ip.Mask(subnet.Mask), subnet.IP)

		ones, _ = subnet.Mask.Size()
		assert.Equal(t, 24, ones)
		assert.Equal(t, 16, scope)
	})

	t.Run("ipv6", func(t *testing.T) {
		ip := net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		m := &dns.Msg{}
		subnet := setECS(m, ip, 48)

		ones, _ := subnet.Mask.Size()
		assert.Equal(t, 56, ones)

		var scope int
		subnet, scope = ecsFromMsg(m)
		assert.Equal(t, ip.Mask(subnet.Mask), subnet.IP)

		ones, _ = subnet.Mask.Size()
		assert.Equal(t, 56, ones)
		assert.Equal(t, 48, scope)
	})
}

func TestProxy_Resolve_ecs(t *testing.T) {
	var (
		ans      []dns.RR
		ecsIP    net.IP
		ecsReqIP net.IP
	)

	onExchange := newECSReplyHandler(&ans, &ecsIP, &ecsReqIP)
	u := newTestUpstreamWithExchange(t, onExchange)

	prx := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{u},
		},
		TrustedProxies:         dnsproxytest.DefaultTrustedProxies,
		DNSSECEnabled:          true,
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
	})

	servicetest.RequireRun(t, prx, dnsproxytest.Timeout)

	require.True(t, t.Run("cache_subnet", func(t *testing.T) {
		ans = []dns.RR{dnsproxytest.NewRR(
			t,
			dnsproxytest.FQDN,
			dns.TypeA,
			dnsproxytest.TTL,
			testCacheIP1,
		)}
		ecsIP = testECSIPSubnet1

		addr := testECSIPSubnet1Str + testECSPort
		testProxyResolveECS(t, prx, addr, testCacheIP1, ecsIP, &ecsReqIP)
	}))

	require.True(t, t.Run("serve_subnet_cache", func(t *testing.T) {
		ans, ecsIP = nil, nil

		addr := "1.2.3.1" + testECSPort
		testProxyResolveECS(t, prx, addr, testCacheIP1, nil, &ecsReqIP)
	}))

	require.True(t, t.Run("another_subnet", func(t *testing.T) {
		ans = []dns.RR{dnsproxytest.NewRR(
			t,
			dnsproxytest.FQDN,
			dns.TypeA,
			dnsproxytest.TTL,
			testCacheIP2,
		)}
		ecsIP = testECSIPSubnet2

		addr := testECSIPSubnet2Str + testECSPort
		testProxyResolveECS(t, prx, addr, testCacheIP2, ecsIP, &ecsReqIP)
	}))

	require.True(t, t.Run("cache_general", func(t *testing.T) {
		ans = []dns.RR{dnsproxytest.NewRR(
			t,
			dnsproxytest.FQDN,
			dns.TypeA,
			dnsproxytest.TTL,
			testCacheIP3,
		)}
		ecsIP = nil

		testProxyResolveECS(t, prx, listenIP+testECSPort, testCacheIP3, nil, &ecsReqIP)
	}))

	require.True(t, t.Run("serve_general_cache", func(t *testing.T) {
		ans, ecsIP = nil, nil

		testProxyResolveECS(t, prx, "127.0.0.2"+testECSPort, testCacheIP3, nil, &ecsReqIP)
	}))
}

// testProxyResolveECS resolves addr using p, checking wantIP in the answer and
// wantECSIP in ecsReqIP.
func testProxyResolveECS(
	tb testing.TB,
	p *Proxy,
	addr string,
	wantIP net.IP,
	wantECSIP net.IP,
	ecsReqIP *net.IP,
) {
	*ecsReqIP = nil
	d := &DNSContext{
		Req:  dnsproxytest.NewTestRequest(),
		Addr: netip.MustParseAddrPort(addr),
	}

	ctx := testutil.ContextWithTimeout(tb, defaultTimeout)
	err := p.Resolve(ctx, d)
	require.NoError(tb, err)

	assert.Equal(tb, wantIP, firstIP(d.Res))
	assert.Equal(tb, wantECSIP, *ecsReqIP)
}

func TestProxy_Resolve_ecsProxyCacheMinMaxTTL(t *testing.T) {
	t.Parallel()

	t.Run("min", func(t *testing.T) {
		t.Parallel()

		testProxyResolveECSCacheTTL(t, testCacheMinTTL/2, testCacheMinTTL)
	})

	t.Run("max", func(t *testing.T) {
		t.Parallel()

		testProxyResolveECSCacheTTL(t, dnsproxytest.TTL, testCacheMaxTTL)
	})
}

// testProxyResolveECSCacheTTL checks that an upstream answer with ttl is cached
// with wantTTL after applying ECS cache TTL limits.
func testProxyResolveECSCacheTTL(tb testing.TB, ttl, wantTTL uint32) {
	req := dnsproxytest.NewTestRequest()
	subnet := setECS(req, dnsproxytest.IPv4, 0)
	ans := []dns.RR{dnsproxytest.NewRR(
		tb,
		dnsproxytest.FQDN,
		dns.TypeA,
		ttl,
		dnsproxytest.IPv4.To4(),
	)}
	onExchange := newECSReplyHandler(&ans, &subnet.IP, nil)
	u := newTestUpstreamWithExchange(tb, onExchange)

	udpAddr := dnsproxytest.LocalhostAnyPortUDP
	tcpAddr := dnsproxytest.LocalhostAnyPortTCP

	p := mustNew(tb, &Config{
		Logger:                 testLogger,
		UDPListenAddr:          []*net.UDPAddr{udpAddr},
		TCPListenAddr:          []*net.TCPAddr{tcpAddr},
		UpstreamConfig:         &UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		TrustedProxies:         dnsproxytest.DefaultTrustedProxies,
		DNSSECEnabled:          true,
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
		CacheMinTTL:            testCacheMinTTL,
		CacheMaxTTL:            testCacheMaxTTL,
	})

	servicetest.RequireRun(tb, p, dnsproxytest.Timeout)

	d := &DNSContext{
		Req:  req,
		Addr: testRaddr,
	}
	ctx := testutil.ContextWithTimeout(tb, defaultTimeout)
	err := p.Resolve(ctx, d)
	require.NoError(tb, err)

	ci, expired, key := p.cache.getWithSubnet(d.Req, subnet)
	require.NotNil(tb, ci)
	require.Len(tb, ci.m.Answer, 1)

	ones, _ := subnet.Mask.Size()
	assert.False(tb, expired)
	assert.Equal(tb, key, msgToKeyWithSubnet(d.Req, subnet.IP, ones))

	// TODO(f.setrakov): Make this assertion wall-clock independent.
	assert.Equal(tb, wantTTL, ci.m.Answer[0].Header().Ttl)
}

func TestProxy_Resolve_withOptimisticResolver(t *testing.T) {
	t.Parallel()

	p, firstCtx, secondCtx, out, in := setupProxyResolveWithOptimisticResolver(t)
	ctx := testutil.ContextWithTimeout(t, defaultTimeout)

	err := p.Resolve(ctx, firstCtx)
	require.NoError(t, err)
	require.Len(t, firstCtx.Res.Answer, 1)

	assert.Equal(t, uint32(testOptimisticTTL.Seconds()), firstCtx.Res.Answer[0].Header().Ttl)

	<-out

	err = p.Resolve(ctx, secondCtx)
	require.NoError(t, err)
	require.Len(t, secondCtx.Res.Answer, 1)

	assert.Equal(t, uint32(testOptimisticTTL.Seconds()), secondCtx.Res.Answer[0].Header().Ttl)

	in <- unit{}
	<-out

	data := p.cache.items.Get(msgToKey(firstCtx.Req))
	unpacked, expired := p.cache.unpackItem(data, firstCtx.Req)
	require.False(t, expired)
	require.NotNil(t, unpacked)
	require.Len(t, unpacked.m.Answer, 1)

	// TODO(f.setrakov): Make this assertion wall-clock independent.
	assert.EqualValues(t, testTTL, unpacked.m.Answer[0].Header().Ttl)
}

// setupProxyResolveWithOptimisticResolver sets up the optimistic resolver for
// test.
func setupProxyResolveWithOptimisticResolver(tb testing.TB) (
	p *Proxy,
	firstCtx *DNSContext,
	secondCtx *DNSContext,
	out chan unit,
	in chan unit,
) {
	tb.Helper()

	buildCtx := func() (dctx *DNSContext) {
		req := &dns.Msg{
			Id: dns.Id(),
			Question: []dns.Question{{
				Name:   dnsproxytest.FQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		return &DNSContext{Req: req}
	}
	buildResp := func(req *dns.Msg, ttl uint32) (resp *dns.Msg) {
		resp = (&dns.Msg{}).SetReply(req)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   dnsproxytest.FQDN,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: dnsproxytest.IPv4.To4(),
		}}

		return resp
	}

	p = &Proxy{
		reqCtx:                   contextutil.EmptyConstructor{},
		requestHandler:           DefaultHandler{},
		cacheEnabled:             true,
		cacheOptimistic:          true,
		cacheOptimisticAnswerTTL: testOptimisticTTL,
		cacheOptimisticMaxAge:    testOptimisticMaxAge,
		dnsSecEnabled:            true,
		// TODO(e.burkov):  Set panicking upstream configuration.
		logger:          testLogger,
		pendingRequests: newDefaultPendingRequests(),
		mu:              &sync.RWMutex{},
	}

	p.initCache()
	out, in = make(chan unit), make(chan unit)
	p.shortFlighter.cr = &testCachingResolver{
		onReplyFromUpstream: func(_ context.Context, dctx *DNSContext) (ok bool, err error) {
			dctx.Res = buildResp(dctx.Req, testTTL)

			return true, nil
		},
		onCacheResp: func(ctx context.Context, dctx *DNSContext) {
			// Report adding to cache is in process.
			out <- unit{}
			// Wait for tests to finish.
			<-in

			p.cacheResp(ctx, dctx)

			// Report adding to cache is finished.
			out <- unit{}
		},
	}

	// Two different contexts are made to emulate two different requests
	// with the same question section.
	firstCtx, secondCtx = buildCtx(), buildCtx()

	// Add expired response into cache.
	req := firstCtx.Req.Copy()
	p.addDO(req)
	key := msgToKey(req)
	data := (&cacheItem{
		m: buildResp(req, 0),
		u: testUpsAddr,
	}).pack()
	items := glcache.New(glcache.Config{
		EnableLRU: true,
	})
	items.Set(key, data)
	p.cache.items = items

	return p, firstCtx, secondCtx, out, in
}

func TestProxy_ValidateRequest_general(t *testing.T) {
	t.Parallel()

	p := setupProxyValidateRequest(t)

	testCases := []struct {
		req       *dns.Msg
		name      string
		wantRcode int
	}{{
		name:      "valid_request",
		req:       dnsproxytest.NewTestRequest(),
		wantRcode: dns.RcodeSuccess,
	}, {
		name: "no_questions",
		req: &dns.Msg{
			Id:       dns.Id(),
			Question: []dns.Question{},
		},
		wantRcode: dns.RcodeFormatError,
	}, {
		name:      "refuse_any",
		req:       (&dns.Msg{}).SetQuestion(dnsproxytest.FQDN, dns.TypeANY),
		wantRcode: dns.RcodeNotImplemented,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testProxyValidateRequest(t, p, &DNSContext{
				Req:  tc.req,
				Addr: testRaddr,
			}, tc.wantRcode)
		})
	}
}

func TestProxy_ValidateRequest_arpa(t *testing.T) {
	t.Parallel()

	p := setupProxyValidateRequest(t)
	privateARPAFQDN, err := dns.ReverseAddr(testCacheIPStr3)
	require.NoError(t, err)

	publicARPAFQDN, err := dns.ReverseAddr(testIPStr1)
	require.NoError(t, err)

	privateAddr := netip.AddrPortFrom(netip.MustParseAddr(testCacheIPStr3), testRaddr.Port())
	testCases := []struct {
		addr            netip.AddrPort
		name            string
		fqdn            string
		wantRcode       int
		qtype           uint16
		isPrivateClient bool
	}{{
		name:            "private_arpa_from_public_client",
		fqdn:            privateARPAFQDN,
		qtype:           dns.TypePTR,
		addr:            testRaddr,
		wantRcode:       dns.RcodeNameError,
		isPrivateClient: false,
	}, {
		name:            "private_arpa_from_private_client",
		fqdn:            privateARPAFQDN,
		qtype:           dns.TypePTR,
		addr:            privateAddr,
		wantRcode:       dns.RcodeSuccess,
		isPrivateClient: true,
	}, {
		name:            "private_arpa_soa_from_public_client",
		fqdn:            privateARPAFQDN,
		qtype:           dns.TypeSOA,
		addr:            testRaddr,
		wantRcode:       dns.RcodeNameError,
		isPrivateClient: false,
	}, {
		name:            "private_arpa_ns_from_public_client",
		fqdn:            privateARPAFQDN,
		qtype:           dns.TypeNS,
		addr:            testRaddr,
		wantRcode:       dns.RcodeNameError,
		isPrivateClient: false,
	}, {
		name:            "public_arpa",
		fqdn:            publicARPAFQDN,
		qtype:           dns.TypePTR,
		addr:            testRaddr,
		wantRcode:       dns.RcodeSuccess,
		isPrivateClient: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testProxyValidateRequest(t, p, &DNSContext{
				Req:             (&dns.Msg{}).SetQuestion(tc.fqdn, tc.qtype),
				Addr:            tc.addr,
				IsPrivateClient: tc.isPrivateClient,
			}, tc.wantRcode)
		})
	}
}

// setupProxyValidateRequest creates a proxy with request validation enabled.
func setupProxyValidateRequest(tb testing.TB) (p *Proxy) {
	tb.Helper()

	privateNets := netutil.SliceSubnetSet{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/8"),
	}
	ups := &testUpstream{
		OnExchange: func(_ context.Context, m *dns.Msg) (resp *dns.Msg, err error) {
			resp = &dns.Msg{}
			resp.SetReply(m)

			return resp, nil
		},
		OnAddress: func() (addr string) { return "stub" },
		OnClose:   func() (err error) { return nil },
	}

	return mustNew(tb, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{ups}},
		RefuseAny:      true,
		PrivateSubnets: privateNets,
	})
}

// testProxyValidateRequest checks that the dctx validation results in the
// wantRcode.  For [dns.RcodeSuccess], a nil resp is expected.
func testProxyValidateRequest(tb testing.TB, p *Proxy, dctx *DNSContext, wantRcode int) {
	resp := p.validateRequest(dctx)
	if wantRcode == dns.RcodeSuccess {
		assert.Nil(tb, resp)

		return
	}

	require.NotNil(tb, resp)
	assert.Equal(tb, wantRcode, resp.Rcode)
}

// testHandler is a mock request handler implementation to simplify
// testing.
//
// TODO(m.kazantsev):  Use [dnsproxytest.Handler].
type testHandler struct {
	OnHandle func(ctx context.Context, p *Proxy, dctx *DNSContext) (err error)
}

// type check
var _ Handler = (*testHandler)(nil)

// ServeDNS implements the [Handler] interface for *testHandler.
func (h *testHandler) ServeDNS(ctx context.Context, p *Proxy, dctx *DNSContext) (err error) {
	return h.OnHandle(ctx, p, dctx)
}

// testUpstream is a mock upstream implementation to simplify testing.
//
// TODO(m.kazantsev):  Use [dnsproxytest.Upstream].
type testUpstream struct {
	OnAddress  func() (addr string)
	OnExchange func(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error)
	OnClose    func() (err error)
}

// newECSReplyHandler creates an OnExchange handler that builds a DNS reply
// with optional answer records and ECS support.
//
// The handler dereferences ans, ecsIP, and ecsReqIP at call time, so tests
// can reassign those variables between sub-tests and the handler will see
// the current values.
func newECSReplyHandler(
	ans *[]dns.RR,
	ecsIP *net.IP,
	ecsReqIP *net.IP,
) func(context.Context, *dns.Msg) (*dns.Msg, error) {
	return func(_ context.Context, m *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(m)

		if ans != nil && *ans != nil {
			resp.Answer = append(resp.Answer, *ans...)
		}

		if ecsIP != nil && *ecsIP != nil {
			setECS(resp, *ecsIP, 24)
		}

		if ecsReqIP == nil {
			return resp, nil
		}

		ecs, _ := ecsFromMsg(m)
		if ecs != nil {
			*ecsReqIP = ecs.IP
		}

		return resp, nil
	}
}

// type check
var _ upstream.Upstream = (*testUpstream)(nil)

// Exchange implements the upstream.Upstream interface for *testUpstream.
func (u *testUpstream) Exchange(ctx context.Context, m *dns.Msg) (resp *dns.Msg, err error) {
	return u.OnExchange(ctx, m)
}

// Address implements the upstream.Upstream interface for *testUpstream.
func (u *testUpstream) Address() (addr string) {
	return u.OnAddress()
}

// Close implements the upstream.Upstream interface for *testUpstream.
func (u *testUpstream) Close() (err error) {
	return u.OnClose()
}
