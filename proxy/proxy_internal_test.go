package proxy

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/contextutil"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	listenIP                = "127.0.0.1"
	testDefaultUpstreamAddr = "8.8.8.8:53"

	// defaultTestTTL used to guarantee caching.
	defaultTestTTL = 1000

	// testOptimisticTTL is a common optimistic cache ttl value for tests.
	testOptimisticTTL = 10 * time.Second

	// testOptimisticMaxAge is a common optimistic max age value for tests.
	testOptimisticMaxAge = 12 * time.Hour
)

// testLogger is a common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

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

// newTestUpstreamConfigWithBoot creates a new UpstreamConfig with upstream
// addresses and a bootstrapped resolver.
func newTestUpstreamConfigWithBoot(
	t require.TestingT,
	timeout time.Duration,
	addrs ...string,
) (u *UpstreamConfig) {
	googleRslv, err := upstream.NewUpstreamResolver(
		"8.8.8.8:53",
		&upstream.Options{
			Logger:  testLogger,
			Timeout: timeout,
		},
	)
	require.NoError(t, err)

	upsConf, err := ParseUpstreamsConfig(addrs, &upstream.Options{
		Logger:    testLogger,
		Timeout:   timeout,
		Bootstrap: upstream.NewCachingResolver(googleRslv),
	})
	require.NoError(t, err)

	return upsConf
}

// newTestUpstreamConfig creates a new UpstreamConfig with given upstream
// addresses and timeout.
func newTestUpstreamConfig(
	tb testing.TB,
	timeout time.Duration,
	addrs ...string,
) (u *UpstreamConfig) {
	tb.Helper()

	upsConf, err := ParseUpstreamsConfig(addrs, &upstream.Options{
		Logger:  testLogger,
		Timeout: timeout,
	})
	require.NoError(tb, err)

	return upsConf
}

// newTxts returns new test TXT RR strings.
func newTxts(tb testing.TB, txtDataLen int) (txts []string) {
	tb.Helper()

	const txtDataChunkLen = 255

	txtDataChunkNum := txtDataLen / txtDataChunkLen
	if txtDataLen%txtDataChunkLen > 0 {
		txtDataChunkNum++
	}

	txts = make([]string, txtDataChunkNum)
	randData := make([]byte, txtDataLen)
	n, err := rand.Read(randData)
	require.NoError(tb, err)
	require.Equal(tb, txtDataLen, n)

	for i, c := range randData {
		randData[i] = c%26 + 'a'
	}

	// *dns.TXT requires splitting the actual data into 256-byte chunks.
	for i := range txtDataChunkNum {
		r := min(txtDataChunkLen*(i+1), txtDataLen)
		txts[i] = string(randData[txtDataChunkLen*i : r])
	}

	return txts
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
		MsgHdr: dns.MsgHdr{
			Id: dns.Id(),
		},
		Compress: true,
		Question: []dns.Question{{
			Name:   dns.Fqdn(domain),
			Qtype:  qtype,
			Qclass: qclass,
		}},
	}
}

func TestProxy_Resolve_dnssecCache(t *testing.T) {
	const (
		host = "example.com"

		// Larger than UDP buffer size to invoke truncation.
		txtDataLen = 1024
	)

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(host),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
		},
		Txt: newTxts(t, txtDataLen),
	}

	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(host),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
		},
		A: net.IP{1, 2, 3, 4},
	}

	ds := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(host),
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
		},
		Digest: "736f6d652064656c65676174696f6e207369676e6572",
	}

	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(host),
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    defaultTestTTL,
		},
		TypeCovered: dns.TypeA,
		Algorithm:   8,
		Labels:      2,
		SignerName:  dns.Fqdn(host),
		Signature:   "c29tZSBycnNpZyByZWxhdGVkIHN0dWZm",
	}

	u := &testUpstream{
		OnExchange: func(m *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(m)

			q := m.Question[0]
			switch q.Qtype {
			case dns.TypeA:
				resp.Answer = append(resp.Answer, a)
			case dns.TypeTXT:
				resp.Answer = append(resp.Answer, txt)
			case dns.TypeDS:
				resp.Answer = append(resp.Answer, ds)
			default:
				// Go on.  The RRSIG resource record is added afterward.  This
				// upstream.Upstream implementation doesn't handle explicit
				// requests for it.
			}

			if len(resp.Answer) > 0 {
				resp.Answer[0].Header().Ttl = defaultTestTTL
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

	p := mustNew(t, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		CacheEnabled:   true,
		DNSSECEnabled:  true,
		CacheSizeBytes: dnsproxytest.CacheSize,
	})

	testCases := []struct {
		wantAns dns.RR
		name    string
		wantLen int
		edns    bool
	}{{
		wantAns: a,
		name:    "a_noedns",
		wantLen: 1,
		edns:    false,
	}, {
		wantAns: a,
		name:    "a_ends",
		wantLen: 2,
		edns:    true,
	}, {
		wantAns: txt,
		name:    "txt_noedns",
		wantLen: 1,
		edns:    false,
	}, {
		wantAns: txt,
		name:    "txt_edns",
		// Truncated.
		wantLen: 0,
		edns:    true,
	}, {
		wantAns: ds,
		name:    "ds_noedns",
		wantLen: 1,
		edns:    false,
	}, {
		wantAns: ds,
		name:    "ds_edns",
		wantLen: 2,
		edns:    true,
	}}

	for _, tc := range testCases {
		ansHdr := tc.wantAns.Header()
		dctx := newDNSContext(ansHdr.Name, ansHdr.Rrtype, ansHdr.Class, tc.edns, txtDataLen/2)

		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(p.cache.items.Clear)

			err := p.Resolve(testutil.ContextWithTimeout(t, defaultTimeout), dctx)
			require.NoError(t, err)

			res := dctx.Res
			require.NotNil(t, res)

			require.Len(t, res.Answer, tc.wantLen, res.Answer)
			switch tc.wantLen {
			case 0:
				assert.True(t, res.Truncated)
			case 1:
				res.Answer[0].Header().Ttl = defaultTestTTL
				assert.Equal(t, tc.wantAns, res.Answer[0])
			case 2:
				res.Answer[0].Header().Ttl = defaultTestTTL
				assert.Equal(t, tc.wantAns, res.Answer[0])
				assert.Equal(t, rrsig, res.Answer[1])
			default:
				t.Fatalf("wanted length has unexpected value %d", tc.wantLen)
			}

			cached, expired, key := p.cache.get(dctx.Req)
			require.NotNil(t, cached)
			require.Len(t, cached.m.Answer, 2)

			assert.False(t, expired)
			assert.Equal(t, key, msgToKey(dctx.Req))

			// Just make it match.
			cached.m.Answer[0].Header().Ttl = defaultTestTTL
			assert.Equal(t, tc.wantAns.String(), cached.m.Answer[0].String())
			assert.Equal(t, rrsig.String(), cached.m.Answer[1].String())
		})

	}
}

func TestProxy_handleDNSRequest_exchangeWithReservedDomains(t *testing.T) {
	t.Parallel()

	dnsProxy := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfigWithBoot(
			t,
			dnsproxytest.Timeout,
			"[/adguard.com/]192.0.2.1",
			"[/google.ru/]192.0.2.2",
			"[/maps.google.ru/]#",
			"tls://1.1.1.1",
		),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	})

	servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

	// Create a DNS-over-TCP client connection.
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)

	// Create google-a test message.
	req := dnsproxytest.NewTestRequest()
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Make sure that dnsproxy is working.
	res, err := conn.ReadMsg()
	require.NoError(t, err)
	dnsproxytest.RequireResponse(t, req, res)

	// Create adguard.com test message.
	req = dnsproxytest.NewTestRequestWithHost("adguard.com")
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Test message should not be resolved.
	res, _ = conn.ReadMsg()
	require.Nil(t, res.Answer)

	// Create www.google.ru test message.
	req = dnsproxytest.NewTestRequestWithHost("www.google.ru")
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Test message should not be resolved.
	res, _ = conn.ReadMsg()
	require.Empty(t, res.Answer)

	// Create maps.google.ru test message.
	req = dnsproxytest.NewTestRequestWithHost("maps.google.ru")
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Test message should be resolved.
	res, _ = conn.ReadMsg()
	require.NotNil(t, res.Answer)
}

func TestProxy_handleDNSRequest_oneByOneUpstreamsExchange(t *testing.T) {
	t.Parallel()

	dnsProxy := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfigWithBoot(
			t,
			dnsproxytest.Timeout,
			"https://fake-dns.com/fake-dns-query",
			"tls://fake-dns.com",
			"1.1.1.1",
		),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		Fallbacks:      newTestUpstreamConfig(t, dnsproxytest.Timeout, "1.2.3.4:567"),
	})

	servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

	// create a DNS-over-TCP client connection
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)

	// make sure that the response is okay and resolved by valid upstream
	req := dnsproxytest.NewTestRequest()
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	start := time.Now()
	res, err := conn.ReadMsg()
	require.NoError(t, err)
	dnsproxytest.RequireResponse(t, req, res)

	elapsed := time.Since(start)
	assert.Greater(t, 3*dnsproxytest.Timeout, elapsed)
}

// newLocalUpstreamListener creates a new localhost listener on the specified
// port for tcp4 network and returns its listening address.
func newLocalUpstreamListener(tb testing.TB, port uint16, h dns.Handler) (real netip.AddrPort) {
	tb.Helper()

	startCh := make(chan struct{})
	upsSrv := &dns.Server{
		Addr:              netip.AddrPortFrom(netutil.IPv4Localhost(), port).String(),
		Net:               "tcp",
		Handler:           h,
		NotifyStartedFunc: func() { close(startCh) },
	}
	go func() {
		err := upsSrv.ListenAndServe()
		require.NoError(testutil.NewPanicT(tb), err)
	}()

	<-startCh
	testutil.CleanupAndRequireSuccess(tb, upsSrv.Shutdown)

	return testutil.RequireTypeAssert[*net.TCPAddr](tb, upsSrv.Listener.Addr()).AddrPort()
}

func TestProxy_handleDNSRequest_fallback(t *testing.T) {
	t.Parallel()

	responseCh := make(chan uint16)
	failCh := make(chan uint16)

	successHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		testutil.RequireSend(testutil.NewPanicT(t), responseCh, r.Id, dnsproxytest.Timeout)

		require.NoError(testutil.NewPanicT(t), w.WriteMsg((&dns.Msg{}).SetReply(r)))
	})
	failHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		testutil.RequireSend(testutil.NewPanicT(t), failCh, r.Id, dnsproxytest.Timeout)

		require.NoError(testutil.NewPanicT(t), w.WriteMsg(&dns.Msg{}))
	})

	successAddr := (&url.URL{
		Scheme: string(ProtoTCP),
		Host:   newLocalUpstreamListener(t, 0, successHandler).String(),
	}).String()
	alsoSuccessAddr := (&url.URL{
		Scheme: string(ProtoTCP),
		Host:   newLocalUpstreamListener(t, 0, successHandler).String(),
	}).String()
	failAddr := (&url.URL{
		Scheme: string(ProtoTCP),
		Host:   newLocalUpstreamListener(t, 0, failHandler).String(),
	}).String()

	dnsProxy := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfig(
			t,
			dnsproxytest.Timeout,
			failAddr,
			"[/specific.example/]"+alsoSuccessAddr,
			// almost.failing.example will fall here first.
			"[/failing.example/]"+failAddr,
		),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		Fallbacks: newTestUpstreamConfig(
			t,
			dnsproxytest.Timeout,
			failAddr,
			successAddr,
			"[/failing.example/]"+failAddr,
			"[/almost.failing.example/]"+alsoSuccessAddr,
		),
	})

	servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

	conn, err := dns.Dial("tcp", dnsProxy.Addr(ProtoTCP).String())
	require.NoError(t, err)

	testCases := []struct {
		name        string
		wantSignals []chan uint16
	}{{
		name: "general.example",
		wantSignals: []chan uint16{
			failCh,
			// Both non-specific fallbacks tried.
			failCh,
			responseCh,
		},
	}, {
		name: "specific.example",
		wantSignals: []chan uint16{
			responseCh,
		},
	}, {
		name: "failing.example",
		wantSignals: []chan uint16{
			failCh,
			failCh,
		},
	}, {
		name: "almost.failing.example",
		wantSignals: []chan uint16{
			failCh,
			responseCh,
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := dnsproxytest.NewTestRequestWithHost(tc.name)
			err = conn.WriteMsg(req)
			require.NoError(t, err)

			for _, ch := range tc.wantSignals {
				reqID, ok := testutil.RequireReceive(testutil.NewPanicT(t), ch, dnsproxytest.Timeout)
				require.True(t, ok)

				assert.Equal(t, req.Id, reqID)
			}

			_, err = conn.ReadMsg()
			require.NoError(t, err)
		})
	}
}

func TestProxy_handleDNSRequest_fallbackFromInvalidBootstrap(t *testing.T) {
	t.Parallel()

	invalidRslv, err := upstream.NewUpstreamResolver("8.8.8.8:555", &upstream.Options{
		Logger:  testLogger,
		Timeout: dnsproxytest.Timeout,
	})
	require.NoError(t, err)

	// Prepare the proxy server
	upsConf, err := ParseUpstreamsConfig([]string{"tls://dns.adguard.com"}, &upstream.Options{
		Logger:    testLogger,
		Bootstrap: invalidRslv,
		Timeout:   dnsproxytest.Timeout,
	})
	require.NoError(t, err)

	dnsProxy := mustNew(t, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: upsConf,
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		Fallbacks: newTestUpstreamConfig(
			t,
			dnsproxytest.Timeout,
			"1.0.0.1",
			"8.8.8.8",
		),
	})

	servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)

	// Make sure that the response is okay and resolved by the fallback
	req := dnsproxytest.NewTestRequest()
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	start := time.Now()
	res, err := conn.ReadMsg()
	require.NoError(t, err)
	dnsproxytest.RequireResponse(t, req, res)

	elapsed := time.Since(start)
	assert.Greater(t, 3*dnsproxytest.Timeout, elapsed)
}

func TestProxy_Resolve_exchangeCustomUpstreamConfig(t *testing.T) {
	p := mustNew(t, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	})

	servicetest.RequireRun(t, p, dnsproxytest.Timeout)

	ansIP := net.IP{4, 3, 2, 1}
	ans := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeA,
			Name:   "host.",
			Ttl:    60,
		},
		A: ansIP,
	}}

	onExchange := newECSReplyHandler(&ans, nil, nil)
	u := newTestECSUpstream(onExchange)

	d := &DNSContext{
		CustomUpstreamConfig: NewCustomUpstreamConfig(
			&UpstreamConfig{Upstreams: []upstream.Upstream{u}},
			false,
			0,
			false,
		),
		Req:  dnsproxytest.NewTestRequestWithHost("host"),
		Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
	}

	err := p.Resolve(testutil.ContextWithTimeout(t, defaultTimeout), d)
	require.NoError(t, err)

	assert.Equal(t, ansIP, firstIP(d.Res))
}

func TestProxy_Resolve_customUpstreamConfigCache(t *testing.T) {
	prx := mustNew(t, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		CacheEnabled:   true,
		DNSSECEnabled:  true,
	})

	servicetest.RequireRun(t, prx, dnsproxytest.Timeout)

	var count int

	ansIP := net.IP{4, 3, 2, 1}
	exchangeFunc := func(m *dns.Msg) (resp *dns.Msg, err error) {
		resp = &dns.Msg{}
		resp.SetReply(m)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Class:  dns.ClassINET,
				Rrtype: dns.TypeA,
				Ttl:    defaultTestTTL,
			},
			A: ansIP,
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
		Addr:                 netip.MustParseAddrPort("1.2.3.0:1234"),
	}

	ctx := testutil.ContextWithTimeout(t, defaultTimeout)
	err := prx.Resolve(ctx, d)
	require.NoError(t, err)

	require.Equal(t, 1, count)
	assert.Equal(t, ansIP, firstIP(d.Res))

	err = prx.Resolve(ctx, d)
	require.NoError(t, err)

	assert.Equal(t, 1, count)
	assert.Equal(t, ansIP, firstIP(d.Res))

	customUpstreamConfig.ClearCache()

	err = prx.Resolve(ctx, d)
	require.NoError(t, err)

	assert.Equal(t, 2, count)
	assert.Equal(t, ansIP, firstIP(d.Res))
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
		ip1230 = net.IP{1, 2, 3, 0}
		ip2230 = net.IP{2, 2, 3, 0}
		ip4321 = net.IP{4, 3, 2, 1}
		ip4322 = net.IP{4, 3, 2, 2}
		ip4323 = net.IP{4, 3, 2, 3}
	)

	var (
		ans      []dns.RR
		ecsIP    net.IP
		ecsReqIP net.IP
	)

	onExchange := newECSReplyHandler(&ans, &ecsIP, &ecsReqIP)
	u := newTestECSUpstream(onExchange)

	ans = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 60},
		A:   ip4321,
	}}
	ecsIP = ip1230

	prx := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{u},
		},
		TrustedProxies:         dnsproxytest.DefaultTrustedProxies,
		DNSSECEnabled:          true,
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
	})

	servicetest.RequireRun(t, prx, dnsproxytest.Timeout)

	t.Run("cache_subnet", func(t *testing.T) {
		d := &DNSContext{
			Req:  dnsproxytest.NewTestRequestWithHost("host"),
			Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
		}

		ctx := testutil.ContextWithTimeout(t, defaultTimeout)
		err := prx.Resolve(ctx, d)
		require.NoError(t, err)

		assert.Equal(t, net.IP{4, 3, 2, 1}, firstIP(d.Res))
		assert.Equal(t, ip1230, ecsReqIP)
	})

	t.Run("serve_subnet_cache", func(t *testing.T) {
		d := &DNSContext{
			Req:  dnsproxytest.NewTestRequestWithHost("host"),
			Addr: netip.MustParseAddrPort("1.2.3.1:1234"),
		}
		ans, ecsIP = nil, nil
		ecsReqIP = nil

		ctx := testutil.ContextWithTimeout(t, defaultTimeout)
		err := prx.Resolve(ctx, d)
		require.NoError(t, err)

		assert.Equal(t, ip4321, firstIP(d.Res))
		assert.Nil(t, ecsReqIP)
	})

	t.Run("another_subnet", func(t *testing.T) {
		d := &DNSContext{
			Req:  dnsproxytest.NewTestRequestWithHost("host"),
			Addr: netip.MustParseAddrPort("2.2.3.0:1234"),
		}
		ans = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 60},
			A:   ip4322,
		}}
		ecsIP = ip2230

		ctx := testutil.ContextWithTimeout(t, defaultTimeout)
		err := prx.Resolve(ctx, d)
		require.NoError(t, err)

		assert.Equal(t, ip4322, firstIP(d.Res))
		assert.Equal(t, ip2230, ecsReqIP)
	})

	t.Run("cache_general", func(t *testing.T) {
		d := &DNSContext{
			Req:  dnsproxytest.NewTestRequestWithHost("host"),
			Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
		}
		ans = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 60},
			A:   ip4323,
		}}
		ecsIP = nil
		ecsReqIP = nil

		ctx := testutil.ContextWithTimeout(t, defaultTimeout)
		err := prx.Resolve(ctx, d)
		require.NoError(t, err)

		assert.Equal(t, ip4323, firstIP(d.Res))
		assert.Nil(t, ecsReqIP)
	})

	t.Run("serve_general_cache", func(t *testing.T) {
		d := &DNSContext{
			Req:  dnsproxytest.NewTestRequestWithHost("host"),
			Addr: netip.MustParseAddrPort("127.0.0.2:1234"),
		}
		ans, ecsIP = nil, nil
		ecsReqIP = nil

		ctx := testutil.ContextWithTimeout(t, defaultTimeout)
		err := prx.Resolve(ctx, d)
		require.NoError(t, err)

		assert.Equal(t, ip4323, firstIP(d.Res))
		assert.Nil(t, ecsReqIP)
	})
}

func TestProxy_Resolve_ecsProxyCacheMinMaxTTL(t *testing.T) {
	clientIP := net.IP{1, 2, 3, 0}

	var (
		ans   []dns.RR
		ecsIP net.IP
	)

	onExchange := newECSReplyHandler(&ans, &ecsIP, nil)
	u := newTestECSUpstream(onExchange)

	ans = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeA,
			Name:   "host.",
			Ttl:    10,
		},
		A: net.IP{4, 3, 2, 1},
	}}
	ecsIP = clientIP

	udpAddr := net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)
	tcpAddr := net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)

	prx := mustNew(t, &Config{
		Logger:                 testLogger,
		UDPListenAddr:          []*net.UDPAddr{udpAddr},
		TCPListenAddr:          []*net.TCPAddr{tcpAddr},
		UpstreamConfig:         &UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		TrustedProxies:         dnsproxytest.DefaultTrustedProxies,
		DNSSECEnabled:          true,
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
		CacheMinTTL:            20,
		CacheMaxTTL:            40,
	})

	servicetest.RequireRun(t, prx, dnsproxytest.Timeout)

	// first request
	d := &DNSContext{
		Req:  dnsproxytest.NewTestRequestWithHost("host"),
		Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
	}
	ctx := testutil.ContextWithTimeout(t, defaultTimeout)
	err := prx.Resolve(ctx, d)
	require.NoError(t, err)

	// get from cache - check min TTL
	ci, expired, key := prx.cache.getWithSubnet(d.Req, &net.IPNet{
		IP:   clientIP,
		Mask: net.CIDRMask(24, netutil.IPv4BitLen),
	})
	assert.False(t, expired)

	assert.Equal(t, key, msgToKeyWithSubnet(d.Req, clientIP, 24))
	assert.True(t, ci.m.Answer[0].Header().Ttl == prx.cacheMinTTL)

	// 2nd request
	clientIP = net.IP{1, 2, 4, 0}
	d.Req = dnsproxytest.NewTestRequestWithHost("host")
	d.Addr = netip.MustParseAddrPort("1.2.4.0:1234")
	ans = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeA,
			Name:   "host.",
			Ttl:    60,
		},
		A: net.IP{4, 3, 2, 1},
	}}
	ecsIP = clientIP

	err = prx.Resolve(ctx, d)
	require.NoError(t, err)

	// get from cache - check max TTL
	ci, expired, key = prx.cache.getWithSubnet(d.Req, &net.IPNet{
		IP:   clientIP,
		Mask: net.CIDRMask(24, netutil.IPv4BitLen),
	})
	assert.False(t, expired)
	assert.Equal(t, key, msgToKeyWithSubnet(d.Req, clientIP, 24))
	assert.True(t, ci.m.Answer[0].Header().Ttl == prx.cacheMaxTTL)
}

func TestProxy_Resolve_withOptimisticResolver(t *testing.T) {
	const (
		host             = "some.domain.name."
		nonOptimisticTTL = 3600
	)

	buildCtx := func() (dctx *DNSContext) {
		req := &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id()},
			Question: []dns.Question{{
				Name:   host,
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
				Name:   host,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: net.IP{1, 2, 3, 4},
		}}

		return resp
	}

	p := &Proxy{
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
	out, in := make(chan unit), make(chan unit)
	p.shortFlighter.cr = &testCachingResolver{
		onReplyFromUpstream: func(dctx *DNSContext) (ok bool, err error) {
			dctx.Res = buildResp(dctx.Req, nonOptimisticTTL)

			return true, nil
		},
		onCacheResp: func(dctx *DNSContext) {
			// Report adding to cache is in process.
			out <- unit{}
			// Wait for tests to finish.
			<-in

			p.cacheResp(dctx)

			// Report adding to cache is finished.
			out <- unit{}
		},
	}

	// Two different contexts are made to emulate two different requests
	// with the same question section.
	firstCtx, secondCtx := buildCtx(), buildCtx()

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

	ctx := testutil.ContextWithTimeout(t, defaultTimeout)

	err := p.Resolve(ctx, firstCtx)
	require.NoError(t, err)
	require.Len(t, firstCtx.Res.Answer, 1)

	assert.Equal(t, uint32(testOptimisticTTL.Seconds()), firstCtx.Res.Answer[0].Header().Ttl)

	// Wait for optimisticResolver to reach the tested function.
	<-out

	err = p.Resolve(ctx, secondCtx)
	require.NoError(t, err)
	require.Len(t, secondCtx.Res.Answer, 1)

	assert.Equal(t, uint32(testOptimisticTTL.Seconds()), secondCtx.Res.Answer[0].Header().Ttl)

	// Continue and wait for it to finish.
	in <- unit{}
	<-out

	// Should be served from cache.
	data = p.cache.items.Get(msgToKey(firstCtx.Req))
	unpacked, expired := p.cache.unpackItem(data, firstCtx.Req)
	require.False(t, expired)
	require.NotNil(t, unpacked)
	require.Len(t, unpacked.m.Answer, 1)

	assert.EqualValues(t, nonOptimisticTTL, unpacked.m.Answer[0].Header().Ttl)
}

func TestProxy_validateRequest(t *testing.T) {
	t.Parallel()

	const (
		fqdn            = "test.example."
		privateARPAFQDN = "1.100.51.198.in-addr.arpa."
		publicARPAFQDN  = "8.8.8.8.in-addr.arpa."
	)

	testAddr := netip.MustParseAddrPort("192.0.2.1:53")
	privateAddr := netip.MustParseAddrPort("198.51.100.1:53")

	privateNets := netutil.SliceSubnetSet{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/8"),
	}

	ups := &testUpstream{
		OnExchange: func(m *dns.Msg) (resp *dns.Msg, err error) {
			resp = &dns.Msg{}
			resp.SetReply(m)

			return resp, nil
		},
		OnAddress: func() (addr string) { return "stub" },
		OnClose:   func() (err error) { return nil },
	}

	p, err := New(&Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{ups}},
		RefuseAny:      true,
		PrivateSubnets: privateNets,
	})
	require.NoError(t, err)

	testCases := []struct {
		req             *dns.Msg
		addr            netip.AddrPort
		name            string
		wantRcode       int
		isPrivateClient bool
		wantNil         bool
	}{{
		name:            "valid_request",
		req:             (&dns.Msg{}).SetQuestion(fqdn, dns.TypeA),
		addr:            testAddr,
		wantNil:         true,
		isPrivateClient: false,
	}, {
		name: "no_questions",
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Id: dns.Id()},
			Question: []dns.Question{},
		},
		addr:            testAddr,
		wantRcode:       dns.RcodeFormatError,
		wantNil:         false,
		isPrivateClient: false,
	}, {
		name:            "refuse_any",
		req:             (&dns.Msg{}).SetQuestion(fqdn, dns.TypeANY),
		addr:            testAddr,
		wantRcode:       dns.RcodeNotImplemented,
		wantNil:         false,
		isPrivateClient: false,
	}, {
		name:            "private_arpa_from_public_client",
		req:             (&dns.Msg{}).SetQuestion(privateARPAFQDN, dns.TypePTR),
		addr:            testAddr,
		wantRcode:       dns.RcodeNameError,
		wantNil:         false,
		isPrivateClient: false,
	}, {
		name:            "private_arpa_from_private_client",
		req:             (&dns.Msg{}).SetQuestion(privateARPAFQDN, dns.TypePTR),
		addr:            privateAddr,
		wantNil:         true,
		isPrivateClient: true,
	}, {
		name:            "private_arpa_soa_from_public_client",
		req:             (&dns.Msg{}).SetQuestion(privateARPAFQDN, dns.TypeSOA),
		addr:            testAddr,
		wantRcode:       dns.RcodeNameError,
		wantNil:         false,
		isPrivateClient: false,
	}, {
		name:            "private_arpa_ns_from_public_client",
		req:             (&dns.Msg{}).SetQuestion(privateARPAFQDN, dns.TypeNS),
		addr:            testAddr,
		wantRcode:       dns.RcodeNameError,
		wantNil:         false,
		isPrivateClient: false,
	}, {
		name:            "public_arpa",
		req:             (&dns.Msg{}).SetQuestion(publicARPAFQDN, dns.TypePTR),
		addr:            testAddr,
		wantNil:         true,
		isPrivateClient: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dctx := &DNSContext{
				Req:             tc.req,
				Addr:            tc.addr,
				IsPrivateClient: tc.isPrivateClient,
			}

			resp := p.validateRequest(dctx)

			if tc.wantNil {
				assert.Nil(t, resp)

				return
			}

			require.NotNil(t, resp)
			assert.Equal(t, tc.wantRcode, resp.Rcode)
		})
	}
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
	OnExchange func(req *dns.Msg) (resp *dns.Msg, err error)
	OnClose    func() (err error)
}

// newTestECSUpstream creates a new test upstream with the given OnExchange
// handler.
func newTestECSUpstream(
	onExchange func(req *dns.Msg) (resp *dns.Msg, err error),
) (u *testUpstream) {
	return &testUpstream{
		OnAddress:  func() string { return "" },
		OnClose:    func() error { return nil },
		OnExchange: onExchange,
	}
}

// newECSReplyHandler creates an OnExchange handler that builds a DNS reply
// with optional answer records and ECS support.
//
// The handler dereferences ans, ecsIP, and ecsReqIP at call time, so tests
// can reassign those variables between sub-tests and the handler will see
// the current values.
func newECSReplyHandler(ans *[]dns.RR, ecsIP, ecsReqIP *net.IP) func(*dns.Msg) (*dns.Msg, error) {
	return func(m *dns.Msg) (resp *dns.Msg, err error) {
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
func (u *testUpstream) Exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	return u.OnExchange(m)
}

// Address implements the upstream.Upstream interface for *testUpstream.
func (u *testUpstream) Address() (addr string) {
	return u.OnAddress()
}

// Close implements the upstream.Upstream interface for *testUpstream.
func (u *testUpstream) Close() (err error) {
	return u.OnClose()
}
