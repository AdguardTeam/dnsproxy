package proxy_test

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	proxytest "github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// defaultTimeout is a default timeout for tests.
	defaultTimeout = 10 * time.Second

	// testTTL is a common time-to-live value in seconds for tests.
	testTTL = 60
)

var (
	// testLogger is a common logger for tests.
	testLogger = slogutil.NewDiscardLogger()

	// testIPv4 is a common IPv4 for tests
	testIPv4 = net.IP{192, 0, 2, 0}
)

// newTestUpstreamConfig creates a new upstream config with the default mock
// upstream, which expects the request will contain a single question with the
// [proxytest.Host] name.
//
// TODO(f.setrakov): DRY with internal version.
func newTestUpstreamConfig(tb testing.TB) (uc *proxy.UpstreamConfig) {
	onExchange := func(req *dns.Msg) (resp *dns.Msg, err error) {
		pt := testutil.NewPanicT(tb)

		require.Len(pt, req.Question, 1)
		assert.Equal(pt, dns.Fqdn(proxytest.Host), req.Question[0].Name)

		return proxytest.NewTestResponse(req), nil
	}

	u := &dnsproxytest.Upstream{
		OnAddress:  func() (addr string) { return "" },
		OnExchange: onExchange,
		OnClose:    func() (err error) { return nil },
	}

	return &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{u},
	}
}

// mustStartDefaultProxy starts a new proxy with default settings and returns
// it.  It fails the test on error.
func mustStartDefaultProxy(tb testing.TB) (p *proxy.Proxy) {
	tb.Helper()

	p, err := proxy.New(&proxy.Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfig(tb),
		TrustedProxies: proxytest.DefaultTrustedProxies,
	})
	require.NoError(tb, err)

	servicetest.RequireRun(tb, p, proxytest.Timeout)

	return p
}

// sendTestMessages sends [proxytest.MessageCount] DNS requests to the specified
// connection and checks the responses.
func sendTestMessages(tb testing.TB, conn *dns.Conn) {
	tb.Helper()

	for i := range proxytest.MessageCount {
		req := proxytest.NewTestRequest()
		err := conn.WriteMsg(req)
		require.NoErrorf(tb, err, "req number %d", i)

		res, err := conn.ReadMsg()
		require.NoErrorf(tb, err, "resp number %d", i)

		proxytest.RequireResponse(tb, req, res)
	}
}

func TestProxy_Resolve_badResponse(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	onExchange := func(m *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(m)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Class:  dns.ClassINET,
				Rrtype: dns.TypeA,
			},
			A: net.IP{1, 2, 3, 4},
		})
		// Make the response invalid.
		resp.Question = []dns.Question{}

		return resp, nil
	}

	u := &dnsproxytest.Upstream{
		OnExchange: onExchange,
		OnAddress:  func() (addr string) { return "stub" },
		OnClose:    func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	d := &proxy.DNSContext{
		CustomUpstreamConfig: proxy.NewCustomUpstreamConfig(
			&proxy.UpstreamConfig{Upstreams: []upstream.Upstream{u}},
			false,
			0,
			false,
		),
		Req:  proxytest.NewTestRequestWithHost("host"),
		Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
	}

	var err error
	require.NotPanics(t, func() {
		err = dnsProxy.Resolve(testutil.ContextWithTimeout(t, defaultTimeout), d)
	})
	require.NoError(t, err)

	assert.Equal(t, d.Req.Question[0], d.Res.Question[0])
}

// newCustomUpstreamConfig is a helper function that returns an initialized
// [*proxy.CustomUpstreamConfig].
func newCustomUpstreamConfig(ups upstream.Upstream, enabled bool) (c *proxy.CustomUpstreamConfig) {
	return proxy.NewCustomUpstreamConfig(
		&proxy.UpstreamConfig{Upstreams: []upstream.Upstream{ups}},
		enabled,
		0,
		false,
	)
}

// isCachedWithCustomConfig is a helper function that returns the caching
// results of a constructed request using the provided custom upstream
// configuration and FQDN.
func isCachedWithCustomConfig(
	tb testing.TB,
	p *proxy.Proxy,
	conf *proxy.CustomUpstreamConfig,
	fqdn string,
) (isCached bool) {
	tb.Helper()

	d := &proxy.DNSContext{
		CustomUpstreamConfig: conf,
		Req:                  (&dns.Msg{}).SetQuestion(fqdn, dns.TypeA),
	}

	err := p.Resolve(testutil.ContextWithTimeout(tb, defaultTimeout), d)
	require.NoError(tb, err)

	qs := d.QueryStatistics()
	require.NotNil(tb, qs)

	s := qs.Main()
	require.Len(tb, s, 1)

	return s[0].IsCached
}

func TestProxy_HandleDNSRequest_race(t *testing.T) {
	upsConf := newTestUpstreamConfig(t)

	dnsProxy, err := proxy.New(&proxy.Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		UpstreamConfig: upsConf,
		TrustedProxies: proxytest.DefaultTrustedProxies,
	})
	require.NoError(t, err)

	servicetest.RequireRun(t, dnsProxy, proxytest.Timeout)

	addr := dnsProxy.Addr(proxy.ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)

	wg := &sync.WaitGroup{}

	pt := testutil.NewPanicT(t)
	for range proxytest.MessageCount {
		wg.Go(func() {
			req := proxytest.NewTestRequest()
			writeErr := conn.WriteMsg(req)
			require.NoError(pt, writeErr)

			res, readErr := conn.ReadMsg()
			require.NoError(pt, readErr)

			// We do not check if msg IDs match because the order of responses
			// may be different.

			require.NotNil(pt, res)
			require.Len(pt, res.Answer, 1)

			a := testutil.RequireTypeAssert[*dns.A](pt, res.Answer[0])
			require.IsType(pt, &dns.A{}, res.Answer[0])

			require.Equal(pt, proxytest.IPv4.To16(), a.A.To16())
		})
	}

	wg.Wait()
}

func TestProxy_HandleDNSRequest_responseInRequest(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	addr := dnsProxy.Addr(proxy.ProtoTCP)
	client := &dns.Client{
		Net:     string(proxy.ProtoTCP),
		Timeout: proxytest.Timeout,
	}

	req := proxytest.NewTestRequest()
	req.Response = true

	r, _, err := client.Exchange(req, addr.String())

	netErr := &net.OpError{}
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout())
	assert.Nil(t, r)
}

func TestProxy_Resolve_cache(t *testing.T) {
	const host = "example.test."

	ups := &dnsproxytest.Upstream{
		OnAddress: func() (addr string) { return "stub" },
		OnClose:   func() (err error) { return nil },
	}
	ups.OnExchange = func(req *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    testTTL,
			},
			A: testIPv4,
		})

		return resp, nil
	}

	upsConf := &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{ups},
	}

	testCases := []struct {
		customUpstreamConf *proxy.CustomUpstreamConfig
		wantCachedWithConf assert.BoolAssertionFunc
		wantCachedGlobal   assert.BoolAssertionFunc
		name               string
		prxCacheEnabled    bool
	}{{
		customUpstreamConf: nil,
		wantCachedWithConf: assert.True,
		wantCachedGlobal:   assert.True,
		name:               "global_cache",
		prxCacheEnabled:    true,
	}, {
		customUpstreamConf: newCustomUpstreamConfig(ups, true),
		wantCachedWithConf: assert.True,
		wantCachedGlobal:   assert.False,
		name:               "custom_cache",
		prxCacheEnabled:    false,
	}, {
		customUpstreamConf: newCustomUpstreamConfig(ups, false),
		wantCachedWithConf: assert.False,
		wantCachedGlobal:   assert.False,
		name:               "custom_cache_only_upstreams",
		prxCacheEnabled:    false,
	}, {
		customUpstreamConf: newCustomUpstreamConfig(ups, true),
		wantCachedWithConf: assert.True,
		wantCachedGlobal:   assert.False,
		name:               "two_caches_enabled",
		prxCacheEnabled:    true,
	}, {
		customUpstreamConf: nil,
		wantCachedWithConf: assert.False,
		wantCachedGlobal:   assert.False,
		name:               "proxy_cache_disabled",
		prxCacheEnabled:    false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := proxy.New(&proxy.Config{
				Logger:         testLogger,
				UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
				UpstreamConfig: upsConf,
				CacheEnabled:   tc.prxCacheEnabled,
			})
			require.NoError(t, err)
			require.NotNil(t, p)

			servicetest.RequireRun(t, p, proxytest.Timeout)

			res := isCachedWithCustomConfig(t, p, tc.customUpstreamConf, host)
			assert.False(t, res)

			res = isCachedWithCustomConfig(t, p, tc.customUpstreamConf, host)
			tc.wantCachedWithConf(t, res)

			res = isCachedWithCustomConfig(t, p, nil, host)
			tc.wantCachedGlobal(t, res)
		})
	}
}

func TestProxy_Start_closeOnFail(t *testing.T) {
	t.Parallel()

	addr := net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)
	l, err := net.ListenTCP(bootstrap.NetworkTCP, addr)
	require.NoError(t, err)

	tcpAddr := testutil.RequireTypeAssert[*net.TCPAddr](t, l.Addr())

	ups := &dnsproxytest.Upstream{
		OnExchange: func(m *dns.Msg) (_ *dns.Msg, _ error) { panic(testutil.UnexpectedCall(m)) },
		OnAddress:  func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:    func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	p, err := proxy.New(&proxy.Config{
		Logger: testLogger,
		// Add a free address.
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		// Add a bound address.
		TCPListenAddr:  []*net.TCPAddr{tcpAddr},
		UpstreamConfig: &proxy.UpstreamConfig{Upstreams: []upstream.Upstream{ups}},
	})
	require.NoError(t, err)

	require.True(t, t.Run("start_fail", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, proxytest.Timeout)
		err = p.Start(ctx)

		var netErr net.Error
		require.ErrorAs(t, err, &netErr)
	}))

	// Don't panic anymore.
	ups.OnClose = func() (err error) { return nil }

	require.True(t, t.Run("restart_success", func(t *testing.T) {
		require.NoError(t, l.Close())

		servicetest.RequireRun(t, p, proxytest.Timeout)
	}))
}

func TestProxy_ServeDNS_formatError(t *testing.T) {
	t.Parallel()

	ups := &dnsproxytest.Upstream{
		OnAddress: func() (addr string) { return testIPv4.String() },
		OnClose:   func() (err error) { return nil },
	}
	ups.OnExchange = func(req *dns.Msg) (resp *dns.Msg, err error) {
		panic(testutil.UnexpectedCall(req))
	}

	upsConf := &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{ups},
	}

	// NOTE: This case must not run on darwin systems by default, because the
	// default maximum value of UDP datagrams on such systems is less than the
	// actual maximum UDP message size.
	//
	// TODO(f.setrakov): Find the other way to fix this case on macOS.
	exception := "query_with_multiple_edns_options"

	testDataPattern := filepath.Join("testdata", t.Name(), "*")
	testNames, err := filepath.Glob(testDataPattern)
	require.NoError(t, err)
	require.NotEmpty(t, testNames)

	p, err := proxy.New(&proxy.Config{
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		UpstreamConfig: upsConf,
		Logger:         testLogger,
	})
	require.NoError(t, err)
	require.NotNil(t, p)
	servicetest.RequireRun(t, p, proxytest.Timeout)

	addr := p.Addr(proxy.ProtoUDP)

	for _, testName := range testNames {
		t.Run(testName, func(t *testing.T) {
			skipDarwin(t, exception)

			t.Parallel()

			testJiggleVulnerability(t, filepath.Join(testName), addr)
		})
	}
}

// testJiggleVulnerability makes sure that proxy correctly responds to malformed
// DNS packets without crashing.
func testJiggleVulnerability(tb testing.TB, dataPath string, addr net.Addr) {
	data, err := os.ReadFile(dataPath)
	require.NoError(tb, err)

	conn := requireDial(tb, addr, proxytest.Timeout)
	requireWritePacket(tb, conn, data)
	resp := requireReadPacket(tb, conn)

	msg := &dns.Msg{}
	err = msg.Unpack(resp)
	require.NoError(tb, err)

	assert.Equal(tb, msg.Rcode, dns.RcodeFormatError)
}

// requireDial dials the given address and returns the connection, setting a
// deadline to reflect timeout.  The connection is closed in the test cleanup.
func requireDial(tb testing.TB, addr net.Addr, timeout time.Duration) (conn net.Conn) {
	tb.Helper()

	conn, err := net.DialTimeout(addr.Network(), addr.String(), timeout)
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, conn.Close)

	deadline := time.Now().Add(timeout)
	require.NoError(tb, conn.SetDeadline(deadline))

	return conn
}

// requireWritePacket writes data into the given conn.  conn must not be nil.
func requireWritePacket(tb testing.TB, conn net.Conn, data []byte) {
	tb.Helper()

	n, err := conn.Write(data)
	require.NoError(tb, err)
	require.Equal(tb, len(data), n)
}

// requireReadPacket reads a DNS packet from the given conn and returns the
// packet data.  conn must not be nil.
func requireReadPacket(tb testing.TB, conn net.Conn) (data []byte) {
	tb.Helper()

	buf := make([]byte, dns.MaxMsgSize)
	n, err := conn.Read(buf)
	require.NoError(tb, err)
	require.Positive(tb, n)

	return buf[:n]
}
