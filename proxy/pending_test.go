package proxy_test

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/AdguardTeam/dnsproxy/dnsproxytest"
	proxytest "github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertEqualResponses is a helper function that checks if two DNS messages are
// equal, excluding their ID.
//
// TODO(e.burkov):  Cosider using go-cmp.
func assertEqualResponses(tb testing.TB, expected, actual *dns.Msg) {
	tb.Helper()

	if expected == nil {
		require.Nil(tb, actual)

		return
	}

	require.NotNil(tb, actual)

	expectedHdr, actualHdr := expected.MsgHdr, actual.MsgHdr
	expectedHdr.Id, actualHdr.Id = 0, 0
	assert.Equal(tb, expectedHdr, actualHdr)

	assert.Equal(tb, expected.Question, actual.Question)
	assert.Equal(tb, expected.Answer, actual.Answer)
	assert.Equal(tb, expected.Ns, actual.Ns)
	assert.Equal(tb, expected.Extra, actual.Extra)
}

func TestPendingRequests(t *testing.T) {
	t.Parallel()

	const reqsNum = 100

	// workloadWG is used to hold the upstream response until as many requests
	// as possible reach the [proxy.Resolve] method.  This is a best-effort
	// approach, so it's not strictly guaranteed to hold all requests, but it
	// works for the test.
	workloadWG := &sync.WaitGroup{}
	workloadWG.Add(reqsNum)

	reqHandler := &dnsproxytest.Handler{
		OnHandle: func(ctx context.Context, p *proxy.Proxy, d *proxy.DNSContext) (err error) {
			workloadWG.Done()

			return p.Resolve(ctx, d)
		},
	}

	once := &sync.Once{}
	u := &dnsproxytest.Upstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			once.Do(func() {
				resp = (&dns.Msg{}).SetReply(req)
			})

			// Only allow a single request to be processed.
			require.NotNil(testutil.NewPanicT(t), resp)

			workloadWG.Wait()

			return resp, nil
		},
		OnAddress: func() (addr string) { return "" },
		OnClose:   func() (err error) { return nil },
	}

	p, err := proxy.New(&proxy.Config{
		Logger:         testLogger,
		UpstreamConfig: &proxy.UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		TrustedProxies: proxytest.DefaultTrustedProxies,
		PendingRequests: &proxy.PendingRequestsConfig{
			Enabled: true,
		},
		RequestHandler:         reqHandler,
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		CacheSizeBytes:         proxytest.CacheSize,
		CacheEnabled:           true,
		DNSSECEnabled:          true,
		EnableEDNSClientSubnet: true,
	})
	require.NoError(t, err)

	servicetest.RequireRun(t, p, proxytest.Timeout)

	addr := p.Addr(proxy.ProtoTCP).String()
	client := &dns.Client{
		Net:     string(proxy.ProtoTCP),
		Timeout: proxytest.Timeout,
	}

	resolveWG := &sync.WaitGroup{}
	responses := make([]*dns.Msg, reqsNum)
	errs := make([]error, reqsNum)

	for i := range reqsNum {
		req := (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeA)
		resolveWG.Go(func() {
			reqCtx := testutil.ContextWithTimeout(t, proxytest.Timeout)
			responses[i], _, errs[i] = client.ExchangeContext(reqCtx, req, addr)
		})
	}

	resolveWG.Wait()

	require.NoError(t, errs[0])

	for i, resp := range responses[:len(responses)-1] {
		assert.Equal(t, errs[i], errs[i+1])
		assertEqualResponses(t, resp, responses[i+1])
	}
}

func TestProxy_Resolve_pendingRequestsCustomUpstreamConfig(t *testing.T) {
	t.Parallel()

	firstStarted := &sync.Mutex{}
	firstRespond := &sync.Mutex{}
	secondStarted := &sync.Mutex{}

	firstStarted.Lock()
	firstRespond.Lock()
	secondStarted.Lock()

	panicUps := &dnsproxytest.Upstream{
		OnAddress: func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnExchange: func(ctx context.Context, req *dns.Msg) (_ *dns.Msg, _ error) {
			panic(testutil.UnexpectedCall(ctx, req))
		},
		OnClose: func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	firstUps := &dnsproxytest.Upstream{
		OnAddress: func() (addr string) { return "first" },
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			firstStarted.Unlock()
			firstRespond.Lock()

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnClose: func() (err error) { return nil },
	}
	secondUps := &dnsproxytest.Upstream{
		OnAddress: func() (addr string) { return "second" },
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			secondStarted.Unlock()

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnClose: func() (err error) { return nil },
	}

	p, err := proxy.New(&proxy.Config{
		Logger:          testLogger,
		UpstreamConfig:  &proxy.UpstreamConfig{Upstreams: []upstream.Upstream{panicUps}},
		PendingRequests: &proxy.PendingRequestsConfig{Enabled: true},
		CacheEnabled:    true,
		CacheSizeBytes:  proxytest.CacheSize,
	})
	require.NoError(t, err)

	first := newPendingTestDNSContext(t, firstUps)
	second := newPendingTestDNSContext(t, secondUps)

	firstErrCh := resolveConcurrently(t, p, first)

	firstStarted.Lock()

	secondErrCh := resolveConcurrently(t, p, second)

	secondStarted.Lock()

	firstRespond.Unlock()

	err, ok := testutil.RequireReceive(t, firstErrCh, defaultTimeout)
	require.True(t, ok)
	require.NoError(t, err)

	err, ok = testutil.RequireReceive(t, secondErrCh, defaultTimeout)
	require.True(t, ok)
	require.NoError(t, err)

	require.NotNil(t, first.Res)
	assert.Equal(t, first.Req.Id, first.Res.Id)

	require.NotNil(t, second.Res)
	assert.Equal(t, second.Req.Id, second.Res.Id)
}

// newPendingTestDNSContext returns a new [proxy.DNSContext] with an A request
// and a custom upstream configuration containing a single upstream u.
func newPendingTestDNSContext(tb testing.TB, u upstream.Upstream) (dctx *proxy.DNSContext) {
	tb.Helper()

	return &proxy.DNSContext{
		CustomUpstreamConfig: newCustomUpstreamConfig(u, true),
		Req:                  (&dns.Msg{}).SetQuestion(proxytest.FQDN, dns.TypeA),
	}
}

// resolveConcurrently runs [proxy.Proxy.Resolve] with d in a separate goroutine
// and returns a channel receiving the resulting error.
func resolveConcurrently(tb testing.TB, p *proxy.Proxy, d *proxy.DNSContext) (errCh chan error) {
	tb.Helper()

	errCh = make(chan error)

	ctx := testutil.ContextWithTimeout(tb, proxytest.Timeout)
	go func() {
		err := p.Resolve(ctx, d)
		testutil.RequireSend(testutil.NewPanicT(tb), errCh, err, proxytest.Timeout)
	}()

	return errCh
}
