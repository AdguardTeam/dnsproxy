package proxy_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

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
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
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

func TestPendingRequestsDifferentUpstreamResponses(t *testing.T) {
	t.Parallel()

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})
	newUpstream := func(ip net.IP, beforeReply func()) *dnsproxytest.Upstream {
		return &dnsproxytest.Upstream{
			OnAddress: func() string { return "stub" },
			OnClose:   func() error { return nil },
			OnExchange: func(req *dns.Msg) (*dns.Msg, error) {
				beforeReply()
				resp := (&dns.Msg{}).SetReply(req)
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name:   req.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    testTTL,
					},
					A: ip,
				}}

				return resp, nil
			},
		}
	}

	ipA := net.IP{192, 0, 2, 1}
	ipB := net.IP{192, 0, 2, 2}
	upstreamA := newUpstream(ipA, func() {
		close(firstStarted)
		<-releaseFirst
	})
	upstreamB := newUpstream(ipB, func() { close(secondStarted) })
	p := newPendingTestProxy(t, upstreamA)
	first := newPendingTestContext(upstreamA)
	second := newPendingTestContext(upstreamB)
	ctx := testutil.ContextWithTimeout(t, defaultTimeout)
	firstErr := make(chan error, 1)
	secondErr := make(chan error, 1)
	go func() { firstErr <- p.Resolve(ctx, first) }()
	select {
	case <-firstStarted:
	case err := <-firstErr:
		t.Fatalf("first upstream was not queried: %v", err)
	}
	go func() { secondErr <- p.Resolve(ctx, second) }()

	select {
	case <-secondStarted:
	case <-time.After(2 * time.Second):
		t.Error("second upstream was not queried while the first request was pending")
	}
	close(releaseFirst)

	require.NoError(t, <-firstErr)
	require.NoError(t, <-secondErr)
	require.NotNil(t, first.Res)
	require.NotNil(t, second.Res)
	require.Len(t, first.Res.Answer, 1)
	require.Len(t, second.Res.Answer, 1)
	assert.Equal(t, ipA, first.Res.Answer[0].(*dns.A).A)
	assert.Equal(t, ipB, second.Res.Answer[0].(*dns.A).A)
}

func TestPendingRequestsNestedResolveDoesNotDeadlock(t *testing.T) {
	t.Parallel()

	innerUpstream := &dnsproxytest.Upstream{
		OnAddress: func() string { return "inner" },
		OnClose:   func() error { return nil },
		OnExchange: func(req *dns.Msg) (*dns.Msg, error) {
			return (&dns.Msg{}).SetReply(req), nil
		},
	}
	inner := newPendingTestContext(innerUpstream)
	ctx := testutil.ContextWithTimeout(t, defaultTimeout)
	var p *proxy.Proxy
	outerUpstream := &dnsproxytest.Upstream{
		OnAddress: func() string { return "outer" },
		OnClose:   func() error { return nil },
		OnExchange: func(req *dns.Msg) (*dns.Msg, error) {
			err := p.Resolve(ctx, inner)
			if inner.Res != nil {
				inner.Res.Id = req.Id
			}

			return inner.Res, err
		},
	}
	p = newPendingTestProxy(t, outerUpstream)

	outer := newPendingTestContext(outerUpstream)
	done := make(chan error, 1)
	go func() { done <- p.Resolve(ctx, outer) }()

	select {
	case err := <-done:
		require.NoError(t, err)
		require.NotNil(t, outer.Res)
	case <-time.After(2 * time.Second):
		t.Fatal("nested resolve blocked on the outer pending request")
	}
}

func newPendingTestProxy(t *testing.T, u upstream.Upstream) *proxy.Proxy {
	t.Helper()

	p, err := proxy.New(&proxy.Config{
		Logger:          testLogger,
		UpstreamConfig:  &proxy.UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		PendingRequests: &proxy.PendingRequestsConfig{Enabled: true},
		CacheEnabled:    true,
		CacheSizeBytes:  proxytest.CacheSize,
	})
	require.NoError(t, err)

	return p
}

func newPendingTestContext(u upstream.Upstream) *proxy.DNSContext {
	return &proxy.DNSContext{
		CustomUpstreamConfig: newCustomUpstreamConfig(u, true),
		Req:                  (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeA),
	}
}
