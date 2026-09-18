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
