package proxy

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPendingRequests is a mock implementation of [PendingRequests] for tests.
//
// TODO(e.burkov):  Think of a better way to test [PendingRequests].
type testPendingRequests struct {
	onQueue func(ctx context.Context, dctx *DNSContext) (exists bool, err error)
	onDone  func(ctx context.Context, dctx *DNSContext, err error)
}

// type check
var _ PendingRequests = (*testPendingRequests)(nil)

// queue implements the [proxy.PendingRequests] interface for
// *testPendingRequests.
func (p *testPendingRequests) queue(
	ctx context.Context,
	dctx *DNSContext,
) (exists bool, err error) {
	return p.onQueue(ctx, dctx)
}

// done implements the [proxy.PendingRequests] interface for
// *testPendingRequests.
func (p *testPendingRequests) done(ctx context.Context, dctx *DNSContext, err error) {
	p.onDone(ctx, dctx, err)
}

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

	loadWG := &sync.WaitGroup{}
	loadWG.Add(reqsNum)

	once := &sync.Once{}
	u := &dnsproxytest.FakeUpstream{
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			loadWG.Wait()
			once.Do(func() {
				resp = (&dns.Msg{}).SetReply(req)
			})

			// Only allow a single request to be processed.
			require.NotNil(testutil.PanicT{}, resp)

			return resp, nil
		},
		OnAddress: func() (addr string) { return "" },
		OnClose:   func() (err error) { return nil },
	}

	pending := NewDefaultPendingRequests()
	testPending := &testPendingRequests{
		onQueue: func(ctx context.Context, dctx *DNSContext) (exists bool, err error) {
			loadWG.Done()

			return pending.queue(ctx, dctx)
		},
		onDone: pending.done,
	}

	p := mustNew(t, &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         &UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		Ratelimit:              0,
		CacheEnabled:           true,
		CacheSizeBytes:         defaultCacheSize,
		EnableEDNSClientSubnet: true,
		PendingRequests:        testPending,
	})

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err := p.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		ctx = testutil.ContextWithTimeout(t, testTimeout)

		return p.Shutdown(ctx)
	})

	addr := p.Addr(ProtoTCP).String()
	client := &dns.Client{
		Net:     string(ProtoTCP),
		Timeout: testTimeout,
	}

	resolveWG := &sync.WaitGroup{}
	responses := make([]*dns.Msg, reqsNum)
	errs := make([]error, reqsNum)

	for i := range reqsNum {
		resolveWG.Add(1)

		go func() {
			defer resolveWG.Done()

			req := (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeA)

			reqCtx := testutil.ContextWithTimeout(t, testTimeout)
			responses[i], _, errs[i] = client.ExchangeContext(reqCtx, req, addr)
		}()
	}

	resolveWG.Wait()

	require.NoError(t, errs[0])

	for i, resp := range responses[:len(responses)-1] {
		assert.Equal(t, errs[i], errs[i+1])
		assertEqualResponses(t, resp, responses[i+1])
	}
}
