package proxy_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
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

const (
	// saturatedBlockedName is a name whose upstream exchange blocks until the
	// test releases it.
	saturatedBlockedName = "blocked.test."

	// saturatedLocalName is answered by the request handler without an upstream.
	saturatedLocalName = "local.test."

	// saturatedCachedName is resolved once and then must be served from cache.
	saturatedCachedName = "cached.test."

	// saturatedLocalIP is the address returned for [saturatedLocalName].
	saturatedLocalIP = "192.0.2.55"
)

func TestProxy_ServeDNS_localAnswerWhileUpstreamSaturated(t *testing.T) {
	t.Parallel()

	t.Run("rewrite", func(t *testing.T) {
		t.Parallel()

		block := make(chan struct{})
		var inUpstream atomic.Int32
		handler := proxy.HandlerFunc(func(
			ctx context.Context,
			prx *proxy.Proxy,
			dctx *proxy.DNSContext,
		) (err error) {
			if dctx.Req.Question[0].Name == saturatedLocalName {
				dctx.Res = localRewrite(dctx.Req)

				return nil
			}

			return prx.Resolve(ctx, dctx)
		})

		addr := startBlockingProxy(t, block, &inUpstream, false, handler)
		saturateUpstream(t, addr, &inUpstream)

		started := time.Now()
		resp, err := exchangeA(addr, saturatedLocalName, 300*time.Millisecond)
		elapsed := time.Since(started)
		require.NoError(t, err)
		requireAnswerIP(t, resp, net.ParseIP(saturatedLocalIP))
		assert.Less(t, elapsed, 150*time.Millisecond)
		t.Logf("rewrite answered in %s", elapsed)
	})

	t.Run("cache", func(t *testing.T) {
		t.Parallel()

		block := make(chan struct{})
		var inUpstream atomic.Int32
		addr := startBlockingProxy(t, block, &inUpstream, true, nil)

		prime, err := exchangeA(addr, saturatedCachedName, time.Second)
		require.NoError(t, err)
		requireAnswerIP(t, prime, proxytest.IPv4)

		saturateUpstream(t, addr, &inUpstream)

		started := time.Now()
		resp, err := exchangeA(addr, saturatedCachedName, 300*time.Millisecond)
		elapsed := time.Since(started)
		require.NoError(t, err)
		requireAnswerIP(t, resp, proxytest.IPv4)
		assert.Less(t, elapsed, 150*time.Millisecond)
		t.Logf("cache hit answered in %s", elapsed)
	})
}

// startBlockingProxy starts a UDP proxy whose upstream blocks on
// [saturatedBlockedName] until block is closed.  inUpstream counts those
// blocked exchanges.  handler may be nil to use the default resolver.
func startBlockingProxy(
	tb testing.TB,
	block chan struct{},
	inUpstream *atomic.Int32,
	cache bool,
	handler proxy.Handler,
) (addr string) {
	tb.Helper()

	tb.Cleanup(func() { close(block) })

	u := &dnsproxytest.Upstream{
		OnAddress: func() (addr string) { return "blocked.invalid." },
		OnClose:   func() (err error) { return nil },
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			if req.Question[0].Name == saturatedBlockedName {
				inUpstream.Add(1)
				<-block
			}

			resp = (&dns.Msg{}).SetReply(req)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    testTTL,
				},
				A: proxytest.IPv4.To4(),
			}}

			return resp, nil
		},
	}

	p, err := proxy.New(&proxy.Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{u},
		},
		TrustedProxies:  proxytest.DefaultTrustedProxies,
		RequestHandler:  handler,
		MaxGoroutines:   2,
		CacheEnabled:    cache,
		CacheSizeBytes:  proxytest.CacheSize,
		PendingRequests: &proxy.PendingRequestsConfig{Enabled: cache},
	})
	require.NoError(tb, err)
	servicetest.RequireRun(tb, p, proxytest.Timeout)

	return p.Addr(proxy.ProtoUDP).String()
}

// saturateUpstream holds one upstream exchange, then sends a second.  The
// second either stays queued without an admission slot, and its client times
// out, or it also enters the upstream.  Either way the reserved admission slot
// is not held by both for the local query that follows.
func saturateUpstream(tb testing.TB, addr string, inUpstream *atomic.Int32) {
	tb.Helper()

	long := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	go func() {
		req := new(dns.Msg)
		req.SetQuestion(saturatedBlockedName, dns.TypeA)
		_, _, _ = long.Exchange(req, addr)
	}()
	require.Eventually(tb, func() bool {
		return inUpstream.Load() >= 1
	}, time.Second, time.Millisecond)

	secondErr := make(chan error, 1)
	secondResp := make(chan *dns.Msg, 1)
	go func() {
		resp, err := exchangeA(addr, saturatedBlockedName, 500*time.Millisecond)
		secondResp <- resp
		secondErr <- err
	}()

	waitForSaturation(tb, inUpstream, secondErr, secondResp)
}

// waitForSaturation returns when a second upstream exchange is blocked or has
// already failed with SERVFAIL.
func waitForSaturation(
	tb testing.TB,
	inUpstream *atomic.Int32,
	secondErr <-chan error,
	secondResp <-chan *dns.Msg,
) {
	tb.Helper()

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()

	for {
		if inUpstream.Load() >= 2 {
			return
		}

		select {
		case err := <-secondErr:
			if err != nil {
				// Admission or the upstream is still holding every slot, so
				// this exchange timed out.  The local query below will too.
				return
			}

			require.Equal(tb, dns.RcodeServerFailure, (<-secondResp).Rcode)

			return
		case <-deadline.C:
			tb.Fatal("timed out waiting for upstream saturation")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestProxy_ServeDNS_upstreamBurstWaits(t *testing.T) {
	t.Parallel()

	const (
		burst       = 6
		delay       = 50 * time.Millisecond
		maxRoutines = 2
	)

	u := &dnsproxytest.Upstream{
		OnAddress: func() (addr string) { return "slow.invalid." },
		OnClose:   func() (err error) { return nil },
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			time.Sleep(delay)
			resp = (&dns.Msg{}).SetReply(req)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    testTTL,
				},
				A: proxytest.IPv4.To4(),
			}}

			return resp, nil
		},
	}
	p, err := proxy.New(&proxy.Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{u},
		},
		TrustedProxies: proxytest.DefaultTrustedProxies,
		MaxGoroutines:  maxRoutines,
	})
	require.NoError(t, err)
	servicetest.RequireRun(t, p, proxytest.Timeout)

	addr := p.Addr(proxy.ProtoUDP).String()
	var servfails atomic.Int32
	var noerrors atomic.Int32
	var failures atomic.Int32
	var wg sync.WaitGroup
	for i := range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()

			resp, exchErr := exchangeA(addr, fmt.Sprintf("burst-%d.test.", i), 3*time.Second)
			countBurstResult(resp, exchErr, &noerrors, &servfails, &failures)
		}()
	}
	wg.Wait()

	t.Logf("burst %d: noerror=%d servfail=%d other_err=%d", burst, noerrors.Load(), servfails.Load(), failures.Load())
	assert.Equal(t, int32(0), failures.Load())
	assert.Equal(t, int32(0), servfails.Load())
	assert.Equal(t, int32(burst), noerrors.Load())
}

// countBurstResult records one burst response.
func countBurstResult(
	resp *dns.Msg,
	err error,
	noerrors *atomic.Int32,
	servfails *atomic.Int32,
	failures *atomic.Int32,
) {
	if err != nil || resp == nil {
		failures.Add(1)

		return
	}

	switch resp.Rcode {
	case dns.RcodeServerFailure:
		servfails.Add(1)
	case dns.RcodeSuccess:
		noerrors.Add(1)
	default:
		failures.Add(1)
	}
}

// exchangeA sends an A query for name to addr.
func exchangeA(addr, name string, timeout time.Duration) (resp *dns.Msg, err error) {
	client := &dns.Client{Net: "udp", Timeout: timeout}
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)

	resp, _, err = client.Exchange(req, addr)

	return resp, err
}

// localRewrite returns an A answer for a handler-local name.
func localRewrite(req *dns.Msg) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetReply(req)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    testTTL,
		},
		A: net.ParseIP(saturatedLocalIP),
	}}

	return resp
}

// requireAnswerIP asserts that resp is a single A answer for want.
func requireAnswerIP(tb testing.TB, resp *dns.Msg, want net.IP) {
	tb.Helper()

	require.NotNil(tb, resp)
	require.Equal(tb, dns.RcodeSuccess, resp.Rcode)
	require.Len(tb, resp.Answer, 1)

	ans := testutil.RequireTypeAssert[*dns.A](tb, resp.Answer[0])
	assert.True(tb, ans.A.Equal(want))
}
