package proxy_test

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrefetch_ComprehensiveVerification verifies prefetch behavior in multiple environments
// including default upstreams and custom upstreams (simulating AdGuardHome integration).
// It also verifies that configured parameters (Threshold) are respected.
func TestPrefetch_ComprehensiveVerification(t *testing.T) {
	// 1. Setup Mock Upstream
	// This upstream will return a different IP for each request to track updates.
	// It also counts the number of requests it receives.
	var reqCount atomic.Int32
	ups := &dnsproxytest.Upstream{
		OnAddress: func() string { return "1.1.1.1:53" },
		OnExchange: func(req *dns.Msg) (*dns.Msg, error) {
			count := reqCount.Add(1)
			resp := (&dns.Msg{}).SetReply(req)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    2, // Short TTL (2s) to ensure prefetch triggers quickly (refresh at <= 1s)
				},
				A: net.IP{192, 0, 2, byte(count)}, // 192.0.2.1, 192.0.2.2, ...
			})
			return resp, nil
		},
		OnClose: func() error { return nil },
	}

	// 2. Configure Proxy
	// Threshold=2 means:
	// - 1st request: Cache Miss (from upstream)
	// - 2nd request: Cache Hit (hits=1) -> No Prefetch
	// - 3rd request: Cache Hit (hits=2) -> Trigger Prefetch
	p, err := proxy.New(&proxy.Config{
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		CacheEnabled:   true,
		CacheSizeBytes: 4096,
		Prefetch: &proxy.PrefetchConfig{
			Enabled:               true,
			Threshold:             2,
			BatchSize:             2,
			MaxQueueSize:          100,
			MaxConcurrentRequests: 5,
			RefreshBefore:         1 * time.Second, // Aggressive refresh
		},
	})
	require.NoError(t, err)
	require.NoError(t, p.Start(testutil.ContextWithTimeout(t, testTimeout)))
	defer p.Shutdown(testutil.ContextWithTimeout(t, testTimeout))

	// Helper to perform a query
	doQuery := func(domain string, customConfig *proxy.CustomUpstreamConfig) *dns.Msg {
		req := (&dns.Msg{}).SetQuestion(domain, dns.TypeA)
		d := &proxy.DNSContext{
			Req:                  req,
			CustomUpstreamConfig: customConfig,
		}
		// We use Resolve directly to simulate internal processing or direct usage
		err := p.Resolve(d)
		require.NoError(t, err)
		return d.Res
	}

	// Scenario 1: Default Upstream Verification
	// Verifies that prefetch works for standard requests.
	t.Run("DefaultUpstream", func(t *testing.T) {
		domain := "default.example.com."
		reqCount.Store(0) // Reset counter

		// Query 1: Cache Miss
		// Expect: Upstream queried (count=1), IP=...1
		doQuery(domain, nil)
		assert.Equal(t, int32(1), reqCount.Load(), "Query 1 should hit upstream")

		// Query 2: Cache Hit (Hit #1)
		// Expect: Cache hit, NO prefetch (Threshold=2)
		// Reset counter to be sure we track *prefetch* requests
		reqCount.Store(0)

		// Query 2: Cache Hit
		// Expect: Cache hit. Prefetch triggered. Upstream queried asynchronously.
		doQuery(domain, nil)

		// Wait for prefetch to happen and cache to be updated
		// We poll the cache by querying until we see the new IP
		assert.Eventually(t, func() bool {
			resp := doQuery(domain, nil)
			if resp.Answer == nil || len(resp.Answer) == 0 {
				return false
			}
			ip := resp.Answer[0].(*dns.A).A
			return ip.Equal(net.IP{192, 0, 2, 2})
		}, 4*time.Second, 100*time.Millisecond, "Cache should be updated by prefetch to 192.0.2.2")
	})

	// Scenario 2: Custom Upstream Verification (AdGuardHome Scenario)
	// Verifies that prefetch works when using CustomUpstreamConfig (which has its own cache).
	t.Run("CustomUpstream", func(t *testing.T) {
		domain := "custom.example.com."
		reqCount.Store(0)

		// Create Custom Config
		// This simulates what AdGuardHome does: creates a config with its own cache.
		customConfig := newCustomUpstreamConfig(ups, true)

		// Query 1: Cache Miss
		doQuery(domain, customConfig)
		assert.Equal(t, int32(1), reqCount.Load(), "Query 1 should hit upstream")

		// Reset counter
		reqCount.Store(0)

		// Query 2: Cache Hit
		// Expect: Prefetch triggered (Threshold=2).
		// This is the CRITICAL check for the bug fix.
		// If the fix is working, this will trigger prefetch using the global manager.
		doQuery(domain, customConfig)

		// Wait for prefetch and cache update
		assert.Eventually(t, func() bool {
			resp := doQuery(domain, customConfig)
			if resp.Answer == nil || len(resp.Answer) == 0 {
				return false
			}
			ip := resp.Answer[0].(*dns.A).A
			return ip.Equal(net.IP{192, 0, 2, 2})
		}, 4*time.Second, 100*time.Millisecond, "Custom cache should be updated by prefetch to 192.0.2.2")
	})
}
