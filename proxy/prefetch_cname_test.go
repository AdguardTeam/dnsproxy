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

// TestPrefetch_CNAME verifies prefetch behavior for domains with CNAME records.
func TestPrefetch_CNAME(t *testing.T) {
	// 1. Setup Mock Upstream
	var reqCount atomic.Int32
	ups := &dnsproxytest.Upstream{
		OnAddress: func() string { return "1.1.1.1:53" },
		OnExchange: func(req *dns.Msg) (*dns.Msg, error) {
			count := reqCount.Add(1)
			resp := (&dns.Msg{}).SetReply(req)

			// Return CNAME + A
			// cname.example.com -> target.example.com -> 192.0.2.x
			resp.Answer = append(resp.Answer,
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   req.Question[0].Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    3600, // Long TTL for CNAME
					},
					Target: "target.example.com.",
				},
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "target.example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    2, // Short TTL for A
					},
					A: net.IP{192, 0, 2, byte(count)},
				},
			)
			return resp, nil
		},
		OnClose: func() error { return nil },
	}

	// 2. Configure Proxy
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
			RefreshBefore:         1 * time.Second,
		},
	})
	require.NoError(t, err)
	require.NoError(t, p.Start(testutil.ContextWithTimeout(t, testTimeout)))
	defer p.Shutdown(testutil.ContextWithTimeout(t, testTimeout))

	// Helper to perform a query
	doQuery := func(domain string) *dns.Msg {
		req := (&dns.Msg{}).SetQuestion(domain, dns.TypeA)
		d := &proxy.DNSContext{
			Req: req,
		}
		err := p.Resolve(d)
		require.NoError(t, err)
		return d.Res
	}

	t.Run("CNAME_Prefetch", func(t *testing.T) {
		domain := "cname.example.com."
		reqCount.Store(0)

		// Query 1: Cache Miss
		doQuery(domain)
		assert.Equal(t, int32(1), reqCount.Load(), "Query 1 should hit upstream")

		// Reset counter
		reqCount.Store(0)

		// Query 2: Cache Hit
		// Expect: Prefetch triggered (Threshold=2)
		doQuery(domain)

		// Wait for prefetch and cache update
		assert.Eventually(t, func() bool {
			resp := doQuery(domain)
			if len(resp.Answer) < 2 {
				return false
			}
			// Check A record IP (second record)
			aRecord, ok := resp.Answer[1].(*dns.A)
			if !ok {
				return false
			}
			ip := aRecord.A
			t.Logf("ReqCount: %d, IP: %s", reqCount.Load(), ip)
			return ip.Equal(net.IP{192, 0, 2, 2})
		}, 4*time.Second, 100*time.Millisecond, "Cache should be updated by prefetch to 192.0.2.2")
	})

	t.Run("CNAME_Prefetch_Optimistic", func(t *testing.T) {
		// Enable Optimistic Cache
		p.Config.CacheOptimistic = true
		defer func() { p.Config.CacheOptimistic = false }()

		domain := "optimistic.example.com."
		reqCount.Store(0)

		// Query 1: Cache Miss
		doQuery(domain)
		assert.Equal(t, int32(1), reqCount.Load(), "Query 1 should hit upstream")

		// Reset counter
		reqCount.Store(0)

		// Query 2: Cache Hit
		// Expect: Prefetch triggered (Threshold=2)
		doQuery(domain)

		// Wait for prefetch and cache update
		assert.Eventually(t, func() bool {
			resp := doQuery(domain)
			if len(resp.Answer) < 2 {
				return false
			}
			aRecord, ok := resp.Answer[1].(*dns.A)
			if !ok {
				return false
			}
			ip := aRecord.A
			t.Logf("Opt ReqCount: %d, IP: %s", reqCount.Load(), ip)
			return ip.Equal(net.IP{192, 0, 2, 2})
		}, 4*time.Second, 100*time.Millisecond, "Cache should be updated by prefetch to 192.0.2.2")
	})
}
