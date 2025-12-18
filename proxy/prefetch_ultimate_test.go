package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefetch_Ultimate(t *testing.T) {
	// This test suite covers advanced edge cases:
	// 1. Upstream Failure & Retry
	// 2. Queue Overflow
	// 3. Threshold Logic
	// 4. High Concurrency Deduplication
	// 5. ECS Support

	t.Run("UpstreamFailureAndRetry", func(t *testing.T) {
		// Setup: Upstream fails first 2 times, succeeds on 3rd.
		// Prefetcher retries up to 2 times (total 3 attempts).
		// So it should succeed.

		failCount := int32(0)
		mockU := &mockUpstream{
			exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
				count := atomic.AddInt32(&failCount, 1)
				if count <= 2 {
					return nil, fmt.Errorf("simulated network error")
				}
				resp := new(dns.Msg)
				resp.SetReply(m)
				rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 1.2.3.4", m.Question[0].Name))
				resp.Answer = append(resp.Answer, rr)
				return resp, nil
			},
		}

		p := createTestProxy(t, mockU, &PrefetchConfig{
			Enabled:       true,
			CheckInterval: 100 * time.Millisecond,
			RefreshBefore: 5 * time.Second,
		})
		defer p.Shutdown(context.TODO())

		// Trigger prefetch
		// We manually add to queue to bypass initial Resolve failure
		// and strictly test the background prefetch retry logic.
		// Set expiration to near future so it triggers quickly.
		p.cache.prefetchManager.Add("retry.com.", dns.TypeA, nil, nil, time.Now().Add(200*time.Millisecond))

		// Wait for prefetch to run.
		// It should fail twice then succeed.
		time.Sleep(1 * time.Second)

		// Verify stats
		refreshed, failed, _ := p.cache.prefetchManager.GetStats()
		assert.Equal(t, int64(1), refreshed, "Should have succeeded after retries")
		assert.Equal(t, int64(0), failed, "Should NOT count as failed if retry succeeded")
	})

	t.Run("QueueOverflow", func(t *testing.T) {
		// Setup: MaxQueueSize = 10. Add 20 items.
		mockU := &mockUpstream{
			exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
				return simpleResponse(m, "1.2.3.4"), nil
			},
		}

		p := createTestProxy(t, mockU, &PrefetchConfig{
			Enabled:      true,
			MaxQueueSize: 10,
		})
		defer p.Shutdown(context.TODO())

		// Add 20 unique domains
		for i := 0; i < 20; i++ {
			domain := fmt.Sprintf("overflow-%d.com.", i)
			query(t, p, domain)
		}

		// Check queue size
		_, _, queueSize := p.cache.prefetchManager.GetStats()
		assert.Equal(t, 10, queueSize, "Queue size should be capped at 10")
	})

	t.Run("ThresholdLogic", func(t *testing.T) {
		// Setup: Threshold = 3.
		mockU := &mockUpstream{
			exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
				return simpleResponse(m, "1.2.3.4"), nil
			},
		}

		p := createTestProxy(t, mockU, &PrefetchConfig{
			Enabled:   true,
			Threshold: 3,
		})
		defer p.Shutdown(context.TODO())

		domain := "threshold.com."

		// Access 1
		query(t, p, domain)
		_, _, queueSize := p.cache.prefetchManager.GetStats()
		assert.Equal(t, 0, queueSize, "Should not be in queue after 1 access")

		// Access 2
		query(t, p, domain)
		_, _, queueSize = p.cache.prefetchManager.GetStats()
		// Threshold-1 strategy: 3-1=2. So 2nd access triggers prefetch.
		assert.Equal(t, 1, queueSize, "Should be in queue after 2 accesses (Threshold-1)")
	})

	t.Run("ConcurrencyDeduplication", func(t *testing.T) {
		// Setup: 50 concurrent requests for same domain.
		mockU := &mockUpstream{
			exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
				// Simulate some latency to allow concurrency to build up
				time.Sleep(10 * time.Millisecond)
				return simpleResponse(m, "1.2.3.4"), nil
			},
		}

		p := createTestProxy(t, mockU, &PrefetchConfig{
			Enabled: true,
		})
		defer p.Shutdown(context.TODO())

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				query(t, p, "concurrent.com.")
			}()
		}
		wg.Wait()

		// Check queue size. Should be 1.
		_, _, queueSize := p.cache.prefetchManager.GetStats()
		assert.Equal(t, 1, queueSize, "Should have exactly 1 item in queue")
	})

	t.Run("ECSSupport", func(t *testing.T) {
		// Setup: Query with ECS. Verify upstream receives it.
		var receivedSubnet *net.IPNet
		mockU := &mockUpstream{
			exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
				// Inspect ECS
				opt := m.IsEdns0()
				if opt != nil {
					for _, o := range opt.Option {
						if e, ok := o.(*dns.EDNS0_SUBNET); ok {
							receivedSubnet = &net.IPNet{
								IP:   e.Address,
								Mask: net.CIDRMask(int(e.SourceNetmask), 32),
							}
						}
					}
				}
				return simpleResponse(m, "1.2.3.4"), nil
			},
		}

		p := createTestProxy(t, mockU, &PrefetchConfig{
			Enabled: true,
		})
		defer p.Shutdown(context.TODO())

		// Create query with ECS
		req := new(dns.Msg)
		req.SetQuestion("ecs.com.", dns.TypeA)
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		e := new(dns.EDNS0_SUBNET)
		e.Code = dns.EDNS0SUBNET
		e.Family = 1 // IPv4
		e.SourceNetmask = 24
		e.Address = net.ParseIP("1.2.3.0")
		o.Option = append(o.Option, e)
		req.Extra = append(req.Extra, o)

		dctx := p.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		err := p.Resolve(dctx)
		require.NoError(t, err)

		// Wait for prefetch (triggered by Resolve)
		time.Sleep(100 * time.Millisecond)

		// Verify upstream received ECS
		require.NotNil(t, receivedSubnet, "Upstream should have received ECS")
		assert.Equal(t, "1.2.3.0/24", receivedSubnet.String())
	})
}

// Helper functions

func createTestProxy(t *testing.T, u upstream.Upstream, prefetchConf *PrefetchConfig) *Proxy {
	config := &Config{
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{u},
		},
		UDPListenAddr: []*net.UDPAddr{
			{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		},
		CacheEnabled:          true,
		CacheSizeBytes:        1024 * 1024,
		CacheOptimisticMaxAge: 1 * time.Hour,
		Prefetch:              prefetchConf,
	}
	p, err := New(config)
	require.NoError(t, err)
	err = p.Start(context.TODO())
	require.NoError(t, err)
	return p
}

func query(t *testing.T, p *Proxy, domain string) {
	req := new(dns.Msg)
	req.SetQuestion(domain, dns.TypeA)
	dctx := p.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	err := p.Resolve(dctx)
	require.NoError(t, err)
}

func simpleResponse(m *dns.Msg, ip string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(m)
	rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", m.Question[0].Name, ip))
	resp.Answer = append(resp.Answer, rr)
	return resp
}
