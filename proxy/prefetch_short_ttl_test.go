package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// TestShortTTL verifies the smart refresh threshold logic
func TestShortTTL(t *testing.T) {
	// Helper to create fresh manager
	createManager := func() *PrefetchQueueManager {
		mu := &mockUpstream{
			exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
				return new(dns.Msg), nil
			},
		}
		config := &Config{
			UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
			UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
		}
		p, _ := New(config)
		pc := &PrefetchConfig{
			Enabled:         true,
			Threshold:       1,
			ThresholdWindow: 1 * time.Second,
			BatchSize:       1,
			CheckInterval:   100 * time.Millisecond,
			RefreshBefore:   5 * time.Second, // Default 5s
		}
		return NewPrefetchQueueManager(p, pc)
	}

	t.Run("Short TTL", func(t *testing.T) {
		pm := createManager()
		pm.Start()
		defer pm.Stop()

		domain := "short-ttl.com"
		// TTL = 2s. RefreshBefore = 5s.
		// Effective RefreshBefore should be min(5, 2/2) = 1s.
		// So it should NOT refresh immediately (Wait < 1s).

		pm.CheckThreshold(domain, dns.TypeA, nil)

		// Add item with 2s TTL
		pm.Add(domain, dns.TypeA, nil, nil, time.Now().Add(2*time.Second))

		// Wait 200ms.
		// Remaining TTL ~ 1.8s.
		// Threshold = 1s.
		// 1.8s > 1s, so NO refresh.
		time.Sleep(200 * time.Millisecond)

		// Queue should still have the item (not popped for processing)
		// But wait, processQueue pops and checks. If not ready, does it put it back?
		// No, processQueue peeks. If not ready, it returns.
		// So queue len should be 1.
		assert.Equal(t, 1, pm.queue.Len(), "Should NOT be processed yet")

		// Wait until 1.1s passed (Remaining ~ 0.9s < 1s)
		time.Sleep(1000 * time.Millisecond)

		// Now it should be processed
		// Wait for processing cycle
		time.Sleep(200 * time.Millisecond)

		// It might be re-added or removed depending on retention.
		// But the point is it WAS processed.
		// We can check totalProcessed count.
		assert.Equal(t, int64(1), pm.totalProcessed.Load(), "Should be processed after threshold")
	})

	t.Run("Long TTL", func(t *testing.T) {
		pm := createManager()
		pm.Start()
		defer pm.Stop()

		domain := "long-ttl.com"
		// TTL = 60s. RefreshBefore = 5s.
		// Effective RefreshBefore = 5s.

		pm.CheckThreshold(domain, dns.TypeA, nil)

		// Add item with 60s TTL
		pm.Add(domain, dns.TypeA, nil, nil, time.Now().Add(60*time.Second))

		// Wait 200ms. Remaining ~ 59.8s > 5s. No refresh.
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, 1, pm.queue.Len(), "Should NOT be processed yet")
		assert.Equal(t, int64(0), pm.totalProcessed.Load())

		// We won't wait 55s for this test, but logic is verified by Short TTL case.
	})
}
