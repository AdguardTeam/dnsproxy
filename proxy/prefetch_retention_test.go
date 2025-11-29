package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// TestDynamicRetention verifies the dynamic retention logic
func TestDynamicRetention(t *testing.T) {
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
			Threshold:       5,
			ThresholdWindow: 1 * time.Second,
			BatchSize:       1,
			CheckInterval:   100 * time.Millisecond,
			RefreshBefore:   1 * time.Hour,
		}
		return NewPrefetchQueueManager(p, pc)
	}

	t.Run("Scenario A: Just Qualified", func(t *testing.T) {
		pm := createManager()
		pm.Start()
		defer pm.Stop()

		domain := "scenario-a.com"
		for i := 0; i < 5; i++ {
			pm.CheckThreshold(domain, dns.TypeA, nil)
		}
		pm.Add(domain, dns.TypeA, nil, time.Now().Add(1*time.Minute))
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, 1, pm.queue.Len(), "Should be re-added to queue")
	})

	t.Run("Scenario B: High Heat", func(t *testing.T) {
		pm := createManager()
		pm.Start()
		defer pm.Stop()

		domain := "scenario-b.com"
		for i := 0; i < 50; i++ {
			pm.CheckThreshold(domain, dns.TypeA, nil)
		}
		pm.Add(domain, dns.TypeA, nil, time.Now().Add(1*time.Minute))
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, 1, pm.queue.Len(), "Should be re-added to queue")
	})

	t.Run("Scenario C: Decay", func(t *testing.T) {
		pm := createManager()
		pm.Start()
		defer pm.Stop()

		domain := "scenario-c.com"
		for i := 0; i < 5; i++ {
			pm.CheckThreshold(domain, dns.TypeA, nil)
		}

		// Wait for decay (Window is 1s)
		time.Sleep(1100 * time.Millisecond)

		pm.Add(domain, dns.TypeA, nil, time.Now().Add(1*time.Minute))
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, 0, pm.queue.Len(), "Should NOT be re-added to queue")
	})
}

func TestHybridRetention(t *testing.T) {
	// Helper to create fresh manager
	createManager := func(retentionTime int) *PrefetchQueueManager {
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
			Threshold:       5,
			ThresholdWindow: 1 * time.Second,
			BatchSize:       1,
			CheckInterval:   100 * time.Millisecond,
			RefreshBefore:   1 * time.Hour,
			RetentionTime:   retentionTime,
		}
		return NewPrefetchQueueManager(p, pc)
	}

	t.Run("Fixed Retention Mode", func(t *testing.T) {
		// RetentionTime = 60s
		pm := createManager(60)
		pm.Start()
		defer pm.Stop()

		domain := "fixed-retention.com"
		// Simulate only 1 hit (below threshold of 5)
		// In dynamic mode, this would NOT be retained.
		// In fixed mode, it SHOULD be retained if idle < 60s.
		pm.CheckThreshold(domain, dns.TypeA, nil)

		pm.Add(domain, dns.TypeA, nil, time.Now().Add(1*time.Minute))
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, 1, pm.queue.Len(), "Should be retained in fixed mode despite low heat")
	})

	t.Run("Dynamic Retention Mode", func(t *testing.T) {
		// RetentionTime = 0 (Dynamic)
		pm := createManager(0)
		pm.Start()
		defer pm.Stop()

		domain := "dynamic-retention.com"
		// Simulate 1 hit (below threshold)
		pm.CheckThreshold(domain, dns.TypeA, nil)

		pm.Add(domain, dns.TypeA, nil, time.Now().Add(1*time.Minute))
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, 0, pm.queue.Len(), "Should NOT be retained in dynamic mode with low heat")
	})
}
