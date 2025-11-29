package proxy

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// BenchmarkStats benchmarks the Stats() method
// This verifies the O(1) performance of the atomic uniqueDomainsCount
func BenchmarkStats(b *testing.B) {
	// Setup
	mu := &mockUpstream{}
	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
	}
	p, _ := New(config)
	pc := &PrefetchConfig{Enabled: true, MaxQueueSize: 100000}
	pm := NewPrefetchQueueManager(p, pc)

	// Fill queue with 1000 items
	for i := 0; i < 1000; i++ {
		domain := fmt.Sprintf("example-%d.com", i)
		pm.Add(domain, dns.TypeA, nil, time.Now().Add(time.Hour))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm.Stats()
	}
}

// BenchmarkProcessQueue benchmarks the throughput of queue processing
// This verifies the non-blocking behavior
func BenchmarkProcessQueue(b *testing.B) {
	// Setup slow upstream (1ms delay)
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			time.Sleep(1 * time.Millisecond)
			return new(dns.Msg), nil
		},
	}
	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
	}
	p, _ := New(config)

	// High concurrency to test non-blocking dispatch
	pc := &PrefetchConfig{
		Enabled:               true,
		MaxQueueSize:          100000,
		MaxConcurrentRequests: 100,
		BatchSize:             100,
		RefreshBefore:         100 * time.Hour, // Ensure items are "expired" relative to refreshBefore
	}
	pm := NewPrefetchQueueManager(p, pc)

	// We need to manually trigger processQueue, so we don't Start() the manager
	// Instead we fill the queue and call processQueue directly in the loop

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Refill queue if empty
		if pm.queue.Len() < 100 {
			for j := 0; j < 100; j++ {
				domain := fmt.Sprintf("bench-%d-%d.com", i, j)
				// Set expire time such that it triggers refresh (now + 1s < now + 100h)
				pm.Add(domain, dns.TypeA, nil, time.Now().Add(1*time.Second))
			}
		}
		b.StartTimer()

		pm.processQueue()
	}
}
