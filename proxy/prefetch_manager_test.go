package proxy

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockUpstream struct {
	exchangeFunc func(m *dns.Msg) (*dns.Msg, error)
}

func (mu *mockUpstream) Exchange(m *dns.Msg) (*dns.Msg, error) {
	if mu.exchangeFunc != nil {
		return mu.exchangeFunc(m)
	}
	return new(dns.Msg), nil
}

func (mu *mockUpstream) Address() string { return "1.1.1.1:53" }
func (mu *mockUpstream) Close() error    { return nil }

func TestPrefetchQueueManager(t *testing.T) {
	// Create a mock upstream
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			resp := new(dns.Msg)
			resp.SetReply(m)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IP{1, 2, 3, 4},
			})
			return resp, nil
		},
	}

	// Create Proxy with this upstream
	config := &Config{
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{mu},
		},
		UDPListenAddr: []*net.UDPAddr{
			{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		},
	}
	p, err := New(config)
	require.NoError(t, err)

	// Create PrefetchQueueManager
	pc := &PrefetchConfig{
		Enabled:       true,
		BatchSize:     1,
		CheckInterval: 100 * time.Millisecond,
		RefreshBefore: 1 * time.Hour, // Always refresh if in queue
	}
	pm := NewPrefetchQueueManager(p, pc)
	pm.Start()
	defer pm.Stop()

	// Add item with time.Now() to trigger immediate processing
	pm.Add("example.com", dns.TypeA, nil, nil, time.Now())
	time.Sleep(200 * time.Millisecond)

	// Verify stats
	refreshed, failed, _ := pm.GetStats()
	assert.Equal(t, int64(1), refreshed)
	assert.Equal(t, int64(0), failed)
}

func TestPrefetchQueueManager_Concurrency(t *testing.T) {
	// Create a slow mock upstream
	startCh := make(chan struct{})
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			<-startCh // Wait for signal
			return new(dns.Msg), nil
		},
	}

	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
	}
	p, err := New(config)
	require.NoError(t, err)

	// MaxConcurrentRequests = 2
	pc := &PrefetchConfig{
		Enabled:               true,
		BatchSize:             5,
		CheckInterval:         100 * time.Millisecond,
		RefreshBefore:         1 * time.Hour,
		MaxConcurrentRequests: 2,
		Threshold:             10, // Prevent retention
	}
	pm := NewPrefetchQueueManager(p, pc)
	// Don't start PM automatically, we want to control processQueue
	// But processQueue is private. We can use Start() and rely on smart scheduling.
	pm.Start()
	defer pm.Stop()

	// Add 5 items
	now := time.Now()
	for i := 0; i < 5; i++ {
		domain := fmt.Sprintf("example-%d.com", i)
		// Use time.Now() to ensure immediate processing (bypass 50% TTL wait)
		pm.Add(domain, dns.TypeA, nil, nil, now)
	}

	// Give it a moment to start goroutines
	time.Sleep(50 * time.Millisecond)

	// Wait for async processing to complete
	close(startCh)
	time.Sleep(100 * time.Millisecond)

	// All 5 items should have been processed (no retention due to high threshold)
	assert.Equal(t, int64(5), pm.totalProcessed.Load(), "Should have processed all 5 items")
}
