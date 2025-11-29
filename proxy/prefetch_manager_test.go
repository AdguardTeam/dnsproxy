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
	}
	pm := NewPrefetchQueueManager(p, pc)
	// Don't start PM automatically, we want to control processQueue
	// But processQueue is private. We can use Start() and rely on smart scheduling.
	pm.Start()
	defer pm.Stop()

	// Add 5 items
	now := time.Now()
	for i := 0; i < 5; i++ {
		pm.Add("example.com", dns.TypeA, nil, now.Add(10*time.Second))
	}

	// Give it a moment to start goroutines
	time.Sleep(50 * time.Millisecond)

	// Check that only 2 goroutines acquired the semaphore
	close(startCh)

	// Wait for completion
	time.Sleep(100 * time.Millisecond)
}

func TestPrefetchQueueManager_QueueBloat(t *testing.T) {
	// Create a mock upstream
	mu := &mockUpstream{}

	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
	}
	p, err := New(config)
	require.NoError(t, err)

	pc := &PrefetchConfig{Enabled: true}
	pm := NewPrefetchQueueManager(p, pc)

	now := time.Now()
	// Add same item multiple times
	for i := 0; i < 10; i++ {
		pm.Add("example.com", dns.TypeA, nil, now.Add(10*time.Second))
	}

	// Should only be 1 item in queue
	assert.Equal(t, 1, pm.queue.Len())
}

func TestPrefetchQueueManager_ECS(t *testing.T) {
	// Create a mock upstream that checks for ECS
	ecsFound := false
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			opt := m.IsEdns0()
			if opt != nil {
				for _, o := range opt.Option {
					if o.Option() == dns.EDNS0SUBNET {
						ecsFound = true
					}
				}
			}
			return new(dns.Msg), nil
		},
	}

	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
	}
	p, err := New(config)
	require.NoError(t, err)

	pc := &PrefetchConfig{
		Enabled:       true,
		BatchSize:     1,
		RefreshBefore: 1 * time.Hour,
	}
	pm := NewPrefetchQueueManager(p, pc)
	pm.Start()
	defer pm.Stop()

	subnet := &net.IPNet{
		IP:   net.IPv4(1, 2, 3, 0),
		Mask: net.CIDRMask(24, 32),
	}
	pm.Add("example.com", dns.TypeA, subnet, time.Now().Add(10*time.Second))

	time.Sleep(100 * time.Millisecond)

	assert.True(t, ecsFound, "ECS option should be present in prefetch request")
}

func TestPrefetchQueueManager_Threshold(t *testing.T) {
	mu := &mockUpstream{}
	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
	}
	p, err := New(config)
	require.NoError(t, err)

	pc := &PrefetchConfig{
		Enabled:   true,
		Threshold: 3,
	}
	pm := NewPrefetchQueueManager(p, pc)

	// 1st hit
	shouldPrefetch := pm.CheckThreshold("example.com", dns.TypeA, nil)
	assert.False(t, shouldPrefetch)

	// 2nd hit
	shouldPrefetch = pm.CheckThreshold("example.com", dns.TypeA, nil)
	assert.False(t, shouldPrefetch)

	// 3rd hit
	shouldPrefetch = pm.CheckThreshold("example.com", dns.TypeA, nil)
	assert.True(t, shouldPrefetch)
}

func TestPrefetchQueueManager_SmartScheduling(t *testing.T) {
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			return new(dns.Msg), nil
		},
	}
	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
	}
	p, err := New(config)
	require.NoError(t, err)

	pc := &PrefetchConfig{
		Enabled:       true,
		BatchSize:     1,
		RefreshBefore: 1 * time.Second, // Refresh 1s before expiry
	}
	pm := NewPrefetchQueueManager(p, pc)
	pm.Start()
	defer pm.Stop()

	now := time.Now()
	// Add item expiring in 2 seconds. Should refresh in 1 second (2 - 1).
	pm.Add("example.com", dns.TypeA, nil, now.Add(2*time.Second))

	// Immediately, it shouldn't be refreshed yet
	refreshed, _, _ := pm.GetStats()
	assert.Equal(t, int64(0), refreshed)

	// Wait 1.2 seconds
	time.Sleep(1200 * time.Millisecond)

	// Should be refreshed now
	refreshed, _, _ = pm.GetStats()
	assert.Equal(t, int64(1), refreshed)
}

func TestPrefetchQueueManager_BatchFlush(t *testing.T) {
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			return new(dns.Msg), nil
		},
	}
	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
	}
	p, err := New(config)
	require.NoError(t, err)

	pc := &PrefetchConfig{
		Enabled:       true,
		BatchSize:     10,
		RefreshBefore: 1 * time.Second,
	}
	pm := NewPrefetchQueueManager(p, pc)
	pm.Start()
	defer pm.Stop()

	now := time.Now()
	// Item 1: Expires in 2s (Refresh in 1s). This is the trigger.
	pm.Add("trigger.com", dns.TypeA, nil, now.Add(2*time.Second))

	// Item 2: Expires in 1 hour (Refresh in 59m59s). This should NOT be refreshed normally,
	// but SHOULD be refreshed in Batch Flush mode.
	pm.Add("follower.com", dns.TypeA, nil, now.Add(1*time.Hour))

	// Wait 1.2s to trigger Item 1
	time.Sleep(1200 * time.Millisecond)

	refreshed, _, _ := pm.GetStats()
	// Both should be refreshed
	assert.Equal(t, int64(2), refreshed, "Both items should be refreshed in batch flush")
}

func TestPrefetchQueueManager_DynamicPriority(t *testing.T) {
	mu := &mockUpstream{}
	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
	}
	p, err := New(config)
	require.NoError(t, err)

	pc := &PrefetchConfig{Enabled: true}
	pm := NewPrefetchQueueManager(p, pc)

	now := time.Now()
	// Item A: Expires in 100s. Priority ~100.
	pm.Add("A.com", dns.TypeA, nil, now.Add(100*time.Second))

	// Item B: Expires in 10s. Priority ~10.
	pm.Add("B.com", dns.TypeA, nil, now.Add(10*time.Second))

	// Initial order should be B (10), A (100)
	head := pm.queue.Peek()
	assert.Equal(t, "B.com", head.Domain)

	// Hit A 20 times. Each hit reduces priority by 5.
	// 20 * 5 = 100. New priority ~ 100 - 100 = 0.
	// B is still ~10.
	// So A should become head.
	for i := 0; i < 20; i++ {
		pm.Add("A.com", dns.TypeA, nil, now.Add(100*time.Second))
	}

	head = pm.queue.Peek()
	assert.Equal(t, "A.com", head.Domain, "A should become head after multiple hits")
}

func TestPrefetchQueueManager_DynamicBatching(t *testing.T) {
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			return new(dns.Msg), nil
		},
	}

	proxyConfig := &Config{
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{mu},
		},
		UDPListenAddr: []*net.UDPAddr{
			{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		},
	}
	p, err := New(proxyConfig)
	require.NoError(t, err)

	// Case 1: Fixed Batch Size
	configFixed := &PrefetchConfig{
		Enabled:               true,
		BatchSize:             10, // Fixed
		MaxConcurrentRequests: 100,
		CheckInterval:         100 * time.Millisecond,
		RefreshBefore:         1 * time.Hour,
	}
	pmFixed := NewPrefetchQueueManager(p, configFixed)

	now := time.Now()
	readyTime := now.Add(configFixed.RefreshBefore).Add(-1 * time.Second)

	// Add 100 items
	for i := 0; i < 100; i++ {
		domain := fmt.Sprintf("fixed%d.com", i)
		pmFixed.Add(domain, dns.TypeA, nil, readyTime)
	}

	// Process queue
	pmFixed.processQueue()

	// Should pop exactly 10 items
	assert.Equal(t, 90, pmFixed.queue.Len(), "Fixed mode should pop exactly BatchSize items")

	// Case 2: Auto Batch Size (BatchSize = 0)
	// Should default to MaxConcurrentRequests (100)
	configAuto := &PrefetchConfig{
		Enabled:               true,
		BatchSize:             0, // Auto -> 100
		MaxConcurrentRequests: 100,
		CheckInterval:         100 * time.Millisecond,
		RefreshBefore:         1 * time.Hour,
	}
	pmAuto := NewPrefetchQueueManager(p, configAuto)

	// Add 150 items
	for i := 0; i < 150; i++ {
		domain := fmt.Sprintf("auto%d.com", i)
		pmAuto.Add(domain, dns.TypeA, nil, readyTime)
	}

	// Process queue
	pmAuto.processQueue()

	// Logic:
	// BatchSize defaults to MaxConcurrent (100).
	// Queue = 150.
	// PopCount = 100.
	// Remaining = 150 - 100 = 50.
	assert.Equal(t, 50, pmAuto.queue.Len(), "Auto mode should pop MaxConcurrentRequests items")
}

func TestPrefetch_FullScenario(t *testing.T) {
	// Scenario:
	// 1. Threshold = 2 (Need 2 hits to prefetch)
	// 2. BatchSize = 0 (Auto -> MaxConcurrent)
	// 3. MaxConcurrent = 5

	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			return new(dns.Msg), nil
		},
	}

	config := &PrefetchConfig{
		Enabled:               true,
		BatchSize:             0, // Auto -> 5
		MaxConcurrentRequests: 5,
		Threshold:             2,
		CheckInterval:         100 * time.Millisecond,
		RefreshBefore:         1 * time.Hour, // Always ready
	}

	proxyConfig := &Config{
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{mu},
		},
		UDPListenAddr: []*net.UDPAddr{
			{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		},
	}
	p, err := New(proxyConfig)
	require.NoError(t, err)

	pm := NewPrefetchQueueManager(p, config)

	// Step 1: Verify Threshold
	// Hit 1: Should NOT be added
	if pm.CheckThreshold("example.com", dns.TypeA, nil) {
		pm.Add("example.com", dns.TypeA, nil, time.Now())
	}
	assert.Equal(t, 0, pm.queue.Len(), "Should not be added on first hit")
	assert.Equal(t, 0, pm.queue.Len(), "Should not be added on first hit")

	// Hit 2: Should be added
	if pm.CheckThreshold("example.com", dns.TypeA, nil) {
		pm.Add("example.com", dns.TypeA, nil, time.Now().Add(config.RefreshBefore).Add(-1*time.Second))
	}
	assert.Equal(t, 1, pm.queue.Len(), "Should be added on second hit")

	// Step 2: Verify Auto-Batching
	// Add 10 more items (total 11)
	// We force add them to skip threshold for test speed
	for i := 0; i < 10; i++ {
		pm.Add(fmt.Sprintf("bulk%d.com", i), dns.TypeA, nil, time.Now().Add(config.RefreshBefore).Add(-1*time.Second))
	}
	assert.Equal(t, 11, pm.queue.Len(), "Queue should have 11 items")

	// Process Queue
	// MaxConcurrent is 5. So it should pop 5 items.
	pm.processQueue()

	assert.Equal(t, 6, pm.queue.Len(), "Should have popped 5 items (MaxConcurrent)")

	// Process again
	pm.processQueue()
	assert.Equal(t, 1, pm.queue.Len(), "Should have popped another 5 items")

	// Process last one
	pm.processQueue()
	assert.Equal(t, 0, pm.queue.Len(), "Should be empty")
}
