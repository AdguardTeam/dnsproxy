package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefetch_Comprehensive(t *testing.T) {
	// Comprehensive test covering:
	// 1. Very Short TTL (2s) - Edge case for timing.
	// 2. Fluctuating TTL (10s -> 5s -> 20s) - Adaptability.
	// 3. Batch Load (20 domains) - Worker pool stress.

	// Domain Configurations
	type domainConfig struct {
		ttls []uint32 // Sequence of TTLs to return
		ips  []string // Sequence of IPs to return
	}

	configs := make(map[string]*domainConfig)
	mu := &sync.Mutex{}
	counters := make(map[string]int)

	// 1. Very Short TTL (2s)
	// Logic: max(2*0.1, 5) = 5, capped at 2/2 = 1s. Refresh at T+1s.
	configs["fast.com."] = &domainConfig{
		ttls: []uint32{2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		ips:  []string{"1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4", "1.0.0.5", "1.0.0.6", "1.0.0.7", "1.0.0.8", "1.0.0.9", "1.0.0.10"},
	}

	// 2. Fluctuating TTL (10s -> 5s -> 20s)
	// T=0: TTL 10s. Refresh ~T+5s.
	// T=5: TTL 5s. Refresh ~T+7.5s (5/2 = 2.5s).
	// T=7.5: TTL 20s. Refresh ~T+22.5s (20 - 5 = 15s).
	configs["flux.com."] = &domainConfig{
		ttls: []uint32{10, 5, 20, 10},
		ips:  []string{"2.0.0.1", "2.0.0.2", "2.0.0.3", "2.0.0.4"},
	}

	// 3. Batch Load (20 domains)
	// TTL 30s. Refresh ~T+25s.
	for i := 0; i < 20; i++ {
		domain := fmt.Sprintf("batch-%d.com.", i)
		configs[domain] = &domainConfig{
			ttls: []uint32{30, 30, 30},
			ips:  []string{fmt.Sprintf("3.0.%d.1", i), fmt.Sprintf("3.0.%d.2", i), fmt.Sprintf("3.0.%d.3", i)},
		}
	}

	mockU := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			mu.Lock()
			defer mu.Unlock()

			q := m.Question[0]
			conf, ok := configs[q.Name]
			if !ok {
				return new(dns.Msg), fmt.Errorf("unknown domain")
			}

			idx := counters[q.Name]
			if idx >= len(conf.ips) {
				idx = len(conf.ips) - 1
			}

			// Use the TTL corresponding to the current index
			ttlIdx := idx
			if ttlIdx >= len(conf.ttls) {
				ttlIdx = len(conf.ttls) - 1
			}

			ip := conf.ips[idx]
			ttl := conf.ttls[ttlIdx]

			// Increment for next time
			counters[q.Name]++

			resp := new(dns.Msg)
			resp.SetReply(m)
			rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN A %s", q.Name, ttl, ip))
			resp.Answer = append(resp.Answer, rr)
			return resp, nil
		},
	}

	config := &Config{
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{mockU},
		},
		UDPListenAddr: []*net.UDPAddr{
			{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		},
		CacheEnabled:          true,
		CacheSizeBytes:        1024 * 1024,
		CacheOptimisticMaxAge: 1 * time.Hour,
		Prefetch: &PrefetchConfig{
			Enabled:               true,
			BatchSize:             20,
			CheckInterval:         100 * time.Millisecond,
			RefreshBefore:         5 * time.Second,
			Threshold:             1,
			ThresholdWindow:       1 * time.Hour,
			MaxConcurrentRequests: 20,
		},
	}
	p, err := New(config)
	require.NoError(t, err)
	defer p.Shutdown(context.TODO())

	query := func(domain string) (string, uint32) {
		req := new(dns.Msg)
		req.SetQuestion(domain, dns.TypeA)
		dctx := p.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		err := p.Resolve(dctx)
		require.NoError(t, err)
		require.NotNil(t, dctx.Res)
		require.NotEmpty(t, dctx.Res.Answer)
		a := dctx.Res.Answer[0].(*dns.A)
		return a.A.String(), a.Header().Ttl
	}

	// --- Step 1: Initial Queries ---
	fmt.Println("Step 1: Initial Queries")
	for domain := range configs {
		ip, _ := query(domain)
		// Verify initial IP (suffix .1)
		expected := configs[domain].ips[0]
		assert.Equal(t, expected, ip, "Initial IP mismatch for %s", domain)
	}

	// --- Step 2: Verify Very Short TTL (fast.com) ---
	// TTL=2s. Should refresh every ~1s.
	// Wait 3s. Should have refreshed at least once, maybe twice.
	fmt.Println("Waiting 3s for fast.com...")
	time.Sleep(3 * time.Second)

	ip, _ := query("fast.com.")
	// Should be at least 1.0.0.2 or 1.0.0.3
	assert.NotEqual(t, "1.0.0.1", ip, "fast.com should have updated")
	fmt.Printf("[fast.com] IP: %s\n", ip)

	// --- Step 3: Verify Fluctuating TTL (flux.com) ---
	// Initial: TTL 10s. Refresh at T+5s.
	// Current time: T+3s. Not refreshed yet.
	ip, _ = query("flux.com.")
	assert.Equal(t, "2.0.0.1", ip, "flux.com should NOT have updated yet")

	// Wait 3s more (Total T+6s). Should have refreshed to IP 2 (TTL 5s).
	fmt.Println("Waiting 3s for flux.com update 1...")
	time.Sleep(3 * time.Second)
	ip, ttl := query("flux.com.")
	assert.Equal(t, "2.0.0.2", ip, "flux.com should have updated to IP 2")
	// New TTL is 5s. Refresh at T+2.5s from now.
	fmt.Printf("[flux.com] IP: %s, TTL: %d\n", ip, ttl)

	// Wait 4s more (Total T+10s). Should have refreshed to IP 3 (TTL 20s).
	fmt.Println("Waiting 4s for flux.com update 2...")
	time.Sleep(4 * time.Second)
	ip, ttl = query("flux.com.")
	assert.Equal(t, "2.0.0.3", ip, "flux.com should have updated to IP 3")
	// New TTL is 20s. Refresh at T+15s from now.
	fmt.Printf("[flux.com] IP: %s, TTL: %d\n", ip, ttl)

	// Wait 5s more (Total T+15s). Should NOT refresh yet (needs 15s).
	fmt.Println("Waiting 5s for flux.com stable...")
	time.Sleep(5 * time.Second)
	ip, _ = query("flux.com.")
	assert.Equal(t, "2.0.0.3", ip, "flux.com should still be IP 3")

	// --- Step 4: Verify Batch Load ---
	// Initial TTL 30s. Refresh at T+25s.
	// Current time: T+15s.
	// Wait 15s more (Total T+30s). All batch domains should have updated.
	fmt.Println("Waiting 15s for batch update...")
	time.Sleep(15 * time.Second)

	for i := 0; i < 20; i++ {
		domain := fmt.Sprintf("batch-%d.com.", i)
		ip, _ := query(domain)
		expected := fmt.Sprintf("3.0.%d.2", i)
		assert.Equal(t, expected, ip, "Batch domain %s failed to update", domain)
	}
}
