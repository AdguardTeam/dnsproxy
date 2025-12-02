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

func TestPrefetch_MixedTTL_Stability(t *testing.T) {
	// This test simulates a mixed environment with Short, Medium, and Long TTL domains.
	// It verifies that prefetch triggers at appropriate times for each.

	// Mock Upstream Logic
	// Returns different IPs and TTLs based on the domain
	domains := map[string]struct {
		ttl uint32
		ips []string
	}{
		"short.example.com.":  {ttl: 10, ips: []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"}},
		"medium.example.com.": {ttl: 60, ips: []string{"2.2.2.1", "2.2.2.2", "2.2.2.3"}},
		"long.example.com.":   {ttl: 300, ips: []string{"3.3.3.1", "3.3.3.2", "3.3.3.3"}},
	}

	mu := &sync.Mutex{}
	counters := make(map[string]int)

	mockU := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			mu.Lock()
			defer mu.Unlock()

			q := m.Question[0]
			info, ok := domains[q.Name]
			if !ok {
				return new(dns.Msg), fmt.Errorf("unknown domain")
			}

			idx := counters[q.Name]
			if idx >= len(info.ips) {
				idx = len(info.ips) - 1
			}
			ip := info.ips[idx]
			counters[q.Name]++

			resp := new(dns.Msg)
			resp.SetReply(m)
			rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN A %s", q.Name, info.ttl, ip))
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
			Enabled:       true,
			BatchSize:     5,
			CheckInterval: 100 * time.Millisecond, // Fast check for test
			RefreshBefore: 5 * time.Second,        // Min safety margin
			Threshold:     1,
		},
	}
	p, err := New(config)
	require.NoError(t, err)

	err = p.Start(context.TODO())
	require.NoError(t, err)
	defer p.Shutdown(context.TODO())

	// Helper to query and check
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

	// 1. Initial Queries to populate cache
	fmt.Println("Step 1: Initial Queries")
	for domain, info := range domains {
		ip, ttl := query(domain)
		assert.Equal(t, info.ips[0], ip)
		assert.Equal(t, info.ttl, ttl)
		fmt.Printf("[%s] Initial: IP=%s, TTL=%d\n", domain, ip, ttl)
	}

	// 2. Wait and Query Loop
	// We will loop and check if cache updates happen as expected.
	// Short (10s): Should refresh around T+5s (since 10% is 1s, but min is 5s, capped at 5s)
	// Medium (60s): Should refresh around T+54s (10% is 6s) -> Wait, logic is RefreshBefore.
	// Logic: max(TotalTTL/10, RefreshBefore).
	// Short (10s): max(1s, 5s) = 5s. Cap at 10/2=5s. So refresh at T+5s.
	// Medium (60s): max(6s, 5s) = 6s. So refresh at T+54s.
	// Long (300s): max(30s, 5s) = 30s. So refresh at T+270s.

	// To test this quickly, we can't wait 270s.
	// We will verify Short and Medium mainly, and check Long doesn't refresh too early.

	fmt.Println("Step 2: Monitoring Updates")

	// Check Short Domain (TTL 10s)
	// Wait 6s. Should be refreshed.
	time.Sleep(6 * time.Second)
	ip, ttl := query("short.example.com.")
	fmt.Printf("[short.example.com.] After 6s: IP=%s, TTL=%d\n", ip, ttl)
	assert.Equal(t, "1.1.1.2", ip, "Short domain should have updated to 2nd IP")
	assert.True(t, ttl > 5, "TTL should be refreshed")

	// Check Medium Domain (TTL 60s)
	// It should NOT have refreshed yet (only 6s passed, needs 54s).
	ip, _ = query("medium.example.com.")
	fmt.Printf("[medium.example.com.] After 6s: IP=%s\n", ip)
	assert.Equal(t, "2.2.2.1", ip, "Medium domain should NOT have updated yet")

	// Wait another 50s (Total 56s). Medium should refresh.
	// Note: In test environment, we might need to be careful with exact timing.
	// Let's wait until T+55s.
	time.Sleep(49 * time.Second)
	ip, ttl = query("medium.example.com.")
	fmt.Printf("[medium.example.com.] After 55s: IP=%s, TTL=%d\n", ip, ttl)
	assert.Equal(t, "2.2.2.2", ip, "Medium domain should have updated to 2nd IP")

	// Check Long Domain (TTL 300s)
	// Total 55s passed. Should NOT refresh (needs 270s).
	ip, _ = query("long.example.com.")
	fmt.Printf("[long.example.com.] After 55s: IP=%s\n", ip)
	assert.Equal(t, "3.3.3.1", ip, "Long domain should NOT have updated yet")

}
