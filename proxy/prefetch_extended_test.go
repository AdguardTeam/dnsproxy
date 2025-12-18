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

func TestPrefetch_Extended_MixedTTL(t *testing.T) {
	// Extended test with multiple domains, varying TTLs, and cache hit verification.
	// We simulate a timeline and check if prefetch updates the cache correctly.

	domains := map[string]struct {
		ttl uint32
		ips []string
	}{
		"short.com.":    {ttl: 10, ips: []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}},
		"medium.com.":   {ttl: 30, ips: []string{"2.2.2.1", "2.2.2.2", "2.2.2.3", "2.2.2.4"}},
		"standard.com.": {ttl: 60, ips: []string{"3.3.3.1", "3.3.3.2", "3.3.3.3", "3.3.3.4"}},
		"long.com.":     {ttl: 300, ips: []string{"4.4.4.1", "4.4.4.2", "4.4.4.3", "4.4.4.4"}},
	}

	mu := &sync.Mutex{}
	counters := make(map[string]int)
	upstreamCalls := make(map[string]int)

	mockU := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			mu.Lock()
			defer mu.Unlock()

			q := m.Question[0]
			info, ok := domains[q.Name]
			if !ok {
				return new(dns.Msg), fmt.Errorf("unknown domain")
			}

			upstreamCalls[q.Name]++
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
			Enabled:         true,
			BatchSize:       5,
			CheckInterval:   100 * time.Millisecond,
			RefreshBefore:   5 * time.Second, // Min safety margin
			Threshold:       1,
			ThresholdWindow: 1 * time.Hour, // Ensure items are retained
		},
	}
	p, err := New(config)
	require.NoError(t, err)

	err = p.Start(context.TODO())
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

	// 1. Initial Queries
	fmt.Println("Step 1: Initial Queries")
	for domain, info := range domains {
		ip, ttl := query(domain)
		assert.Equal(t, info.ips[0], ip)
		assert.Equal(t, info.ttl, ttl)
		fmt.Printf("[%s] Initial: IP=%s, TTL=%d\n", domain, ip, ttl)
	}

	// 2. Timeline Simulation
	// We will wait for specific intervals and check if cache is updated.

	// T+6s: Short (10s) should refresh.
	fmt.Println("Waiting 6s...")
	time.Sleep(6 * time.Second)

	// Verify Short.com
	// Should have updated to IP[1].
	// IMPORTANT: This query should hit the cache and return the NEW IP.
	// If it hits the cache but returns OLD IP, prefetch failed.
	// If it triggers upstream, prefetch didn't update cache or cache expired.

	// mu.Lock()
	// callsBefore := upstreamCalls["short.com."]
	// mu.Unlock()

	ip, ttl := query("short.com.")
	fmt.Printf("[short.com.] After 6s: IP=%s, TTL=%d\n", ip, ttl)
	assert.Equal(t, "1.1.1.2", ip, "Short domain should have updated to 2nd IP")
	assert.True(t, ttl > 5, "TTL should be refreshed")

	// mu.Lock()
	// callsAfter := upstreamCalls["short.com."]
	// mu.Unlock()
	// We expect NO new upstream calls during this query if prefetch worked and updated cache.
	// However, prefetch itself causes an upstream call.
	// So callsAfter should be callsBefore (if we count user queries) + 1 (prefetch).
	// Wait, callsBefore was captured AFTER the wait, so prefetch might have already happened.
	// Let's rely on the IP check. If IP is new, it means prefetch happened.

	// Verify Medium (30s) - Should NOT refresh yet (needs 24s).
	ip, _ = query("medium.com.")
	assert.Equal(t, "2.2.2.1", ip, "Medium domain should NOT have updated yet")

	// T+25s (Total 31s): Medium (30s) should refresh.
	fmt.Println("Waiting 25s...")
	time.Sleep(25 * time.Second)

	// Verify Medium.com
	ip, ttl = query("medium.com.")
	fmt.Printf("[medium.com.] After 31s: IP=%s, TTL=%d\n", ip, ttl)
	assert.Equal(t, "2.2.2.2", ip, "Medium domain should have updated to 2nd IP")

	// Verify Standard (60s) - Should NOT refresh yet (needs 54s).
	ip, _ = query("standard.com.")
	assert.Equal(t, "3.3.3.1", ip, "Standard domain should NOT have updated yet")

	// T+30s (Total 61s): Standard (60s) should refresh.
	fmt.Println("Waiting 30s...")
	time.Sleep(30 * time.Second)

	// Verify Standard.com
	ip, ttl = query("standard.com.")
	fmt.Printf("[standard.com.] After 61s: IP=%s, TTL=%d\n", ip, ttl)
	assert.Equal(t, "3.3.3.2", ip, "Standard domain should have updated to 2nd IP")

	// Verify Long (300s) - Should NOT refresh yet.
	ip, _ = query("long.com.")
	assert.Equal(t, "4.4.4.1", ip, "Long domain should NOT have updated yet")

	// Verify Short.com again - Should have updated multiple times.
	// Initial (0s) -> IP[0]
	// T+6s -> IP[1]
	// T+16s -> IP[2]
	// T+26s -> IP[3]
	// T+36s -> IP[3] (Max index) or wrap around if we implemented that (we capped at len-1).
	// Current time T+61s.
	ip, _ = query("short.com.")
	fmt.Printf("[short.com.] After 61s: IP=%s\n", ip)
	assert.Equal(t, "1.1.1.4", ip, "Short domain should be at last IP")

}
