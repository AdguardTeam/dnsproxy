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

func TestPrefetch_Stability(t *testing.T) {
	// This test simulates multiple refresh cycles to ensure:
	// 1. Prefetch continues to work over time.
	// 2. Cache is updated with changing upstream IPs.
	// 3. No goroutine leaks (implicitly, by test finishing).

	var callCount int
	var muLock sync.Mutex

	// Mock Upstream: Returns a new IP every time it's called
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			muLock.Lock()
			defer muLock.Unlock()

			callCount++
			// Generate IP based on call count: 1.0.0.1, 1.0.0.2, ...
			ip := net.IPv4(1, 0, 0, byte(callCount))

			resp := new(dns.Msg)
			resp.SetReply(m)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    2, // Short TTL
				},
				A: ip,
			})
			return resp, nil
		},
	}

	config := &Config{
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{mu},
		},
		UDPListenAddr: []*net.UDPAddr{
			{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		},
		CacheEnabled:          true,
		CacheSizeBytes:        1024,
		CacheOptimisticMaxAge: 1 * time.Hour,
		Prefetch: &PrefetchConfig{
			Enabled:       true,
			BatchSize:     5,
			CheckInterval: 100 * time.Millisecond,
			RefreshBefore: 10 * time.Second, // Always refresh for 2s TTL
			Threshold:     1,
		},
	}
	p, err := New(config)
	require.NoError(t, err)

	err = p.Start(context.TODO())
	require.NoError(t, err)
	defer p.Shutdown(context.TODO())

	req := new(dns.Msg)
	req.SetQuestion("stability.example.com.", dns.TypeA)

	// Cycle 1: Initial Query
	dctx := p.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	err = p.Resolve(dctx)
	require.NoError(t, err)
	require.Equal(t, "1.0.0.1", dctx.Res.Answer[0].(*dns.A).A.String())

	// Wait for Prefetch 1 (T+1s)
	// Upstream should be called again -> 1.0.0.2
	time.Sleep(1500 * time.Millisecond)

	// Verify Cache has 1.0.0.2
	dctx2 := p.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	err = p.Resolve(dctx2)
	require.NoError(t, err)
	require.Equal(t, "1.0.0.2", dctx2.Res.Answer[0].(*dns.A).A.String())

	// Wait for Prefetch 2 (T+1s from last refresh)
	// Since we accessed it again, it should be kept in queue (if retention works)
	// OR we might need to trigger it again if it was dropped.
	// With Threshold=1, accessing it again should trigger/keep it.

	// Wait another cycle
	time.Sleep(1500 * time.Millisecond)

	// Verify Cache has 1.0.0.3
	dctx3 := p.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	err = p.Resolve(dctx3)
	require.NoError(t, err)

	// Note: It might be 1.0.0.3 or higher depending on how many times prefetch triggered.
	// But it should definitely NOT be 1.0.0.2 anymore if prefetch is working continuously.
	currentIP := dctx3.Res.Answer[0].(*dns.A).A.String()
	fmt.Printf("Current IP: %s\n", currentIP)
	assert.NotEqual(t, "1.0.0.2", currentIP, "Cache should have updated again")
	assert.NotEqual(t, "1.0.0.1", currentIP)

	muLock.Lock()
	finalCount := callCount
	muLock.Unlock()
	fmt.Printf("Total Upstream Calls: %d\n", finalCount)
	assert.GreaterOrEqual(t, finalCount, 3)
}
