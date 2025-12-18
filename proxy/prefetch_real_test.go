package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestPrefetch_RealWorld_Google(t *testing.T) {
	// This test runs for 5 minutes and queries google.com repeatedly.
	// It uses a real upstream (8.8.8.8) to verify that prefetch works with real DNS.

	// Use 8.8.8.8 as upstream
	u, err := upstream.AddressToUpstream("8.8.8.8:53", &upstream.Options{
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)

	config := &Config{
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{u},
		},
		UDPListenAddr: []*net.UDPAddr{
			{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		},
		CacheEnabled:          true,
		CacheSizeBytes:        1024 * 1024, // 1MB
		CacheOptimisticMaxAge: 1 * time.Hour,
		Prefetch: &PrefetchConfig{
			Enabled:       true,
			BatchSize:     5,
			CheckInterval: 1 * time.Second,
			RefreshBefore: 60 * time.Second,
			// Threshold 1 means every access triggers prefetch check
			Threshold: 1,
		},
	}
	p, err := New(config)
	require.NoError(t, err)

	err = p.Start(context.TODO())
	require.NoError(t, err)
	defer p.Shutdown(context.TODO())

	domain := "google.com."
	duration := 5 * time.Minute
	ticker := time.NewTicker(5 * time.Second) // Query every 5 seconds
	defer ticker.Stop()

	timeout := time.After(duration)

	fmt.Printf("Starting 5-minute stability test for %s...\n", domain)

	req := new(dns.Msg)
	req.SetQuestion(domain, dns.TypeA)

	var queries int

	for {
		select {
		case <-timeout:
			fmt.Println("\nTest finished successfully.")
			return
		case <-ticker.C:
			queries++
			dctx := p.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
			err = p.Resolve(dctx)
			if err != nil {
				t.Errorf("Query failed: %v", err)
				continue
			}

			if dctx.Res == nil || len(dctx.Res.Answer) == 0 {
				t.Errorf("No answer for %s", domain)
				continue
			}

			answer := dctx.Res.Answer[0]
			ttl := answer.Header().Ttl
			ip := answer.(*dns.A).A.String()

			fmt.Printf("[%s] Query #%d: IP=%s, TTL=%d\n", time.Now().Format("15:04:05"), queries, ip, ttl)

			// Basic verification: TTL should be reasonable.
			// If prefetch is working, TTL should be refreshed periodically.
			// It shouldn't just drop to 0.
			if ttl == 0 {
				t.Errorf("TTL dropped to 0!")
			}
		}
	}
}
