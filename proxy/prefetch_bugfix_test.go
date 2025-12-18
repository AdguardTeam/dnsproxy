package proxy

import (
	"context"
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

func TestPrefetch_UpdatesCache(t *testing.T) {
	// 1. Setup Mock Upstream
	// It returns 1.2.3.4 initially, then 5.6.7.8 after first call
	var callCount int
	var muLock sync.Mutex

	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			muLock.Lock()
			defer muLock.Unlock()

			callCount++
			ip := net.IP{1, 2, 3, 4}
			if callCount > 1 {
				ip = net.IP{5, 6, 7, 8}
			}

			resp := new(dns.Msg)
			resp.SetReply(m)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    2, // Short TTL to allow quick expiration/prefetch
				},
				A: ip,
			})
			return resp, nil
		},
	}

	// 2. Configure Proxy
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
			BatchSize:     1,
			CheckInterval: 100 * time.Millisecond,
			RefreshBefore: 10 * time.Second, // Force refresh if TTL < 10s (our TTL is 2s)
			Threshold:     1,
		},
	}
	p, err := New(config)
	require.NoError(t, err)

	// Start Proxy (needed for prefetch manager)
	err = p.Start(context.TODO())
	require.NoError(t, err)
	defer p.Shutdown(context.TODO())

	// 3. First Query -> Cache Miss -> Upstream Call 1 (IP: 1.2.3.4)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	dctx := p.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))

	err = p.Resolve(dctx)
	require.NoError(t, err)

	// Verify response is 1.2.3.4
	require.NotNil(t, dctx.Res)
	require.Equal(t, "1.2.3.4", dctx.Res.Answer[0].(*dns.A).A.String())

	// 4. Wait for Prefetch to Trigger
	// Since Threshold is 1, the first hit (above) should trigger prefetch.
	// The item is added to queue. The background worker picks it up.
	// Since TTL is 2s and RefreshBefore is 10s, it should be processed immediately.

	// Wait enough time for prefetch to happen
	// TTL is 2s. Effective RefreshBefore is 1s (half TTL).
	// So prefetch triggers at T+1s.
	time.Sleep(1500 * time.Millisecond)

	// 5. Verify Cache Updated
	// If prefetch worked correctly, it should have called upstream again (callCount=2)
	// and updated the cache with 5.6.7.8.

	// Check call count
	muLock.Lock()
	count := callCount
	muLock.Unlock()
	assert.GreaterOrEqual(t, count, 2, "Upstream should have been called at least twice (1 query + 1 prefetch)")

	// Check Cache Content
	// We do a new query. It should hit cache.
	dctx2 := p.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	err = p.Resolve(dctx2)
	require.NoError(t, err)

	require.NotNil(t, dctx2.Res)
	// THIS ASSERTION WILL FAIL IF THE BUG EXISTS
	assert.Equal(t, "5.6.7.8", dctx2.Res.Answer[0].(*dns.A).A.String(), "Cache should have been updated to new IP")
}
