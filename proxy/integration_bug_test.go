package proxy

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCacheHitTriggersPrefetch reproduces the bug where cache hits don't trigger prefetch
func TestCacheHitTriggersPrefetch(t *testing.T) {
	// Mock upstream that returns a valid response
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			resp := new(dns.Msg)
			resp.SetReply(m)
			resp.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   m.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: net.IPv4(1, 2, 3, 4),
				},
			}
			return resp, nil
		},
	}

	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
		CacheEnabled:   true,
		CacheSizeBytes: 4096,
		Prefetch: &PrefetchConfig{
			Enabled:         true,
			Threshold:       2, // Require 2 hits
			ThresholdWindow: 1 * time.Minute,
			BatchSize:       10,
			CheckInterval:   100 * time.Millisecond,
			RefreshBefore:   5 * time.Second,
		},
	}

	p, err := New(config)
	require.NoError(t, err)

	// Start proxy (this starts prefetch manager too)
	err = p.Start(context.Background())
	require.NoError(t, err)
	defer p.Shutdown(context.Background())

	// 2. First Request (Cache Miss)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	d := &DNSContext{
		Req:  req,
		Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 12345),
	}
	err = p.Resolve(d)
	require.NoError(t, err)

	// Wait a bit for async processing in Set
	time.Sleep(100 * time.Millisecond)

	// Check Queue: Should be 0 because Threshold is 2, and we only have 1 hit.
	stats := p.GetPrefetchStats()
	assert.Equal(t, 0, stats.QueueLen, "Queue should be empty after 1st hit (Threshold=2)")

	// 3. Second Request (Cache Hit)
	// This should trigger prefetch if logic is correct.
	err = p.Resolve(d)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	stats = p.GetPrefetchStats()

	assert.Equal(t, 1, stats.QueueLen, "Queue should have 1 item after 2nd hit (Threshold=2)")
}

func TestOptimisticCachePrefetch(t *testing.T) {
	// Mock upstream
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			resp := new(dns.Msg)
			resp.SetReply(m)
			resp.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   m.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    1, // Very short TTL, expires immediately
					},
					A: net.IPv4(1, 2, 3, 4),
				},
			}
			return resp, nil
		},
	}

	config := &Config{
		UpstreamConfig:           &UpstreamConfig{Upstreams: []upstream.Upstream{mu}},
		UDPListenAddr:            []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
		CacheEnabled:             true,
		CacheSizeBytes:           4096,
		CacheOptimistic:          true, // Enable Optimistic
		CacheOptimisticAnswerTTL: 60 * time.Second,
		Prefetch: &PrefetchConfig{
			Enabled:         true,
			Threshold:       2,
			ThresholdWindow: 1 * time.Minute,
			BatchSize:       10,
			CheckInterval:   100 * time.Millisecond,
			RefreshBefore:   5 * time.Second,
		},
	}

	p, err := New(config)
	require.NoError(t, err)

	err = p.Start(context.Background())
	require.NoError(t, err)
	defer p.Shutdown(context.Background())

	req := new(dns.Msg)
	req.SetQuestion("optimistic.com.", dns.TypeA)

	d := &DNSContext{
		Req:  req,
		Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 12345),
	}

	// 1. First Request (Miss)
	err = p.Resolve(d)
	require.NoError(t, err)

	// Wait for TTL to expire (1s)
	time.Sleep(1100 * time.Millisecond)

	// 2. Second Request (Optimistic Hit)
	// Should return expired item AND trigger background refresh AND trigger prefetch check
	err = p.Resolve(d)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	stats := p.GetPrefetchStats()
	// Threshold=2.
	// 1st req: hits=1.
	// 2nd req: hits=2. Should add to queue.
	assert.Equal(t, 1, stats.QueueLen, "Optimistic hit should trigger prefetch")
}

func TestPrefetchWithCustomUpstream(t *testing.T) {
	// Default Upstream: Returns 1.1.1.1
	muDefault := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			resp := new(dns.Msg)
			resp.SetReply(m)
			resp.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(1, 1, 1, 1),
				},
			}
			return resp, nil
		},
	}

	// Custom Upstream: Returns 2.2.2.2
	muCustom := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			resp := new(dns.Msg)
			resp.SetReply(m)
			resp.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(2, 2, 2, 2),
				},
			}
			return resp, nil
		},
	}

	config := &Config{
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{muDefault}},
		UDPListenAddr:  []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}},
		CacheEnabled:   true,
		CacheSizeBytes: 4096,
		Prefetch: &PrefetchConfig{
			Enabled:         true,
			Threshold:       1, // Prefetch immediately
			ThresholdWindow: 1 * time.Minute,
			BatchSize:       10,
			CheckInterval:   10 * time.Second, // Long interval to keep in queue
			RefreshBefore:   5 * time.Second,
		},
	}

	p, err := New(config)
	require.NoError(t, err)

	err = p.Start(context.Background())
	require.NoError(t, err)
	defer p.Shutdown(context.Background())

	// Create Custom Upstream Config
	uc := &UpstreamConfig{Upstreams: []upstream.Upstream{muCustom}}
	customConfig := NewCustomUpstreamConfig(uc, true, 4096, false)

	req := new(dns.Msg)
	req.SetQuestion("custom.com.", dns.TypeA)

	d := &DNSContext{
		Req:                  req,
		Addr:                 netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 12345),
		CustomUpstreamConfig: customConfig,
	}

	// 1. Resolve with Custom Config (Miss)
	// Should get 2.2.2.2
	err = p.Resolve(d)
	require.NoError(t, err)
	require.NotNil(t, d.Res)
	require.Equal(t, net.IPv4(2, 2, 2, 2).String(), d.Res.Answer[0].(*dns.A).A.String())

	// And since Global Queue uses Default Upstream, the bug is confirmed.
}
