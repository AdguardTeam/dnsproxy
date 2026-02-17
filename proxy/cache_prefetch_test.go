package proxy

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache_PrefetchIntegration(t *testing.T) {
	// Create Proxy with mock upstream
	mu := &mockUpstream{
		exchangeFunc: func(m *dns.Msg) (*dns.Msg, error) {
			resp := new(dns.Msg)
			resp.SetReply(m)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IP{1, 2, 3, 4},
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
			BatchSize:     10,
			CheckInterval: 10 * time.Second,
		},
	}
	p, err := New(config)
	require.NoError(t, err)

	// Verify prefetch manager is initialized
	require.NotNil(t, p.cache.prefetchManager)
	require.True(t, p.cache.prefetchEnabled)

	// Perform a query to populate cache
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	dctx := p.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))

	err = p.Resolve(dctx)
	require.NoError(t, err)

	// Verify item is added to prefetch queue
	assert.Equal(t, 1, p.cache.prefetchManager.queue.Len())

	// Verify cache get returns item even if we simulate expiration
	c := p.cache
	key := msgToKey(req)
	data := c.items.Get(key)
	require.NotNil(t, data)

	// Unpack it
	ci, expired := c.unpackItem(data, req)
	assert.NotNil(t, ci)
	assert.False(t, expired) // Should be false because it's fresh

	// Now, let's manually modify the expiration time in the packed data to make it expired
	// The packed data format: [expiration(4)][len(2)][msg...]
	// We set expiration to 1 second ago.
	expiredTime := uint32(time.Now().Unix()) - 1
	binary.BigEndian.PutUint32(data, expiredTime)

	// Now unpack again
	ci, expired = c.unpackItem(data, req)
	assert.NotNil(t, ci)
	assert.False(t, expired) // Should STILL be false because prefetchEnabled is true!

	// Disable prefetch and check again
	c.prefetchEnabled = false
	ci, expired = c.unpackItem(data, req)
	// If optimistic is false (default), it returns nil, expired=true
	assert.Nil(t, ci)
	assert.True(t, expired)
}
