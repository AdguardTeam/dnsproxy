package proxy

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheStats_changed(t *testing.T) {
	testCases := []struct {
		name string
		prev cacheStats
		cur  cacheStats
		want bool
	}{{
		name: "empty",
		prev: cacheStats{},
		cur:  cacheStats{},
		want: false,
	}, {
		name: "from_zero",
		prev: cacheStats{},
		cur:  cacheStats{entries: 1, bytes: 100},
		want: true,
	}, {
		name: "small_growth",
		prev: cacheStats{entries: 1000, bytes: 100_000},
		cur:  cacheStats{entries: 1049, bytes: 104_999},
		want: false,
	}, {
		name: "entries_grew",
		prev: cacheStats{entries: 1000, bytes: 100_000},
		cur:  cacheStats{entries: 1050, bytes: 100_000},
		want: true,
	}, {
		name: "bytes_shrank",
		prev: cacheStats{entries: 1000, bytes: 100_000},
		cur:  cacheStats{entries: 1000, bytes: 95_000},
		want: true,
	}, {
		name: "subnet_grew",
		prev: cacheStats{entries: 1000, bytes: 100_000, subnetEntries: 20, subnetBytes: 2000},
		cur:  cacheStats{entries: 1000, bytes: 100_000, subnetEntries: 21, subnetBytes: 2100},
		want: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.cur.changed(tc.prev))
		})
	}
}

func TestCache_stats(t *testing.T) {
	c := newTestCache(t, &cacheConfig{withECS: true})

	assert.Equal(t, cacheStats{}, c.stats())

	for _, host := range []string{"a.example.", "b.example."} {
		req := (&dns.Msg{}).SetQuestion(host, dns.TypeA)
		resp := (&dns.Msg{
			Response: true,
			Answer:   []dns.RR{dnsproxytest.NewRR(t, host, dns.TypeA, 60, net.IP{192, 0, 2, 1})},
		}).SetQuestion(host, dns.TypeA)

		c.set(req, resp, upstreamWithAddr, testLogger)
	}

	s := c.stats()
	assert.Equal(t, 2, s.entries)
	assert.Positive(t, s.bytes)
	assert.Zero(t, s.subnetEntries)
	assert.Zero(t, s.subnetBytes)

	c.clearItems()
	assert.Equal(t, cacheStats{}, c.stats())
}

// syncBuffer is a [bytes.Buffer] that is safe for concurrent use.
type syncBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

// Write implements the [io.Writer] interface for *syncBuffer.
func (b *syncBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

// String returns the buffer's contents.
func (b *syncBuffer) String() (s string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func TestProxy_logCacheStats(t *testing.T) {
	out := &syncBuffer{}
	p := mustNew(t, &Config{
		Logger:        slog.New(slog.NewTextHandler(out, nil)),
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(t)},
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		CacheEnabled:   true,
		CacheSizeBytes: 4096,
	})

	servicetest.RequireRun(t, p, dnsproxytest.Timeout)

	require.Eventually(t, func() (ok bool) {
		return strings.Contains(out.String(), `msg="cache stats" entries=0 bytes=0 max_bytes=4096`)
	}, dnsproxytest.Timeout, dnsproxytest.Timeout/100)
}
