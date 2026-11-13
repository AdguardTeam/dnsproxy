package proxy_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is a common timeout for tests.
const testTimeout = 1 * time.Second

func TestProxy_LookupNetIP(t *testing.T) {
	t.Parallel()

	conf := &proxy.Config{
		Logger: testLogger,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(t)},
		},
	}

	p := mustNew(t, conf)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	addrs, err := p.LookupNetIP(ctx, "", dnsproxytest.Host)
	require.NoError(t, err)
	require.NotEmpty(t, addrs)

	wantAddr := netip.AddrFrom4([4]byte(dnsproxytest.IPv4.To4()))
	assert.Contains(t, addrs, wantAddr)
}
