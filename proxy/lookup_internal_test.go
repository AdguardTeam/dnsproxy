package proxy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is a common timeout for tests.
const testTimeout = time.Second

func TestLookupNetIP(t *testing.T) {
	conf := &Config{
		Logger:         testLogger,
		UpstreamConfig: newTestUpstreamConfig(t, newTestUpstream(t)),
	}

	p, err := New(conf)
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	addrs, err := p.LookupNetIP(ctx, "", dnsproxytest.Host)
	require.NoError(t, err)
	require.NotEmpty(t, addrs)

	assert.Contains(t, addrs, netip.MustParseAddr("192.0.2.1"))
}
