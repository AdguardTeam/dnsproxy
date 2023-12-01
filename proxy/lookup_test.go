package proxy

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupNetIP(t *testing.T) {
	// Use AdGuard DNS here.
	dnsUpstream, err := upstream.AddressToUpstream("94.140.14.14", &upstream.Options{
		Timeout: defaultTimeout,
	})
	require.NoError(t, err)

	p := Proxy{
		Config: Config{
			UpstreamConfig: &UpstreamConfig{
				Upstreams: []upstream.Upstream{dnsUpstream},
			},
		},
	}

	err = p.Init()
	require.NoError(t, err)

	// Now let's try doing some lookups.
	addrs, err := p.LookupNetIP(context.Background(), "", "dns.google")
	require.NoError(t, err)
	require.NotEmpty(t, addrs)

	assert.Contains(t, addrs, netip.MustParseAddr("8.8.8.8"))
	assert.Contains(t, addrs, netip.MustParseAddr("8.8.4.4"))
	if len(addrs) > 2 {
		assert.Contains(t, addrs, netip.MustParseAddr("2001:4860:4860::8888"))
		assert.Contains(t, addrs, netip.MustParseAddr("2001:4860:4860::8844"))
	}
}
