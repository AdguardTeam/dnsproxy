package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupIPAddr(t *testing.T) {
	// Create a simple proxy
	p := Proxy{}
	upstreams := make([]upstream.Upstream, 0)
	// Use AdGuard DNS here

	dnsUpstream, err := upstream.AddressToUpstream("94.140.14.14", &upstream.Options{
		Timeout: defaultTimeout,
	})
	require.NoError(t, err)

	p.UpstreamConfig = &UpstreamConfig{}
	p.UpstreamConfig.Upstreams = append(upstreams, dnsUpstream)

	// Init the proxy
	err = p.Init()
	require.NoError(t, err)

	// Now let's try doing some lookups
	addrs, err := p.LookupIPAddr("dns.google")
	require.NoError(t, err)
	require.NotEmpty(t, addrs)

	assert.Contains(t, addrs, net.IPAddr{IP: net.IP{8, 8, 8, 8}})
	assert.Contains(t, addrs, net.IPAddr{IP: net.IP{8, 8, 4, 4}})
	if len(addrs) > 2 {
		assert.Contains(t, addrs, net.IPAddr{IP: net.ParseIP("2001:4860:4860::8888")})
		assert.Contains(t, addrs, net.IPAddr{IP: net.ParseIP("2001:4860:4860::8844")})
	}
}
