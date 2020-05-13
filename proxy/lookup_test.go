package proxy

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AdguardTeam/dnsproxy/upstream"
)

func TestLookupIPAddr(t *testing.T) {
	// Create a simple proxy
	p := Proxy{}
	upstreams := make([]upstream.Upstream, 0)
	// Use AdGuard DNS here
	opts := upstream.Options{Timeout: defaultTimeout}
	dnsUpstream, err := upstream.AddressToUpstream("176.103.130.130", opts)
	if err != nil {
		t.Fatalf("cannot prepare the upstream: %s", err)
	}
	p.UpstreamConfig = &UpstreamConfig{}
	p.UpstreamConfig.Upstreams = append(upstreams, dnsUpstream)

	// Init the proxy
	p.Init()

	// Now let's try doing some lookups
	addrs, err := p.LookupIPAddr("dns.adguard.com")
	assert.Nil(t, err)
	assert.Equal(t, 4, len(addrs))

	assertContainsIP(t, addrs, "176.103.130.130")
	assertContainsIP(t, addrs, "176.103.130.131")
	assertContainsIP(t, addrs, "2a00:5a60::ad1:ff")
	assertContainsIP(t, addrs, "2a00:5a60::ad2:ff")

	addrs, err = p.LookupIPAddr("dns.google")
	assert.Nil(t, err)
	assert.True(t, len(addrs) == 2 || len(addrs) == 4)
	assertContainsIP(t, addrs, "8.8.8.8")
	assertContainsIP(t, addrs, "8.8.4.4")
	if len(addrs) == 4 {
		assertContainsIP(t, addrs, "2001:4860:4860::8888")
		assertContainsIP(t, addrs, "2001:4860:4860::8844")
	}
}

func assertContainsIP(t *testing.T, addrs []net.IPAddr, ip string) {
	for _, addr := range addrs {
		if addr.String() == ip {
			return
		}
	}

	t.Fatalf("%s not found in %v", ip, addrs)
}
