package mobile

import (
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
)

// Tests that our limited set of roots is enough for the most popular upstreams
func TestPopularUpstreams(t *testing.T) {
	upstreams := []struct {
		address string
	}{
		{
			address: "https://dns-family.adguard.com/dns-query",
		},
		{
			address: "tls://dns-family.adguard.com",
		},
		{
			address: "https://dns.adguard.com/dns-query",
		},
		{
			address: "tls://dns.adguard.com",
		},
		{
			address: "https://dns.google/dns-query",
		},
		{
			address: "tls://dns.google",
		},
		{
			address: "https://dns.cloudflare.com/dns-query",
		},
		{
			address: "tls://1.1.1.1",
		},
		{
			address: "https://dns9.quad9.net:443/dns-query",
		},
	}

	for _, test := range upstreams {
		t.Run(test.address, func(t *testing.T) {
			u, err := upstream.AddressToUpstream(test.address, upstream.Options{})
			if err != nil {
				t.Fatalf("Failed to generate upstream from address %s: %s", test.address, err)
			}

			checkUpstream(t, u, test.address)
		})
	}
}

func checkUpstream(t *testing.T, u upstream.Upstream, addr string) {
	t.Helper()

	req := createTestMessage()
	reply, err := u.Exchange(req)
	if err != nil {
		t.Fatalf("Couldn't talk to upstream %s: %s", addr, err)
	}
	assertResponse(t, reply)
}
