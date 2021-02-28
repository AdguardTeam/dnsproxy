package proxy

import (
	"github.com/AdguardTeam/dnsproxy/upstream"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetUpstreamsForDomain(t *testing.T) {
	upstreams := []string{"[/google.com/local/]4.3.2.1", "[/www.google.com//]1.2.3.4", "[/maps.google.com/]#", "[/www.google.com/]tls://1.1.1.1"}

	config, err := ParseUpstreamsConfig(upstreams, upstream.Options{InsecureSkipVerify: false, Bootstrap: []string{}, Timeout: 1 * time.Second})
	if err != nil {
		t.Fatalf("Error while upstream config parsing: %s", err)
	}

	assertUpstreamsForDomain(t, config, 2, "www.google.com.", []string{"1.2.3.4:53", "tls://1.1.1.1:853"})
	assertUpstreamsForDomain(t, config, 1, "www2.google.com.", []string{"4.3.2.1:53"})
	assertUpstreamsForDomain(t, config, 1, "internal.local.", []string{"4.3.2.1:53"})
	assertUpstreamsForDomain(t, config, 1, "google.", []string{"1.2.3.4:53"})
	assertUpstreamsForDomain(t, config, 0, "maps.google.com.", []string{})
}

func TestGetUpstreamsForDomainWithoutDuplicates(t *testing.T) {
	upstreams := []string{"[/example.com/]1.1.1.1", "[/example.org/]1.1.1.1"}
	config, err := ParseUpstreamsConfig(upstreams, upstream.Options{InsecureSkipVerify: false, Bootstrap: []string{}, Timeout: 1 * time.Second})
	assert.Nil(t, err)
	assert.Len(t, config.Upstreams, 0)
	assert.Len(t, config.DomainReservedUpstreams, 2)

	u1 := config.DomainReservedUpstreams["example.com."][0]
	u2 := config.DomainReservedUpstreams["example.org."][0]

	// Check that the very same Upstream instance is used for both domains
	assert.True(t, u1 == u2)
}

// assertUpstreamsForDomain checks count and addresses of the specified domain upstreams
func assertUpstreamsForDomain(t *testing.T, config UpstreamConfig, count int, domain string, address []string) {
	u := config.getUpstreamsForDomain(domain)
	if len(u) != count {
		t.Fatalf("wrong count of reserved upstream for %s: expected: %d, actual: %d", domain, count, len(u))
	}

	if len(address) != len(u) {
		t.Fatalf("wrong assertion сondition")
	}

	for i, up := range u {
		if up.Address() != address[i] {
			t.Fatalf("wrong upstream was reserved for %s: %s", domain, up.Address())
		}
	}
}
