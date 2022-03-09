package upstream

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpstreamDOH3(t *testing.T) {
	// Create a DNS-over-HTTP3 upstream
	address := "h3://dns.google/dns-query"
	u, err := AddressToUpstream(address, &Options{InsecureSkipVerify: true})
	assert.Nil(t, err)

	uq := u.(*dnsOverHTTP3)
	var client *http.Client

	// Test that it responds properly
	for i := 0; i < 10; i++ {
		checkUpstream(t, u, address)

		if client == nil {
			client = uq.client
		} else {
			// This way we test that the client is properly reused
			assert.True(t, client == uq.client)
		}
	}
}
