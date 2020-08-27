package upstream

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpstreamDOQ(t *testing.T) {
	// Create a DNS-over-QUIC upstream
	address := "quic://dns.adguard.com"
	u, err := AddressToUpstream(address, Options{InsecureSkipVerify: true})
	assert.Nil(t, err)

	// Test that it responds properly
	for i := 0; i < 10; i++ {
		checkUpstream(t, u, address)
	}
}
