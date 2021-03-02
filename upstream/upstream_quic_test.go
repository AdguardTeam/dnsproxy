package upstream

import (
	"testing"

	"github.com/lucas-clemente/quic-go"
	"github.com/stretchr/testify/assert"
)

func TestUpstreamDOQ(t *testing.T) {
	// Create a DNS-over-QUIC upstream
	address := "quic://dns.adguard.com:784"
	u, err := AddressToUpstream(address, Options{InsecureSkipVerify: true})
	assert.Nil(t, err)

	uq := u.(*dnsOverQUIC)
	var sess quic.Session

	// Test that it responds properly
	for i := 0; i < 10; i++ {
		checkUpstream(t, u, address)

		if sess == nil {
			sess = uq.session
		} else {
			// This way we test that the session is properly reused
			assert.True(t, sess == uq.session)
		}
	}
}
