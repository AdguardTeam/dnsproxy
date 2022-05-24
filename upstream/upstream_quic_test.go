package upstream

import (
	"testing"

	"github.com/lucas-clemente/quic-go"
	"github.com/stretchr/testify/require"
)

func TestUpstreamDOQ(t *testing.T) {
	// Create a DNS-over-QUIC upstream
	address := "quic://dns.adguard.com"
	u, err := AddressToUpstream(address, &Options{InsecureSkipVerify: true})
	require.NoError(t, err)

	uq := u.(*dnsOverQUIC)
	var conn quic.Connection

	// Test that it responds properly
	for i := 0; i < 10; i++ {
		checkUpstream(t, u, address)

		if conn == nil {
			conn = uq.conn
		} else {
			// This way we test that the conn is properly reused
			require.Equal(t, conn, uq.conn)
		}
	}
}
