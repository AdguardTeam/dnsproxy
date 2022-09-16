package upstream

import (
	"crypto/tls"
	"testing"

	"github.com/lucas-clemente/quic-go"
	"github.com/stretchr/testify/require"
)

func TestUpstreamDoQ(t *testing.T) {
	// Create a DNS-over-QUIC upstream
	address := "quic://dns.adguard.com"
	var lastState tls.ConnectionState
	u, err := AddressToUpstream(
		address,
		&Options{
			VerifyConnection: func(state tls.ConnectionState) error {
				lastState = state
				return nil
			},
		},
	)
	require.NoError(t, err)

	uq := u.(*dnsOverQUIC)
	var conn quic.Connection

	// Test that it responds properly
	for i := 0; i < 10; i++ {
		checkUpstream(t, u, address)

		if conn == nil {
			conn = uq.conn
		} else {
			// This way we test that the conn is properly reused.
			require.Equal(t, conn, uq.conn)
		}
	}

	// Close the connection (make sure that we re-establish the connection).
	_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "")

	// Try to establish it again.
	checkUpstream(t, u, address)

	// Make sure that the session has been resumed.
	require.True(t, lastState.DidResume)
}
