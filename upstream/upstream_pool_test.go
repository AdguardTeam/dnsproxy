package upstream

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
)

// TODO(ameshkov): make it not depend on external servers.
func TestTLSPoolReconnect(t *testing.T) {
	var lastState tls.ConnectionState
	u, err := AddressToUpstream(
		"tls://one.one.one.one",
		&Options{
			Bootstrap: []string{"8.8.8.8:53"},
			Timeout:   timeout,
			VerifyConnection: func(state tls.ConnectionState) error {
				lastState = state
				return nil
			},
		},
	)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// Send the first test message.
	req := createTestMessage()
	reply, err := u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)

	// Now let's close the pooled connection and return it back to the pool.
	p := u.(*dnsOverTLS)
	conn, _ := p.pool.Get()
	conn.Close()
	p.pool.Put(conn)

	// Send the second test message.
	req = createTestMessage()
	reply, err = u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)

	// Now assert that the number of connections in the pool is not changed.
	require.Len(t, p.pool.conns, 1)

	// Check that the session was resumed on the last attempt.
	require.True(t, lastState.DidResume)
}

// TODO(ameshkov): make it not depend on external servers.
func TestTLSPoolDeadLine(t *testing.T) {
	u, err := AddressToUpstream(
		"tls://one.one.one.one",
		&Options{
			Bootstrap: []string{"8.8.8.8:53"},
			Timeout:   timeout,
		},
	)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// Send the first test message.
	req := createTestMessage()
	response, err := u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, response)

	p := u.(*dnsOverTLS)

	// Now let's get connection from the pool and use it.
	conn, err := p.pool.Get()
	require.NoError(t, err)

	response, err = p.exchangeConn(conn, req)
	require.NoError(t, err)
	requireResponse(t, req, response)

	// Update connection's deadLine and put it back to the pool.
	err = conn.SetDeadline(time.Now().Add(10 * time.Hour))
	require.NoError(t, err)
	p.pool.Put(conn)

	// Get connection from the pool and reuse it.
	conn, err = p.pool.Get()
	require.NoError(t, err)

	response, err = p.exchangeConn(conn, req)
	require.NoError(t, err)
	requireResponse(t, req, response)

	// Set connection's deadLine to the past and try to reuse it.
	err = conn.SetDeadline(time.Now().Add(-10 * time.Hour))
	require.NoError(t, err)

	// Connection with expired deadLine can't be used.
	response, err = p.exchangeConn(conn, req)
	require.Error(t, err)
}
