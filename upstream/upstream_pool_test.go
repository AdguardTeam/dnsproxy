package upstream

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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

	// Send the first test message.
	req := createTestMessage()
	reply, err := u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)

	// Now let's close the pooled connection and return it back to the pool.
	p := u.(*dnsOverTLS)
	connAndStore, _ := p.pool.Get()
	connAndStore.conn.Close()
	p.pool.Put(connAndStore)

	// Send the second test message.
	req = createTestMessage()
	reply, err = u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)

	// Now assert that the number of connections in the pool is not changed
	require.Len(t, p.pool.conns, 1)

	// Check that the session was resumed on the last attempt.
	require.True(t, lastState.DidResume)
}

func TestTLSPoolDeadLine(t *testing.T) {
	// Create TLS upstream
	u, err := AddressToUpstream(
		"tls://one.one.one.one",
		&Options{
			Bootstrap: []string{"8.8.8.8:53"},
			Timeout:   timeout,
		},
	)
	if err != nil {
		t.Fatalf("cannot create upstream: %s", err)
	}

	// Send the first test message
	req := createTestMessage()
	response, err := u.Exchange(req)
	if err != nil {
		t.Fatalf("first DNS message failed: %s", err)
	}
	requireResponse(t, req, response)

	p := u.(*dnsOverTLS)

	// Now let's get connection from the pool and use it
	connAndStore, err := p.pool.Get()
	if err != nil {
		t.Fatalf("couldn't get connection from pool: %s", err)
	}
	response, err = p.exchangeConn(connAndStore, req)
	if err != nil {
		t.Fatalf("first DNS message failed: %s", err)
	}
	requireResponse(t, req, response)

	// Update connection's deadLine and put it back to the pool
	err = connAndStore.conn.SetDeadline(time.Now().Add(10 * time.Hour))
	if err != nil {
		t.Fatalf("can't set new deadLine for connection. Looks like it's already closed: %s", err)
	}
	p.pool.Put(connAndStore)

	// Get connection from the pool and reuse it
	connAndStore, err = p.pool.Get()
	if err != nil {
		t.Fatalf("couldn't get connection from pool: %s", err)
	}
	response, err = p.exchangeConn(connAndStore, req)
	if err != nil {
		t.Fatalf("first DNS message failed: %s", err)
	}
	requireResponse(t, req, response)

	// Set connection's deadLine to the past and try to reuse it
	err = connAndStore.conn.SetDeadline(time.Now().Add(-10 * time.Hour))
	if err != nil {
		t.Fatalf("can't set new deadLine for connection. Looks like it's already closed: %s", err)
	}

	// Connection with expired deadLine can't be used
	response, err = p.exchangeConn(connAndStore, req)
	if err == nil {
		t.Fatalf("this connection should be already closed, got response %s", response)
	}
}
