package upstream

import (
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDnsOverTLS_CloseWait(t *testing.T) {
	testCases := []struct {
		name string
		test func(t *testing.T)
	}{{
		name: "connection_closed_after_use",
		test: testConnectionClosedAfterUse,
	}, {
		name: "connection_pool_doesnt_leak_on_error",
		test: testConnectionPoolDoesntLeakOnError,
	}, {
		name: "connection_pool_handles_timeout",
		test: testConnectionPoolHandlesTimeout,
	}, {
		name: "concurrent_access_doesnt_cause_close_wait",
		test: testConcurrentAccessDoesntCauseCloseWait,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, tc.test)
	}
}

func TestIsConnAlive(t *testing.T) {
	t.Run("alive_connection", func(t *testing.T) {
		srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
			require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(req)))
		})

		addr := (&url.URL{
			Scheme: "tls",
			Host:   srv.srv.Listener.Addr().String(),
		}).String()
		u, err := AddressToUpstream(addr, &Options{
			Logger:             testLogger,
			InsecureSkipVerify: true,
		})
		require.NoError(t, err)
		defer testutil.CleanupAndRequireSuccess(t, u.Close)

		p := testutil.RequireTypeAssert[*dnsOverTLS](t, u)

		// Create a connection by doing an exchange
		req := createTestMessage()
		reply, err := u.Exchange(req)
		require.NoError(t, err)
		requireResponse(t, req, reply)

		// Get the connection from pool
		dialHandler, err := p.getDialer()
		require.NoError(t, err)
		conn, err := p.conn(dialHandler)
		require.NoError(t, err)
		require.NotNil(t, conn)

		// Verify the connection is alive
		assert.True(t, isConnAlive(conn), "connection should be alive")

		// Put it back for cleanup
		p.putBack(conn)
	})

	t.Run("closed_tcp_connection", func(t *testing.T) {
		// Test with a simple TCP connection that's closed
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		conn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)

		// Close the listener and connection
		require.NoError(t, ln.Close())
		require.NoError(t, conn.Close())

		// Verify the closed connection is not alive
		assert.False(t, isConnAlive(conn), "closed TCP connection should not be alive")
	})
}

// testConnectionClosedAfterUse verifies that closed connections are properly
// removed from the pool and don't cause CLOSE_WAIT issues.
func testConnectionClosedAfterUse(t *testing.T) {
	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(req)))
	})

	addr := (&url.URL{
		Scheme: "tls",
		Host:   srv.srv.Listener.Addr().String(),
	}).String()
	u, err := AddressToUpstream(addr, &Options{
		Logger:             testLogger,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer testutil.CleanupAndRequireSuccess(t, u.Close)

	p := testutil.RequireTypeAssert[*dnsOverTLS](t, u)

	// First exchange to create a connection in the pool.
	req := createTestMessage()
	reply, err := u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)

	// Get the connection from pool using conn() to properly remove it.
	require.Len(t, p.conns, 1)
	dialHandler, err := p.getDialer()
	require.NoError(t, err)
	conn, err := p.conn(dialHandler)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Close the connection (simulating server-side close or timeout).
	require.NoError(t, conn.Close())

	// Put the closed connection back into pool.
	p.putBack(conn)
	require.Len(t, p.conns, 1)

	// Next exchange should detect the closed connection and create a new one.
	req = createTestMessage()
	reply, err = u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)

	// The pool should still have one valid connection.
	require.Len(t, p.conns, 1)
	assert.NotSame(t, conn, p.conns[0])

	// Verify the new connection is valid.
	newConn := p.conns[0]
	err = newConn.SetDeadline(time.Now().Add(time.Second))
	assert.NoError(t, err, "new connection should be valid")
}

// testConnectionPoolDoesntLeakOnError verifies that errors during exchange
// don't cause connection leaks in CLOSE_WAIT state.
func testConnectionPoolDoesntLeakOnError(t *testing.T) {
	requestCount := 0
	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		requestCount++
		// Fail every other request to simulate errors.
		if requestCount%2 == 0 {
			// Close connection without response to cause error.
			return
		}
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(req)))
	})

	addr := (&url.URL{
		Scheme: "tls",
		Host:   srv.srv.Listener.Addr().String(),
	}).String()
	u, err := AddressToUpstream(addr, &Options{
		Logger:             testLogger,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer testutil.CleanupAndRequireSuccess(t, u.Close)

	p := testutil.RequireTypeAssert[*dnsOverTLS](t, u)

	// First successful exchange to populate pool.
	req := createTestMessage()
	reply, err := u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)
	require.Len(t, p.conns, 1)

	// This exchange will fail (server closes connection without response)
	// but shouldn't leak connections.
	_, _ = u.Exchange(createTestMessage())

	// After failed exchange, the connection should be closed and removed.
	// Pool may be empty or have a new valid connection.
	for _, conn := range p.conns {
		err = conn.SetDeadline(time.Now().Add(time.Second))
		assert.NoError(t, err, "connections in pool should be valid")
	}
}

// testConnectionPoolHandlesTimeout verifies that connection timeouts are
// properly handled and don't leave connections in CLOSE_WAIT.
func testConnectionPoolHandlesTimeout(t *testing.T) {
	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(req)))
	})

	addr := (&url.URL{
		Scheme: "tls",
		Host:   srv.srv.Listener.Addr().String(),
	}).String()
	u, err := AddressToUpstream(addr, &Options{
		Logger:             testLogger,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer testutil.CleanupAndRequireSuccess(t, u.Close)

	p := testutil.RequireTypeAssert[*dnsOverTLS](t, u)

	// First exchange to create a connection.
	req := createTestMessage()
	reply, err := u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)
	require.Len(t, p.conns, 1)

	// Get the connection from pool using conn() to properly remove it.
	dialHandler, err := p.getDialer()
	require.NoError(t, err)
	conn, err := p.conn(dialHandler)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Set deadline to past to simulate timeout.
	err = conn.SetDeadline(time.Now().Add(-time.Hour))
	require.NoError(t, err)

	// Put back with expired deadline.
	p.putBack(conn)
	require.Len(t, p.conns, 1)

	// Verify that a subsequent exchange still works - the connection pool
	// should either detect the expired deadline or the exchange should
	// handle it gracefully.
	req = createTestMessage()
	reply, err = u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)

	// The pool should have a valid connection after the exchange.
	require.NotEmpty(t, p.conns)
	for _, c := range p.conns {
		err = c.SetDeadline(time.Now().Add(time.Second))
		assert.NoError(t, err, "connection in pool should be valid")
	}
}

// testConcurrentAccessDoesntCauseCloseWait verifies that concurrent access
// to the connection pool doesn't cause race conditions or CLOSE_WAIT issues.
func testConcurrentAccessDoesntCauseCloseWait(t *testing.T) {
	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(req)))
	})

	addr := (&url.URL{
		Scheme: "tls",
		Host:   srv.srv.Listener.Addr().String(),
	}).String()
	u, err := AddressToUpstream(addr, &Options{
		Logger:             testLogger,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer testutil.CleanupAndRequireSuccess(t, u.Close)

	p := testutil.RequireTypeAssert[*dnsOverTLS](t, u)

	const numGoroutines = 10
	const numRequests = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numRequests; j++ {
				req := createTestMessage()
				reply, err := u.Exchange(req)
				if err == nil {
					requireResponse(testutil.PanicT{}, req, reply)
				}

				// Small delay to allow connection reuse patterns.
				time.Sleep(time.Millisecond * 10)
			}
		}(i)
	}

	wg.Wait()

	// Verify all connections in pool are valid after concurrent access.
	p.connsMu.Lock()
	defer p.connsMu.Unlock()

	for i, conn := range p.conns {
		err = conn.SetDeadline(time.Now().Add(time.Second))
		assert.NoError(t, err, "connection %d in pool should be valid after concurrent access", i)
	}
}
