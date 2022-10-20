package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestUpstream_dnsOverTLS(t *testing.T) {
	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := respondToTestMessage(req)

		err := w.WriteMsg(resp)

		pt := testutil.PanicT{}
		require.NoError(pt, err)
	})
	testutil.CleanupAndRequireSuccess(t, srv.Close)

	// Create a DoT upstream that we'll be testing.
	addr := fmt.Sprintf("tls://127.0.0.1:%d", srv.port)
	u, err := AddressToUpstream(addr, &Options{InsecureSkipVerify: true})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// Test that it responds properly.
	for i := 0; i < 10; i++ {
		checkUpstream(t, u, addr)
	}
}

func TestUpstream_dnsOverTLS_race(t *testing.T) {
	const count = 10

	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := respondToTestMessage(req)

		err := w.WriteMsg(resp)

		pt := testutil.PanicT{}
		require.NoError(pt, err)
	})
	testutil.CleanupAndRequireSuccess(t, srv.Close)

	// Creating a DoT upstream that we will be testing.
	addr := fmt.Sprintf("tls://127.0.0.1:%d", srv.port)
	u, err := AddressToUpstream(addr, &Options{InsecureSkipVerify: true})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// Use this upstream from multiple goroutines in parallel.
	wg := sync.WaitGroup{}
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			pt := testutil.PanicT{}

			req := createTestMessage()
			resp, err := u.Exchange(req)
			require.NoError(pt, err)
			requireResponse(pt, req, resp)
		}()
	}

	wg.Wait()
}

func TestUpstream_dnsOverTLS_poolReconnect(t *testing.T) {
	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := respondToTestMessage(req)

		err := w.WriteMsg(resp)

		pt := testutil.PanicT{}
		require.NoError(pt, err)
	})
	testutil.CleanupAndRequireSuccess(t, srv.Close)

	// This var is used to store the last connection state in order to check
	// if session resumption works as expected.
	var lastState tls.ConnectionState

	// Init the upstream to the test DoT server that also keeps track of the
	// session resumptions.
	addr := fmt.Sprintf("tls://127.0.0.1:%d", srv.port)
	u, err := AddressToUpstream(
		addr,
		&Options{
			InsecureSkipVerify: true,
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

	// Now let's close the pooled connection.
	p := u.(*dnsOverTLS)
	conn, _ := p.pool.Get()
	conn.Close()

	// And return it back to the pool.
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

func TestUpstream_dnsOverTLS_poolDeadline(t *testing.T) {
	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := respondToTestMessage(req)

		err := w.WriteMsg(resp)

		pt := testutil.PanicT{}
		require.NoError(pt, err)
	})
	testutil.CleanupAndRequireSuccess(t, srv.Close)

	// Create a DoT upstream that we'll be testing.
	addr := fmt.Sprintf("tls://127.0.0.1:%d", srv.port)
	u, err := AddressToUpstream(addr, &Options{InsecureSkipVerify: true})
	require.NoError(t, err)

	// Send the first test message.
	req := createTestMessage()
	response, err := u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, response)

	p := u.(*dnsOverTLS)

	// Now let's get connection from the pool and use it again.
	conn, err := p.pool.Get()
	require.NoError(t, err)

	response, err = p.exchangeConn(conn, req)
	require.NoError(t, err)
	requireResponse(t, req, response)

	// Update the connection's deadLine.
	err = conn.SetDeadline(time.Now().Add(10 * time.Hour))
	require.NoError(t, err)

	// And put it back to the pool.
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
	require.Nil(t, response)
}

// testDoTServer is a test DNS-over-TLS server that can be used in unit-tests.
type testDoTServer struct {
	// srv is the *dns.Server instance that listens for DoT requests.
	srv *dns.Server

	// tlsConfig is the TLS configuration that is used for this server.
	tlsConfig *tls.Config

	// rootCAs is the pool with root certificates used by the test server.
	rootCAs *x509.CertPool

	// port to which the server listens to.
	port int
}

// type check
var _ io.Closer = (*testDoTServer)(nil)

// startDoTServer starts *testDoTServer on a random port.
func startDoTServer(t *testing.T, handler dns.HandlerFunc) (s *testDoTServer) {
	t.Helper()

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tlsConfig, rootCAs := createServerTLSConfig(t, "127.0.0.1")
	tlsListener := tls.NewListener(tcpListener, tlsConfig)

	srv := &dns.Server{
		Listener:  tlsListener,
		TLSConfig: tlsConfig,
		Net:       "tls",
		Handler:   handler,
	}

	go func() {
		pt := testutil.PanicT{}
		require.NoError(pt, srv.ActivateAndServe())
	}()

	return &testDoTServer{
		srv:       srv,
		tlsConfig: tlsConfig,
		rootCAs:   rootCAs,
		port:      tcpListener.Addr().(*net.TCPAddr).Port,
	}
}

// Close implements the io.Closer interface for *testDoTServer.
func (s *testDoTServer) Close() error {
	return s.srv.Shutdown()
}
