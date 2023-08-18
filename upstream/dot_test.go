package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
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

func TestUpstream_dnsOverTLS(t *testing.T) {
	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := respondToTestMessage(req)

		err := w.WriteMsg(resp)

		pt := testutil.PanicT{}
		require.NoError(pt, err)
	})

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
			resp, uErr := u.Exchange(req)
			require.NoError(pt, uErr)
			requireResponse(pt, req, resp)
		}()
	}

	wg.Wait()
}

// TODO(e.burkov, a.garipov):  Add to golibs and use here some kind of helper
// for type assertion of interface types.
func TestUpstream_dnsOverTLS_poolReconnect(t *testing.T) {
	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(req)))
	})

	// This var is used to store the last connection state in order to check
	// if session resumption works as expected.
	var lastState tls.ConnectionState

	// Init the upstream to the test DoT server that also keeps track of the
	// session resumptions.
	addr := (&url.URL{
		Scheme: "tls",
		Host:   srv.srv.Listener.Addr().String(),
	}).String()
	u, err := AddressToUpstream(addr, &Options{
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			lastState = state

			return nil
		},
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	p := testutil.RequireTypeAssert[*dnsOverTLS](t, u)

	// Send the first test message.
	req := createTestMessage()
	reply, err := u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)

	// Now let's close the pooled connection.
	require.Len(t, p.conns, 1)
	conn := p.conns[0]
	require.NoError(t, conn.Close())

	// Send the second test message.
	req = createTestMessage()
	reply, err = u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, reply)

	// Now assert that the number of connections in the pool is not changed.
	require.Len(t, p.conns, 1)
	assert.NotSame(t, conn, p.conns[0])

	// Check that the session was resumed on the last attempt.
	assert.True(t, lastState.DidResume)
}

func TestUpstream_dnsOverTLS_poolDeadline(t *testing.T) {
	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(req)))
	})

	// Create a DoT upstream that we'll be testing.
	addr := (&url.URL{
		Scheme: "tls",
		Host:   srv.srv.Listener.Addr().String(),
	}).String()
	u, err := AddressToUpstream(addr, &Options{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// Send the first test message.
	req := createTestMessage()
	response, err := u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, response)

	p := testutil.RequireTypeAssert[*dnsOverTLS](t, u)

	// Now let's get connection from the pool and use it again.
	require.Len(t, p.conns, 1)
	conn := p.conns[0]

	dialHandler, err := p.getDialer()
	require.NoError(t, err)

	usedConn, err := p.conn(dialHandler)
	require.NoError(t, err)
	require.Same(t, usedConn, conn)

	response, err = p.exchangeWithConn(conn, req)
	require.NoError(t, err)
	requireResponse(t, req, response)

	// Update the connection's deadLine.
	err = conn.SetDeadline(time.Now().Add(10 * time.Hour))
	require.NoError(t, err)

	p.putBack(conn)

	// Get connection from the pool and reuse it.
	require.Len(t, p.conns, 1)
	conn = p.conns[0]

	usedConn, err = p.conn(dialHandler)
	require.NoError(t, err)
	require.Same(t, usedConn, conn)

	response, err = p.exchangeWithConn(usedConn, req)
	require.NoError(t, err)
	requireResponse(t, req, response)

	// Set connection's deadLine to the past and try to reuse it.
	err = usedConn.SetDeadline(time.Now().Add(-10 * time.Hour))
	require.NoError(t, err)

	// Connection with expired deadLine can't be used.
	response, err = p.exchangeWithConn(usedConn, req)
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
//
// TODO(e.burkov):  Also return address?
func startDoTServer(tb testing.TB, handler dns.HandlerFunc) (s *testDoTServer) {
	tb.Helper()

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(tb, err)

	tlsConfig, rootCAs := createServerTLSConfig(tb, "127.0.0.1")
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

	s = &testDoTServer{
		srv:       srv,
		tlsConfig: tlsConfig,
		rootCAs:   rootCAs,
		port:      tcpListener.Addr().(*net.TCPAddr).Port,
	}
	testutil.CleanupAndRequireSuccess(tb, s.Close)

	return s
}

// Close implements the io.Closer interface for *testDoTServer.
func (s *testDoTServer) Close() error {
	return s.srv.Shutdown()
}

func BenchmarkDoTUpstream(b *testing.B) {
	srv := startDoTServer(b, func(w dns.ResponseWriter, m *dns.Msg) {
		err := w.WriteMsg(respondToTestMessage(m))
		require.NoError(testutil.PanicT{}, err)
	})

	addr := (&url.URL{
		Scheme: "tls",
		Host:   srv.srv.Listener.Addr().String(),
	}).String()

	u, err := AddressToUpstream(addr, &Options{
		InsecureSkipVerify: true,
	})
	require.NoError(b, err)
	testutil.CleanupAndRequireSuccess(b, u.Close)

	reqChan := make(chan *dns.Msg, 64)
	go func() {
		for {
			reqChan <- createTestMessage()
		}
	}()

	// Wait for channel to fill.
	require.Eventually(b, func() bool {
		return len(reqChan) == cap(reqChan)
	}, time.Second, time.Millisecond)

	b.Run("exchange_p", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(p *testing.PB) {
			for p.Next() {
				_, _ = u.Exchange(<-reqChan)
			}
		})
	})
}
