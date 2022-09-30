package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestUpstreamDoQ(t *testing.T) {
	srv := startDoQServer(t, 0)
	t.Cleanup(srv.Shutdown)

	address := fmt.Sprintf("quic://%s", srv.addr)
	var lastState tls.ConnectionState
	opts := &Options{
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			lastState = state
			return nil
		},
	}
	u, err := AddressToUpstream(address, opts)
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

	// Re-create the upstream to make the test check initialization and
	// check it for race conditions.
	u, err = AddressToUpstream(address, opts)
	require.NoError(t, err)

	checkRaceCondition(u)
}

func TestUpstreamDoQ_serverRestart(t *testing.T) {
	// Run the first server instance.
	srv := startDoQServer(t, 0)

	// Create a DNS-over-QUIC upstream.
	address := fmt.Sprintf("quic://%s", srv.addr)
	u, err := AddressToUpstream(address, &Options{InsecureSkipVerify: true, Timeout: time.Second})
	require.NoError(t, err)

	// Test that the upstream works properly.
	checkUpstream(t, u, address)

	// Now let's restart the server on the same address.
	_, portStr, err := net.SplitHostPort(srv.addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)

	// Shutdown the first server.
	srv.Shutdown()

	// Start the new one on the same port.
	srv = startDoQServer(t, port)

	// Check that everything works after restart.
	checkUpstream(t, u, address)

	// Stop the server again.
	srv.Shutdown()

	// Now try to send a message and make sure that it returns an error.
	_, err = u.Exchange(createTestMessage())
	require.Error(t, err)

	// Start the server one more time.
	srv = startDoQServer(t, port)

	// Check that everything works after the second restart.
	checkUpstream(t, u, address)
}

// testDoHServer is an instance of a test DNS-over-QUIC server.
type testDoQServer struct {
	// addr is the address that this server listens to.
	addr string

	// tlsConfig is the TLS configuration that is used for this server.
	tlsConfig *tls.Config

	// listener is the QUIC connections listener.
	listener quic.EarlyListener
}

// Shutdown stops the test server.
func (s *testDoQServer) Shutdown() {
	_ = s.listener.Close()
}

// Serve serves DoQ requests.
func (s *testDoQServer) Serve() {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err == quic.ErrServerClosed {
			// Finish serving on ErrServerClosed error.
			return
		}

		if err != nil {
			log.Debug("error while accepting a new connection: %v", err)
		}

		go s.handleQUICConnection(conn)
	}
}

// handleQUICConnection handles incoming QUIC connection.
func (s *testDoQServer) handleQUICConnection(conn quic.EarlyConnection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			_ = conn.CloseWithError(QUICCodeNoError, "")

			return
		}

		go func() {
			qErr := s.handleQUICStream(stream)
			if qErr != nil {
				_ = conn.CloseWithError(QUICCodeNoError, "")
			}
		}()
	}
}

// handleQUICStream handles new QUIC streams, reads DNS messages and responds to
// them.
func (s *testDoQServer) handleQUICStream(stream quic.Stream) (err error) {
	defer stream.Close()

	buf := make([]byte, dns.MaxMsgSize+2)
	_, err = stream.Read(buf)
	if err != nil && err != io.EOF {
		return err
	}

	req := &dns.Msg{}
	packetLen := binary.BigEndian.Uint16(buf[:2])
	err = req.Unpack(buf[2 : packetLen+2])
	if err != nil {
		return err
	}

	resp := respondToTestMessage(req)

	buf, err = resp.Pack()
	if err != nil {
		return err
	}

	buf = proxyutil.AddPrefix(buf)
	_, err = stream.Write(buf)

	return err
}

// startDoQServer starts a test DoQ server.
func startDoQServer(t *testing.T, port int) (s *testDoQServer) {
	tlsConfig := createServerTLSConfig(t, "127.0.0.1")
	tlsConfig.NextProtos = []string{NextProtoDQ}

	listen, err := quic.ListenAddrEarly(
		fmt.Sprintf("127.0.0.1:%d", port),
		tlsConfig,
		&quic.Config{},
	)
	require.NoError(t, err)

	s = &testDoQServer{
		addr:      listen.Addr().String(),
		tlsConfig: tlsConfig,
		listener:  listen,
	}

	go s.Serve()

	return s
}
