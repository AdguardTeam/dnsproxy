package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
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
	testutil.CleanupAndRequireSuccess(t, u.Close)

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
	testutil.CleanupAndRequireSuccess(t, u.Close)

	checkRaceCondition(u)
}

func TestUpstreamDoQ_serverRestart(t *testing.T) {
	// Run the first server instance.
	srv := startDoQServer(t, 0)

	// Create a DNS-over-QUIC upstream.
	address := fmt.Sprintf("quic://%s", srv.addr)
	u, err := AddressToUpstream(address, &Options{InsecureSkipVerify: true, Timeout: time.Second})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// Test that the upstream works properly.
	checkUpstream(t, u, address)

	// Now let's restart the server on the same address.
	_, portStr, err := net.SplitHostPort(srv.addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

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
	defer srv.Shutdown()

	// Check that everything works after the second restart.
	checkUpstream(t, u, address)
}

func TestUpstreamDoQ_0RTT(t *testing.T) {
	srv := startDoQServer(t, 0)
	t.Cleanup(srv.Shutdown)

	tracer := &quicTracer{}
	address := fmt.Sprintf("quic://%s", srv.addr)
	u, err := AddressToUpstream(address, &Options{
		InsecureSkipVerify: true,
		QUICTracer:         tracer.TracerForConnection,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	uq := u.(*dnsOverQUIC)
	req := createTestMessage()

	// Trigger connection to a QUIC server.
	resp, err := uq.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, resp)

	// Close the active connection to make sure we'll reconnect.
	func() {
		uq.connMu.Lock()
		defer uq.connMu.Unlock()

		err = uq.conn.CloseWithError(QUICCodeNoError, "")
		require.NoError(t, err)

		uq.conn = nil
	}()

	// Trigger second connection.
	resp, err = uq.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, resp)

	// Check traced connections info.
	conns := tracer.getConnectionsInfo()
	require.Len(t, conns, 2)

	// Examine the first connection (no 0-RTT there).
	require.False(t, conns[0].is0RTT())

	// Examine the second connection (the one that used 0-RTT).
	require.True(t, conns[1].is0RTT())
}

// testDoHServer is an instance of a test DNS-over-QUIC server.
type testDoQServer struct {
	// tlsConfig is the TLS configuration that is used for this server.
	tlsConfig *tls.Config

	// rootCAs is the pool with root certificates used by the test server.
	rootCAs *x509.CertPool

	// listener is the QUIC connections listener.
	listener *quic.EarlyListener

	// addr is the address that this server listens to.
	addr string
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
	defer log.OnCloserError(stream, log.DEBUG)

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
	tlsConfig, rootCAs := createServerTLSConfig(t, "127.0.0.1")
	tlsConfig.NextProtos = []string{NextProtoDQ}

	listen, err := quic.ListenAddrEarly(
		fmt.Sprintf("127.0.0.1:%d", port),
		tlsConfig,
		&quic.Config{
			// Necessary for 0-RTT.
			RequireAddressValidation: func(net.Addr) (ok bool) {
				return false
			},
			Allow0RTT: true,
		},
	)
	require.NoError(t, err)

	s = &testDoQServer{
		addr:      listen.Addr().String(),
		tlsConfig: tlsConfig,
		rootCAs:   rootCAs,
		listener:  listen,
	}

	go s.Serve()

	return s
}

// quicTracer implements the logging.Tracer interface.
type quicTracer struct {
	tracers []*quicConnTracer

	// mu protects fields of *quicTracer and also protects fields of every
	// nested *quicConnTracer.
	mu sync.Mutex
}

// TracerForConnection implements the logging.Tracer interface for *quicTracer.
func (q *quicTracer) TracerForConnection(
	_ context.Context,
	_ logging.Perspective,
	odcid logging.ConnectionID,
) (connTracer *logging.ConnectionTracer) {
	q.mu.Lock()
	defer q.mu.Unlock()

	tracer := &quicConnTracer{id: odcid, parent: q}
	q.tracers = append(q.tracers, tracer)

	return &logging.ConnectionTracer{
		SentLongHeaderPacket: tracer.SentLongHeaderPacket,
	}
}

// connInfo contains information about packets that we've logged.
type connInfo struct {
	packets []logging.Header
	id      logging.ConnectionID
}

// is0RTT returns true if this connection's packets contain 0-RTT packets.
func (c *connInfo) is0RTT() (ok bool) {
	for _, packet := range c.packets {
		hdr := packet
		packetType := logging.PacketTypeFromHeader(&hdr)
		if packetType == logging.PacketType0RTT {
			return true
		}
	}

	return false
}

// getConnectionsInfo returns the traced connections' information.
func (q *quicTracer) getConnectionsInfo() (conns []connInfo) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, tracer := range q.tracers {
		conns = append(conns, connInfo{
			id:      tracer.id,
			packets: tracer.packets,
		})
	}

	return conns
}

// quicConnTracer implements the logging.ConnectionTracer interface.
type quicConnTracer struct {
	parent  *quicTracer
	packets []logging.Header
	id      logging.ConnectionID
}

// SentLongHeaderPacket implements the logging.ConnectionTracer interface for
// *quicConnTracer.
func (q *quicConnTracer) SentLongHeaderPacket(
	hdr *logging.ExtendedHeader,
	_ logging.ByteCount,
	_ logging.ECN,
	_ *logging.AckFrame,
	_ []logging.Frame,
) {
	q.parent.mu.Lock()
	defer q.parent.mu.Unlock()

	q.packets = append(q.packets, hdr.Header)
}
