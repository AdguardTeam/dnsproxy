package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/stretchr/testify/require"
)

func TestUpstreamDoQ(t *testing.T) {
	addr := startDoQServer(t, 0)

	address := fmt.Sprintf("quic://%s", addr)

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

	uq := testutil.RequireTypeAssert[*dnsOverQUIC](t, u)
	t.Run("initial_resolve", func(t *testing.T) {
		checkUpstream(t, u, address)
		conn := uq.conn

		// Test that it responds properly
		for i := 0; i < 10; i++ {
			checkUpstream(t, u, address)

			// This way we test that the conn is properly reused.
			require.Equal(t, conn, uq.conn)
		}

		// Close the connection (make sure that we re-establish the connection).
		require.NoError(t, conn.CloseWithError(quic.ApplicationErrorCode(0), ""))
	})
	require.False(t, t.Failed())

	t.Run("reestablish", func(t *testing.T) {
		// Try to establish it again.
		checkUpstream(t, u, address)

		// Make sure that the session has been resumed.
		require.True(t, lastState.DidResume)
	})
	require.False(t, t.Failed())
}

func TestDNSOverQUIC_raceCondition(t *testing.T) {
	addr := startDoQServer(t, 0)

	address := fmt.Sprintf("quic://%s", addr)

	u, err := AddressToUpstream(address, nil)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	checkRaceCondition(u, 30, 10)
}

func TestUpstreamDoQ_serverRestart(t *testing.T) {
	var addr netip.AddrPort
	var upsURL string
	var u Upstream

	tt := t
	t.Run("first", func(t *testing.T) {
		// Run the first server instance.
		addr = startDoQServer(t, 0)

		// Create a DNS-over-QUIC upstream.
		upsURL = fmt.Sprintf("quic://%s", addr)

		var err error
		u, err = AddressToUpstream(upsURL, &Options{InsecureSkipVerify: true, Timeout: time.Second})
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(tt, u.Close)

		// Test that the upstream works properly.
		checkUpstream(t, u, upsURL)
	})
	require.False(t, t.Failed())

	t.Run("rerun", func(t *testing.T) {
		// Start the new one on the same port.
		_ = startDoQServer(t, addr.Port())

		// Check that everything works after restart.
		checkUpstream(t, u, upsURL)
	})
	require.False(t, t.Failed())

	t.Run("error", func(t *testing.T) {
		// Now try to send a message and make sure that it returns an error.
		_, err := u.Exchange(createTestMessage())
		require.Error(t, err)
	})
	require.False(t, t.Failed())

	t.Run("rerun_again", func(t *testing.T) {
		// Start the server one more time.
		_ = startDoQServer(t, addr.Port())

		// Check that everything works after the second restart.
		checkUpstream(t, u, upsURL)
	})
}

func TestUpstreamDoQ_0RTT(t *testing.T) {
	addr := startDoQServer(t, 0)

	tracer := &quicTracer{}
	address := fmt.Sprintf("quic://%s", addr)
	u, err := AddressToUpstream(address, &Options{
		InsecureSkipVerify: true,
		QUICTracer:         tracer.TracerForConnection,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	uq := testutil.RequireTypeAssert[*dnsOverQUIC](t, u)
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
	connInfos := tracer.getConnectionsInfo()
	require.Len(t, connInfos, 2)

	// Examine the first connection (no 0-RTT there).
	require.False(t, connInfos[0].is0RTT())

	// Examine the second connection (the one that used 0-RTT).
	require.True(t, connInfos[1].is0RTT())
}

// testDoHServer is an instance of a test DNS-over-QUIC server.
type testDoQServer struct {
	// tlsConfig is the TLS configuration that is used for this server.
	tlsConfig *tls.Config

	// rootCAs is the pool with root certificates used by the test server.
	rootCAs *x509.CertPool

	// listener is the QUIC connections listener.
	listener *quic.EarlyListener
}

// serve serves DoQ requests.
func (s *testDoQServer) serve(cancel context.CancelCauseFunc) {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			if err == quic.ErrServerClosed {
				cancel(nil)
			} else {
				cancel(fmt.Errorf("accepting quic conn: %w", err))
			}

			return
		}

		go s.handleQUICConn(conn)
	}
}

// handleQUICConnection handles incoming QUIC connection.
func (s *testDoQServer) handleQUICConn(conn quic.EarlyConnection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			_ = conn.CloseWithError(QUICCodeNoError, "")

			return
		}

		go s.handleQUICStream(conn, stream)
	}
}

// handleQUICStream handles new QUIC streams, reads DNS messages and responds to
// them.
func (s *testDoQServer) handleQUICStream(conn quic.EarlyConnection, stream quic.Stream) {
	var err error
	defer func() {
		if err != nil {
			_ = conn.CloseWithError(QUICCodeNoError, "")
		}
	}()

	buf := make([]byte, dns.MaxMsgSize+2)
	_, err = stream.Read(buf)
	if err != nil && err != io.EOF {
		return
	}

	req := &dns.Msg{}
	packetLen := binary.BigEndian.Uint16(buf[:2])
	err = req.Unpack(buf[2 : packetLen+2])
	if err != nil {
		return
	}

	resp := respondToTestMessage(req)

	buf, err = resp.Pack()
	if err != nil {
		return
	}

	buf = proxyutil.AddPrefix(buf)
	_, err = stream.Write(buf)
}

// startDoQServer starts a test DoQ server.
func startDoQServer(t *testing.T, port uint16) (addr netip.AddrPort) {
	t.Helper()

	tlsConfig, rootCAs := createServerTLSConfig(t, "127.0.0.1")
	tlsConfig.NextProtos = []string{NextProtoDQ}

	addr = netip.AddrPortFrom(netutil.IPv4Localhost(), port)
	listen, err := quic.ListenAddrEarly(addr.String(), tlsConfig, &quic.Config{
		// Necessary for 0-RTT.
		RequireAddressValidation: func(net.Addr) (ok bool) {
			return false
		},
		Allow0RTT: true,
	})
	require.NoError(t, err)

	ctx := context.Background()
	ctx, cancel := context.WithCancelCause(ctx)

	s := &testDoQServer{
		tlsConfig: tlsConfig,
		rootCAs:   rootCAs,
		listener:  listen,
	}

	go s.serve(cancel)
	testutil.CleanupAndRequireSuccess(t, s.listener.Close)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return context.Cause(ctx) })

	udpAddr := testutil.RequireTypeAssert[*net.UDPAddr](t, listen.Addr())

	return udpAddr.AddrPort()
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
