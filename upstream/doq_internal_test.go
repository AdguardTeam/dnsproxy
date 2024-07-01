package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamDoQ(t *testing.T) {
	tlsConf, rootCAs := createServerTLSConfig(t, "127.0.0.1")

	srv := startDoQServer(t, tlsConf, 0)

	address := fmt.Sprintf("quic://%s", srv.addr)
	var lastState tls.ConnectionState
	opts := &Options{
		Logger: slogutil.NewDiscardLogger(),
		VerifyConnection: func(state tls.ConnectionState) error {
			lastState = state

			return nil
		},
		RootCAs: rootCAs,
	}
	u, err := AddressToUpstream(address, opts)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	uq := u.(*dnsOverQUIC)
	var conn quic.Connection

	// Test that it responds properly
	for range 10 {
		checkUpstream(t, u, address)

		if conn == nil {
			conn = uq.conn
		} else {
			// This way we test that the connection is properly reused.
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

func TestUpstream_Exchange_quicServerCloseConn(t *testing.T) {
	// Use the same tlsConf for all servers to preserve the data necessary for
	// 0-RTT connections.
	tlsConf, rootCAs := createServerTLSConfig(t, "127.0.0.1")

	// Run the first server instance.
	srv := startDoQServer(t, tlsConf, 0)

	// Create a DNS-over-QUIC upstream.
	address := fmt.Sprintf("quic://%s", srv.addr)
	u, err := AddressToUpstream(address, &Options{
		Logger:  slogutil.NewDiscardLogger(),
		RootCAs: rootCAs,
	})

	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// Test that the upstream works properly.
	checkUpstream(t, u, address)

	// Close all active connections.
	err = srv.closeConns()
	require.NoError(t, err)

	// Now run several queries in parallel to check that the error from the
	// following issue is not happening:
	// https://github.com/AdguardTeam/dnsproxy/issues/389.
	//
	// Run 10 queries in parallel as the initial testing showed that this is
	// enough to trigger the race issue.
	const parallelQueries = 10

	wg := sync.WaitGroup{}
	wg.Add(parallelQueries)

	for i := 0; i < 10; i++ {
		pt := testutil.PanicT{}

		go func(t assert.TestingT) {
			defer wg.Done()

			req := createTestMessage()
			_, errExch := u.Exchange(req)

			assert.NoError(t, errExch)
		}(pt)
	}

	wg.Wait()
}

func TestUpstreamDoQ_serverRestart(t *testing.T) {
	t.Parallel()

	// Use the same tlsConf for all servers to preserve the data necessary for
	// 0-RTT connections.
	tlsConf, rootCAs := createServerTLSConfig(t, "127.0.0.1")

	var addr netip.AddrPort
	var upsStr string
	var u Upstream

	t.Run("first_try", func(t *testing.T) {
		srv := startDoQServer(t, tlsConf, 0)

		addr = netip.MustParseAddrPort(srv.addr)
		upsStr = (&url.URL{
			Scheme: "quic",
			Host:   addr.String(),
		}).String()

		var err error
		u, err = AddressToUpstream(
			upsStr,
			&Options{
				Logger:  slogutil.NewDiscardLogger(),
				RootCAs: rootCAs,
				Timeout: 100 * time.Millisecond,
			},
		)
		require.NoError(t, err)

		checkUpstream(t, u, upsStr)
	})
	require.False(t, t.Failed())
	testutil.CleanupAndRequireSuccess(t, u.Close)

	t.Run("second_try", func(t *testing.T) {
		_ = startDoQServer(t, tlsConf, int(addr.Port()))

		checkUpstream(t, u, upsStr)
	})
	require.False(t, t.Failed())

	t.Run("retry", func(t *testing.T) {
		_, err := u.Exchange(createTestMessage())
		require.Error(t, err)

		_ = startDoQServer(t, tlsConf, int(addr.Port()))

		checkUpstream(t, u, upsStr)
	})
}

func TestUpstreamDoQ_0RTT(t *testing.T) {
	tlsConf, rootCAs := createServerTLSConfig(t, "127.0.0.1")

	srv := startDoQServer(t, tlsConf, 0)

	tracer := &quicTracer{}
	address := fmt.Sprintf("quic://%s", srv.addr)
	u, err := AddressToUpstream(address, &Options{
		Logger:     slogutil.NewDiscardLogger(),
		QUICTracer: tracer.TracerForConnection,
		RootCAs:    rootCAs,
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
	// listener is the QUIC connections listener.
	listener *quic.EarlyListener

	// logger is used for serving errors logging.
	logger *slog.Logger

	// conns is the list of connections that are currently active.
	conns map[quic.EarlyConnection]struct{}

	// connsMu protects conns.
	connsMu *sync.Mutex

	// addr is the address that this server listens to.
	addr string
}

// Shutdown stops the test server.
func (s *testDoQServer) Shutdown() (err error) {
	errConns := s.closeConns()
	errListener := s.listener.Close()

	return errors.Join(errConns, errListener)
}

// Serve serves DoQ requests.
func (s *testDoQServer) Serve() {
	for {
		var conn quic.EarlyConnection
		var err error
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err = s.listener.Accept(ctx)
		}()
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug("accept failed", slogutil.KeyError, err)
			} else {
				s.logger.Error("accept failed", slogutil.KeyError, err)
			}

			return
		}

		go s.handleQUICConnection(conn)
	}
}

// handleQUICConnection handles incoming QUIC connection.
func (s *testDoQServer) handleQUICConnection(conn quic.EarlyConnection) {
	s.addConn(conn)
	defer s.closeConn(conn)

	for {
		ctx := context.Background()

		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}

		go func() {
			qErr := s.handleQUICStream(ctx, stream)
			if qErr != nil {
				s.logger.Error("handling", "raddr", conn.RemoteAddr(), slogutil.KeyError, qErr)

				_ = conn.CloseWithError(QUICCodeNoError, "")
			}
		}()
	}
}

// handleQUICStream handles new QUIC streams, reads DNS messages and responds to
// them.
func (s *testDoQServer) handleQUICStream(ctx context.Context, stream quic.Stream) (err error) {
	defer slogutil.CloseAndLog(ctx, s.logger, stream, slog.LevelDebug)

	buf := make([]byte, dns.MaxMsgSize+2)
	_, err = stream.Read(buf)
	if err != nil && err != io.EOF {
		return err
	}

	stream.CancelRead(0)

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

// addConn adds conn to the list of active connections.
func (s *testDoQServer) addConn(conn quic.EarlyConnection) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	s.conns[conn] = struct{}{}
}

// closeConn closes the specified QUIC connection.
func (s *testDoQServer) closeConn(conn quic.EarlyConnection) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	err := conn.CloseWithError(QUICCodeNoError, "")
	if err != nil {
		s.logger.Debug("failed to close conn", slogutil.KeyError, err)
	}

	delete(s.conns, conn)
}

// closeConns closes all active connections.
func (s *testDoQServer) closeConns() (err error) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	var errs []error

	for conn := range s.conns {
		errConn := conn.CloseWithError(QUICCodeNoError, "")
		if errConn != nil {
			errs = append(errs, errConn)
		}

		delete(s.conns, conn)
	}

	return errors.Join(errs...)
}

// startDoQServer starts a test DoQ server.  Note that it adds its own shutdown
// to cleanup of t.
func startDoQServer(t *testing.T, tlsConf *tls.Config, port int) (s *testDoQServer) {
	tlsConf.NextProtos = []string{NextProtoDQ}

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, conn.Close)

	transport := &quic.Transport{
		Conn: conn,
		// Necessary for 0-RTT.
		VerifySourceAddress: func(a net.Addr) bool {
			return true
		},
	}

	listen, err := transport.ListenEarly(
		tlsConf,
		&quic.Config{
			Allow0RTT: true,
		},
	)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, transport.Close)

	s = &testDoQServer{
		addr:     listen.Addr().String(),
		listener: listen,
		// TODO(d.kolyshev): Add a concurrent safe [slog.Handler] wrapper for
		// [testing.TB] log function.
		logger:  slogutil.NewDiscardLogger(),
		conns:   map[quic.EarlyConnection]struct{}{},
		connsMu: &sync.Mutex{},
	}

	go s.Serve()
	testutil.CleanupAndRequireSuccess(t, s.Shutdown)

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
