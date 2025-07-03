package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	// QUICCodeNoError is used when the connection or stream needs to be closed,
	// but there is no error to signal.
	QUICCodeNoError = quic.ApplicationErrorCode(0)

	// QUICCodeInternalError signals that the DoQ implementation encountered
	// an internal error and is incapable of pursuing the transaction or the
	// connection.
	QUICCodeInternalError = quic.ApplicationErrorCode(1)

	// QUICKeepAlivePeriod is the value that we pass to *quic.Config and that
	// controls the period with with keep-alive frames are being sent to the
	// connection. We set it to 20s as it would be in the quic-go@v0.27.1 with
	// KeepAlive field set to true This value is specified in
	// https://pkg.go.dev/github.com/quic-go/quic-go/internal/protocol#MaxKeepAliveInterval.
	//
	// TODO(ameshkov):  Consider making it configurable.
	QUICKeepAlivePeriod = time.Second * 20

	// NextProtoDQ is the ALPN token for DoQ. During the connection establishment,
	// DNS/QUIC support is indicated by selecting the ALPN token "doq" in the
	// crypto handshake.
	//
	// See https://datatracker.ietf.org/doc/rfc9250.
	NextProtoDQ = "doq"
)

// compatProtoDQ is a list of ALPN tokens used by a QUIC connection.
// NextProtoDQ is the latest draft version supported by dnsproxy, but it also
// includes previous drafts.
var compatProtoDQ = []string{NextProtoDQ, "doq-i00", "dq", "doq-i02"}

// dnsOverQUIC implements the [Upstream] interface for the DNS-over-QUIC
// protocol (spec: https://www.rfc-editor.org/rfc/rfc9250.html).
type dnsOverQUIC struct {
	// getDialer either returns an initialized dial handler or creates a new
	// one.
	getDialer DialerInitializer

	// addr is the DNS-over-QUIC server URL.
	addr *url.URL

	// tlsConf is the configuration of TLS.
	tlsConf *tls.Config

	// quicConfig is the QUIC configuration that is used for establishing
	// connections to the upstream.  This configuration includes the TokenStore
	// that needs to be stored for the lifetime of dnsOverQUIC since we can
	// re-create the connection.
	quicConfig *quic.Config

	// conn is the current active QUIC connection.  It can be closed and
	// re-opened when needed.
	conn *quic.Conn

	// bytesPool is a *sync.Pool we use to store byte buffers in.  These byte
	// buffers are used to read responses from the upstream.
	bytesPool *sync.Pool

	// quicConfigMu protects quicConfig.
	quicConfigMu *sync.Mutex

	// connMu protects conn.
	connMu *sync.Mutex

	// bytesPoolGuard protects bytesPool.
	bytesPoolMu *sync.Mutex

	// logger is used for exchange logging.  It is never nil.
	logger *slog.Logger

	// timeout is the timeout for the upstream connection.
	timeout time.Duration
}

// newDoQ returns the DNS-over-QUIC Upstream.
func newDoQ(addr *url.URL, opts *Options) (u Upstream, err error) {
	addPort(addr, defaultPortDoQ)

	u = &dnsOverQUIC{
		getDialer: newDialerInitializer(addr, opts),
		addr:      addr,
		quicConfig: &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
			Tracer:          opts.QUICTracer,
		},
		tlsConf: &tls.Config{
			ServerName:   addr.Hostname(),
			RootCAs:      opts.RootCAs,
			CipherSuites: opts.CipherSuites,
			// Use the default capacity for the LRU cache.  It may be useful to
			// store several caches since the user may be routed to different
			// servers in case there's load balancing on the server-side.
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
			MinVersion:         tls.VersionTLS12,
			// #nosec G402 -- TLS certificate verification could be disabled by
			// configuration.
			InsecureSkipVerify:    opts.InsecureSkipVerify,
			VerifyPeerCertificate: opts.VerifyServerCertificate,
			VerifyConnection:      opts.VerifyConnection,
			NextProtos:            compatProtoDQ,
		},
		quicConfigMu: &sync.Mutex{},
		connMu:       &sync.Mutex{},
		bytesPoolMu:  &sync.Mutex{},
		logger:       opts.Logger,
		timeout:      opts.Timeout,
	}

	runtime.SetFinalizer(u, (*dnsOverQUIC).Close)

	return u, nil
}

// type check
var _ Upstream = (*dnsOverQUIC)(nil)

// Address implements the [Upstream] interface for *dnsOverQUIC.
func (p *dnsOverQUIC) Address() string { return p.addr.String() }

// Exchange implements the [Upstream] interface for *dnsOverQUIC.
func (p *dnsOverQUIC) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	// When sending queries over a QUIC connection, the DNS Message ID MUST be
	// set to 0.  The stream mapping for DoQ allows for unambiguous correlation
	// of queries and responses, so the Message ID field is not required.
	//
	// See https://www.rfc-editor.org/rfc/rfc9250#section-4.2.1.
	id := req.Id
	req.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies.
		req.Id = id
		if resp != nil {
			resp.Id = id
		}
	}()

	// Gets or opens a QUIC connection to use for this query.
	conn, cached, err := p.getConnection()
	if err != nil {
		return nil, fmt.Errorf("getting conn: %w", err)
	}

	// Make the first attempt to send the DNS query.
	resp, err = p.exchangeQUIC(req, conn)

	// Failure to use a cached connection should be handled gracefully as this
	// connection could have been closed by the server or simply be broken due
	// to how UDP NAT works.  In this case the connection should be re-created.
	if cached && err != nil {
		p.logger.Debug("recreating the quic connection and retrying", slogutil.KeyError, err)

		// Close the active connection to make sure the cached connection is
		// cleaned up.
		p.closeConnWithError(conn, err)

		// Get or re-create the QUIC connection in order to make the second
		// attempt.
		conn, _, err = p.getConnection()
		if err != nil {
			return nil, fmt.Errorf("getting new conn: %w", err)
		}

		// Retry sending the request through the new connection.
		resp, err = p.exchangeQUIC(req, conn)
	}

	if err != nil {
		// If we're unable to exchange messages, make sure the connection is
		// closed and signal about an internal error.
		p.closeConnWithError(conn, err)
	}

	return resp, err
}

// Close implements the [Upstream] interface for *dnsOverQUIC.
func (p *dnsOverQUIC) Close() (err error) {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	runtime.SetFinalizer(p, nil)

	if p.conn != nil {
		err = p.conn.CloseWithError(QUICCodeNoError, "")
	}

	return err
}

// exchangeQUIC attempts to open a new QUIC stream, send the DNS message
// through it and return the response it got from the server.
func (p *dnsOverQUIC) exchangeQUIC(req *dns.Msg, conn *quic.Conn) (resp *dns.Msg, err error) {
	addr := p.Address()

	logBegin(p.logger, addr, networkUDP, req)
	defer func() { logFinish(p.logger, addr, networkUDP, err) }()

	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message for DoQ: %w", err)
	}

	stream, err := p.openStream(conn)
	if err != nil {
		return nil, fmt.Errorf("opening stream: %w", err)
	}

	if p.timeout > 0 {
		err = stream.SetDeadline(time.Now().Add(p.timeout))
		if err != nil {
			return nil, fmt.Errorf("setting deadline: %w", err)
		}
	}

	_, err = stream.Write(proxyutil.AddPrefix(buf))
	if err != nil {
		return nil, fmt.Errorf("failed to write to a QUIC stream: %w", err)
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will be
	// sent on that stream. Note, that stream.Close() closes the write-direction
	// of the stream, but does not prevent reading from it.
	err = stream.Close()
	if err != nil {
		p.logger.Debug("closing quic stream", slogutil.KeyError, err)
	}

	return p.readMsg(stream)
}

// getBytesPool returns (creates if needed) a pool we store byte buffers in.
func (p *dnsOverQUIC) getBytesPool() (pool *sync.Pool) {
	p.bytesPoolMu.Lock()
	defer p.bytesPoolMu.Unlock()

	if p.bytesPool == nil {
		p.bytesPool = &sync.Pool{
			New: func() interface{} {
				b := make([]byte, dns.MaxMsgSize)

				return &b
			},
		}
	}

	return p.bytesPool
}

// getConnection opens or returns an existing *quic.Conn and indicates whether
// it opened a new connection or used an existing cached one.
func (p *dnsOverQUIC) getConnection() (conn *quic.Conn, cached bool, err error) {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	conn = p.conn
	if conn != nil {
		return conn, true, nil
	}

	conn, err = p.openConnection()
	if err != nil {
		return nil, false, err
	}

	p.conn = conn

	return conn, false, nil
}

// getQUICConfig returns the QUIC config in a thread-safe manner.  Note, that
// this method returns a pointer, it is forbidden to change its properties.
func (p *dnsOverQUIC) getQUICConfig() (c *quic.Config) {
	p.quicConfigMu.Lock()
	defer p.quicConfigMu.Unlock()

	return p.quicConfig
}

// resetQUICConfig re-creates the tokens store as we may need to use a new one
// if we failed to connect.
func (p *dnsOverQUIC) resetQUICConfig() {
	p.quicConfigMu.Lock()
	defer p.quicConfigMu.Unlock()

	p.quicConfig = p.quicConfig.Clone()
	p.quicConfig.TokenStore = newQUICTokenStore()
}

// openStream opens a new QUIC stream for the specified connection.
func (p *dnsOverQUIC) openStream(conn *quic.Conn) (*quic.Stream, error) {
	ctx, cancel := p.withDeadline(context.Background())
	defer cancel()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open a QUIC stream: %w", err)
	}

	return stream, nil
}

// openConnection dials a new QUIC connection.
func (p *dnsOverQUIC) openConnection() (conn *quic.Conn, err error) {
	dialContext, err := p.getDialer()
	if err != nil {
		return nil, fmt.Errorf("bootstrapping %s: %w", p.addr, err)
	}

	// we're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there're v4/v6 addresses).
	rawConn, err := dialContext(context.Background(), "udp", "")
	if err != nil {
		return nil, fmt.Errorf("dialing raw connection to %s: %w", p.addr, err)
	}

	// It's never actually used.
	err = rawConn.Close()
	if err != nil {
		p.logger.Debug("closing raw connection", "addr", p.addr, slogutil.KeyError, err)
	}

	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T of connection; should be %T", rawConn, udpConn)
	}

	addr := udpConn.RemoteAddr().String()

	ctx, cancel := p.withDeadline(context.Background())
	defer cancel()

	conn, err = quic.DialAddrEarly(ctx, addr, p.tlsConf.Clone(), p.getQUICConfig())
	if err != nil {
		return nil, fmt.Errorf("dialing quic connection to %s: %w", p.addr, err)
	}

	return conn, nil
}

// closeConnWithError closes the active connection with error to make sure that
// new queries were processed in another connection.  We can do that in the case
// of a fatal error.
func (p *dnsOverQUIC) closeConnWithError(conn *quic.Conn, err error) {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	code := QUICCodeNoError
	if err != nil {
		code = QUICCodeInternalError
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		// Reset the TokenStore only if 0-RTT was rejected.
		p.resetQUICConfig()
	}

	err = conn.CloseWithError(code, "")
	if err != nil {
		p.logger.Error("failed to close the conn", slogutil.KeyError, err)
	}

	// If the connection that's being closed is cached, reset the cache.
	if p.conn == conn {
		p.conn = nil
	}
}

// readMsg reads the incoming DNS message from the QUIC stream.
func (p *dnsOverQUIC) readMsg(stream *quic.Stream) (m *dns.Msg, err error) {
	pool := p.getBytesPool()
	bufPtr := pool.Get().(*[]byte)

	defer pool.Put(bufPtr)

	respBuf := *bufPtr
	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("reading response from %s: %w", p.addr, err)
	}

	stream.CancelRead(0)

	// All DNS messages (queries and responses) sent over DoQ connections MUST
	// be encoded as a 2-octet length field followed by the message content as
	// specified in [RFC1035].
	// IMPORTANT: Note, that we ignore this prefix here as this implementation
	// does not support receiving multiple messages over a single connection.
	m = new(dns.Msg)
	err = m.Unpack(respBuf[2:])
	if err != nil {
		return nil, fmt.Errorf("unpacking response from %s: %w", p.addr, err)
	}

	return m, nil
}

// newQUICTokenStore creates a new quic.TokenStore that is necessary to have
// in order to benefit from 0-RTT.
func newQUICTokenStore() (s quic.TokenStore) {
	// You can read more on address validation here:
	// https://datatracker.ietf.org/doc/html/rfc9000#section-8.1
	// Setting maxOrigins to 1 and tokensPerOrigin to 10 assuming that this is
	// more than enough for the way we use it (one connection per upstream).
	return quic.NewLRUTokenStore(1, 10)
}

// isQUICRetryError checks the error and determines whether it may signal that
// we should re-create the QUIC connection.  This requirement is caused by
// quic-go issues, see the comments inside this function.
// TODO(ameshkov): re-test when updating quic-go.
func isQUICRetryError(err error) (ok bool) {
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) {
		// Error code 0 is often returned when the server has been restarted,
		// and we try to use the same connection on the client-side.
		// http3.ErrCodeNoError may be used by an HTTP/3 server when closing
		// an idle connection.  These connections are not immediately closed
		// by the HTTP client so this case should be handled.
		if qAppErr.ErrorCode == 0 ||
			qAppErr.ErrorCode == quic.ApplicationErrorCode(http3.ErrCodeNoError) {
			return true
		}
	}

	var qIdleErr *quic.IdleTimeoutError
	if errors.As(err, &qIdleErr) {
		// This error means that the connection was closed due to being idle.
		// In this case we should forcibly re-create the QUIC connection.
		// Reproducing is rather simple, stop the server and wait for 30 seconds
		// then try to send another request via the same upstream.
		return true
	}

	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		// A stateless reset is sent when a server receives a QUIC packet that
		// it doesn't know how to decrypt.  For instance, it may happen when
		// the server was recently rebooted.  We should reconnect and try again
		// in this case.
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		// A transport error with the NO_ERROR error code could be sent by the
		// server when it considers that it's time to close the connection.
		// For example, Google DNS eventually closes an active connection with
		// the NO_ERROR code and "Connection max age expired" message:
		// https://github.com/AdguardTeam/dnsproxy/issues/283
		return true
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		// This error happens when we try to establish a 0-RTT connection with
		// a token the server is no more aware of.  This can be reproduced by
		// restarting the QUIC server (it will clear its tokens cache).  The
		// next connection attempt will return this error until the client's
		// tokens cache is purged.
		return true
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		// A timeout that could happen when the server has been restarted.
		return true
	}

	return false
}

func (p *dnsOverQUIC) withDeadline(
	parent context.Context,
) (ctx context.Context, cancel context.CancelFunc) {
	ctx, cancel = parent, func() {}
	if p.timeout > 0 {
		ctx, cancel = context.WithDeadline(ctx, time.Now().Add(p.timeout))
	}

	return ctx, cancel
}
