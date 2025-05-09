package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/bluele/gcache"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// NextProtoDQ is the ALPN token for DoQ. During connection establishment,
// DNS/QUIC support is indicated by selecting the ALPN token "dq" in the
// crypto handshake.
// DoQ RFC: https://www.rfc-editor.org/rfc/rfc9250.html
const NextProtoDQ = "doq"

// compatProtoDQ is a list of ALPN tokens used by a QUIC connection.
// NextProtoDQ is the latest draft version supported by dnsproxy, but it also
// includes previous drafts.
var compatProtoDQ = []string{NextProtoDQ, "doq-i02", "doq-i00", "dq"}

// maxQUICIdleTimeout is maximum QUIC idle timeout.  The default value in
// quic-go is 30 seconds, but our internal tests show that a higher value works
// better for clients written with ngtcp2.
const maxQUICIdleTimeout = 5 * time.Minute

// quicAddrValidatorCacheSize is the size of the cache that we use in the QUIC
// address validator.  The value is chosen arbitrarily and we should consider
// making it configurable.
// TODO(ameshkov): make it configurable.
const quicAddrValidatorCacheSize = 1000

// quicAddrValidatorCacheTTL is time-to-live for cache items in the QUIC address
// validator.  The value is chosen arbitrarily and we should consider making it
// configurable.
// TODO(ameshkov): make it configurable.
const quicAddrValidatorCacheTTL = 30 * time.Minute

const (
	// DoQCodeNoError is used when the connection or stream needs to be closed,
	// but there is no error to signal.
	DoQCodeNoError quic.ApplicationErrorCode = 0
	// DoQCodeInternalError signals that the DoQ implementation encountered
	// an internal error and is incapable of pursuing the transaction or the
	// connection.
	DoQCodeInternalError quic.ApplicationErrorCode = 1
	// DoQCodeProtocolError signals that the DoQ implementation encountered
	// a protocol error and is forcibly aborting the connection.
	DoQCodeProtocolError quic.ApplicationErrorCode = 2
)

// initQUICListeners creates QUIC listeners for the DoQ server.
func (p *Proxy) initQUICListeners(ctx context.Context) (err error) {
	for _, a := range p.QUICListenAddr {
		var conn *net.UDPConn
		var ln *quic.EarlyListener
		var tr *quic.Transport
		conn, ln, tr, err = p.listenQUIC(ctx, a)
		if err != nil {
			return fmt.Errorf("listening on quic addr %s: %w", a, err)
		}

		p.quicConns = append(p.quicConns, conn)
		p.quicTransports = append(p.quicTransports, tr)
		p.quicListen = append(p.quicListen, ln)
	}

	return nil
}

// listenQUIC returns a new UDP connection listening on addr, the QUIC listener
// utilizing it, and the associated QUIC transport.
func (p *Proxy) listenQUIC(
	ctx context.Context,
	addr *net.UDPAddr,
) (conn *net.UDPConn, l *quic.EarlyListener, tr *quic.Transport, err error) {
	p.logger.InfoContext(ctx, "creating quic listener", "addr", addr)

	err = p.bindWithRetry(ctx, func() (listenErr error) {
		conn, listenErr = net.ListenUDP(bootstrap.NetworkUDP, addr)

		return listenErr
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listening to udp socket: %w", err)
	}

	v := newQUICAddrValidator(quicAddrValidatorCacheSize, quicAddrValidatorCacheTTL)
	tr = &quic.Transport{
		Conn:                conn,
		VerifySourceAddress: v.requiresValidation,
	}

	tlsConfig := p.TLSConfig.Clone()
	tlsConfig.NextProtos = compatProtoDQ
	l, err = tr.ListenEarly(
		tlsConfig,
		newServerQUICConfig(),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listening early: %w", err)
	}

	p.logger.InfoContext(ctx, "listening quic", "addr", l.Addr())

	return conn, l, tr, nil
}

// quicPacketLoop listens for incoming QUIC packets.
//
// See also the comment on Proxy.requestsSema.
func (p *Proxy) quicPacketLoop(l *quic.EarlyListener, reqSema syncutil.Semaphore) {
	p.logger.Info("entering dns-over-quic listener loop", "addr", l.Addr())

	for {
		ctx := context.Background()
		conn, err := l.Accept(ctx)
		if err != nil {
			logQUICError(ctx, "accepting quic conn", err, p.logger)

			break
		}

		err = reqSema.Acquire(ctx)
		if err != nil {
			p.logger.ErrorContext(
				ctx,
				"acquiring semaphore",
				"proto", ProtoQUIC,
				slogutil.KeyError, err,
			)

			break
		}
		go func() {
			defer reqSema.Release()

			p.handleQUICConnection(conn, reqSema)
		}()
	}
}

// logQUICError writes suitable log message for the given err.
func logQUICError(ctx context.Context, prefix string, err error, l *slog.Logger) {
	if isQUICErrorForDebugLog(err) {
		l.DebugContext(
			ctx,
			"closed or timed out",
			slogutil.KeyPrefix, prefix,
			slogutil.KeyError, err,
		)
	} else {
		l.ErrorContext(ctx, prefix, slogutil.KeyError, err)
	}
}

// handleQUICConnection handles a new QUIC connection.  It waits for new streams
// and passes them to handleQUICStream.
//
// See also the comment on Proxy.requestsSema.
func (p *Proxy) handleQUICConnection(conn quic.Connection, reqSema syncutil.Semaphore) {
	for {
		ctx := context.Background()

		// The stub to resolver DNS traffic follows a simple pattern in which
		// the client sends a query, and the server provides a response.  This
		// design specifies that for each subsequent query on a QUIC connection
		// the client MUST select the next available client-initiated
		// bidirectional stream.
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			logQUICError(ctx, "accepting quic stream", err, p.logger)

			// Close the connection to make sure resources are freed.
			closeQUICConn(conn, DoQCodeNoError, p.logger)

			return
		}

		err = reqSema.Acquire(ctx)
		if err != nil {
			p.logger.ErrorContext(ctx, "acquiring semaphore", slogutil.KeyError, err)

			// Close the connection to make sure resources are freed.
			closeQUICConn(conn, DoQCodeNoError, p.logger)

			return
		}
		go func() {
			defer reqSema.Release()

			p.handleQUICStream(ctx, stream, conn)

			// The server MUST send the response(s) on the same stream and MUST
			// indicate, after the last response, through the STREAM FIN
			// mechanism that no further data will be sent on that stream.
			_ = stream.Close()
		}()
	}
}

// handleQUICStream reads DNS queries from the stream, processes them,
// and writes back the response.
func (p *Proxy) handleQUICStream(ctx context.Context, stream quic.Stream, conn quic.Connection) {
	bufPtr := p.bytesPool.Get().(*[]byte)
	defer p.bytesPool.Put(bufPtr)

	// One query - one stream.
	// The client MUST select the next available client-initiated bidirectional
	// stream for each subsequent query on a QUIC connection.

	// err is not checked here because STREAM FIN sent by the client is
	// indicated as error here.  Instead, we should check the number of bytes
	// received.
	buf := *bufPtr
	n, err := readAll(stream, buf)

	// Note that io.EOF does not really mean that there's any error, this is
	// just a signal that there will be no data to read anymore from this
	// stream.
	if (err != nil && err != io.EOF) || n < minDNSPacketSize {
		logShortQUICRead(ctx, err, p.logger)

		return
	}

	// In theory, we should use ALPN to get the DoQ version properly. However,
	// since there are not too many versions now, we only check how the DNS
	// query is encoded. If it's sent with a 2-byte prefix, we consider this a
	// DoQ v1. Otherwise, a draft version.
	doqVersion := DoQv1
	req := &dns.Msg{}

	// Note that we support both the old drafts and the new RFC. In the old
	// draft DNS messages were not prefixed with the message length.
	packetLen := binary.BigEndian.Uint16(buf[:2])
	if packetLen == uint16(n-2) {
		err = req.Unpack(buf[2:])
	} else {
		err = req.Unpack(buf)
		doqVersion = DoQv1Draft
	}

	if err != nil {
		p.logger.ErrorContext(ctx, "unpacking quic packet", slogutil.KeyError, err)
		closeQUICConn(conn, DoQCodeProtocolError, p.logger)

		return
	}

	if !validQUICMsg(req, p.logger) {
		// If a peer encounters such an error condition, it is considered a
		// fatal error. It SHOULD forcibly abort the connection using QUIC's
		// CONNECTION_CLOSE mechanism and SHOULD use the DoQ error code
		// DOQ_PROTOCOL_ERROR.
		closeQUICConn(conn, DoQCodeProtocolError, p.logger)

		return
	}

	d := p.newDNSContext(ProtoQUIC, req, netutil.NetAddrToAddrPort(conn.RemoteAddr()))
	d.QUICStream = stream
	d.QUICConnection = conn
	d.DoQVersion = doqVersion

	err = p.handleDNSRequest(d)
	if err != nil {
		p.logger.DebugContext(
			ctx,
			"error handling dns request",
			"proto", d.Proto,
			slogutil.KeyError, err,
		)
	}
}

// respondQUIC writes a response to the QUIC stream.
func (p *Proxy) respondQUIC(d *DNSContext) error {
	resp := d.Res

	if resp == nil {
		// If no response has been written, close the QUIC connection now.
		closeQUICConn(d.QUICConnection, DoQCodeInternalError, p.logger)

		return errors.Error("no response to write")
	}

	bytes, err := resp.Pack()
	if err != nil {
		return fmt.Errorf("couldn't convert message into wire format: %w", err)
	}

	// Depending on the DoQ version with either write a 2-bytes prefixed message
	// or just write the message (for old draft versions).
	var buf []byte
	switch d.DoQVersion {
	case DoQv1:
		buf = proxyutil.AddPrefix(bytes)
	case DoQv1Draft:
		buf = bytes
	default:
		return fmt.Errorf("invalid protocol version: %d", d.DoQVersion)
	}

	n, err := d.QUICStream.Write(buf)
	if err != nil {
		return fmt.Errorf("conn.Write(): %w", err)
	}
	if n != len(buf) {
		return fmt.Errorf("conn.Write() returned with %d != %d", n, len(buf))
	}

	return nil
}

// validQUICMsg validates the incoming DNS message and returns false if
// something is wrong with the message.
func validQUICMsg(req *dns.Msg, l *slog.Logger) (ok bool) {
	// See https://www.rfc-editor.org/rfc/rfc9250.html#name-protocol-errors

	// 1. a client or server receives a message with a non-zero Message ID.
	//
	// We do consciously not validate this case since there are stub proxies
	// that are sending a non-zero Message IDs.

	// 2. a client or server receives a STREAM FIN before receiving all the
	// bytes for a message indicated in the 2-octet length field.
	// 3. a server receives more than one query on a stream
	//
	// These cases are covered earlier when unpacking the DNS message.

	// 4. the client or server does not indicate the expected STREAM FIN after
	// sending requests or responses (see Section 4.2).
	//
	// This is quite problematic to validate this case since this would imply
	// we have to wait until STREAM FIN is arrived before we start processing
	// the message. So we're consciously ignoring this case in this
	// implementation.

	// 5. an implementation receives a message containing the edns-tcp-keepalive
	// EDNS(0) Option [RFC7828] (see Section 5.5.2).
	if opt := req.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			// Check for EDNS TCP keepalive option
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				l.Debug("client sent edns0 tcp keepalive option")

				return false
			}
		}
	}

	// 6. a client or a server attempts to open a unidirectional QUIC stream.
	//
	// This case can only be handled when writing a response.

	// 7. a server receives a "replayable" transaction in 0-RTT data
	//
	// The information necessary to validate this is not exposed by quic-go.

	return true
}

// logShortQUICRead is a logging helper for short reads from a QUIC stream.
func logShortQUICRead(ctx context.Context, err error, l *slog.Logger) {
	if err == nil {
		l.InfoContext(ctx, "quic packet too short for dns query")

		return
	}

	logQUICError(ctx, "reading from quic stream", err, l)
}

const (
	// qCodeNoError is returned when the QUIC connection was gracefully closed
	// and there is no error to signal.
	qCodeNoError = quic.ApplicationErrorCode(quic.NoError)

	// qCodeApplicationErrorError is used for Initial and Handshake packets.
	// This error is considered as non-critical and will not be logged as error.
	qCodeApplicationErrorError = quic.ApplicationErrorCode(quic.ApplicationErrorErrorCode)
)

// isQUICErrorForDebugLog returns true if err is a non-critical error, most
// probably related to the current QUIC implementation. err must not be nil.
//
// TODO(ameshkov): re-test when updating quic-go.
func isQUICErrorForDebugLog(err error) (ok bool) {
	if errors.Is(err, quic.ErrServerClosed) {
		// This error is returned when the QUIC listener was closed by us. This
		// is an expected error, we don't need the detailed logs here.
		return true
	}

	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) &&
		(qAppErr.ErrorCode == qCodeNoError || qAppErr.ErrorCode == qCodeApplicationErrorError) {
		// No need to have detailed logs for these error codes either.
		//
		// TODO(a.garipov): Consider adding other error codes.
		return true
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		// This error is returned on AcceptStream calls when the server rejects
		// 0-RTT for some reason.  This is a common scenario, no need for extra
		// logs.
		return true
	}

	// This error is returned when we're trying to accept a new stream from a
	// connection that had no activity for over than the keep-alive timeout.
	// This is a common scenario, no need for extra logs.
	var qIdleErr *quic.IdleTimeoutError

	return errors.As(err, &qIdleErr)
}

// closeQUICConn quietly closes the QUIC connection.
func closeQUICConn(conn quic.Connection, code quic.ApplicationErrorCode, l *slog.Logger) {
	l.Debug("closing quic conn", "addr", conn.LocalAddr(), "code", code)

	err := conn.CloseWithError(code, "")
	if err != nil {
		l.Debug("closing quic connection", "code", code, slogutil.KeyError, err)
	}
}

// newServerQUICConfig creates *quic.Config populated with the default settings.
// This function is supposed to be used for both DoQ and DoH3 server.
func newServerQUICConfig() (conf *quic.Config) {
	return &quic.Config{
		MaxIdleTimeout:        maxQUICIdleTimeout,
		MaxIncomingStreams:    math.MaxUint16,
		MaxIncomingUniStreams: math.MaxUint16,
		// Enable 0-RTT by default for all connections on the server-side.
		Allow0RTT: true,
	}
}

// quicAddrValidator is a helper struct that holds a small LRU cache of
// addresses for which we do not require address validation.
type quicAddrValidator struct {
	cache gcache.Cache
	ttl   time.Duration
}

// newQUICAddrValidator initializes a new instance of *quicAddrValidator.
func newQUICAddrValidator(cacheSize int, ttl time.Duration) (v *quicAddrValidator) {
	return &quicAddrValidator{
		cache: gcache.New(cacheSize).LRU().Build(),
		ttl:   ttl,
	}
}

// requiresValidation determines if a QUIC Retry packet should be sent by the
// client. This allows the server to verify the client's address but increases
// the latency.
func (v *quicAddrValidator) requiresValidation(addr net.Addr) (ok bool) {
	// addr must be *net.UDPAddr here and if it's not we don't mind panic.
	key := addr.(*net.UDPAddr).IP.String()
	if v.cache.Has(key) {
		return false
	}

	err := v.cache.SetWithExpire(key, true, v.ttl)
	if err != nil {
		// Shouldn't happen, since we don't set a serialization function.
		panic(fmt.Errorf("quic validator: setting cache item: %w", err))
	}

	// Address not found in the cache so return true to make sure the server
	// will require address validation.
	return true
}

// readAll reads from r until an error or io.EOF into the specified buffer buf.
// A successful call returns err == nil, not err == io.EOF.  If the buffer is
// too small, it returns error io.ErrShortBuffer.  This function has some
// similarities to io.ReadAll, but it reads to the specified buffer and not
// allocates (and grows) a new one.  Also, it is completely different from
// io.ReadFull as that one reads the exact number of bytes (buffer length) and
// readAll reads until io.EOF or until the buffer is filled.
func readAll(r io.Reader, buf []byte) (n int, err error) {
	for {
		if n == len(buf) {
			return n, io.ErrShortBuffer
		}

		var read int
		read, err = r.Read(buf[n:])
		n += read

		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return n, err
		}
	}
}
