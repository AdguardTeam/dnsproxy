package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
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

const (
	// DOQCodeNoError is used when the connection or stream needs to be closed,
	// but there is no error to signal.
	DOQCodeNoError quic.ApplicationErrorCode = 0
	// DOQCodeInternalError signals that the DoQ implementation encountered
	// an internal error and is incapable of pursuing the transaction or the
	// connection.
	DOQCodeInternalError quic.ApplicationErrorCode = 1
	// DOQCodeProtocolError signals that the DoQ implementation encountered
	// a protocol error and is forcibly aborting the connection.
	DOQCodeProtocolError quic.ApplicationErrorCode = 2
)

func (p *Proxy) createQUICListeners() error {
	for _, a := range p.QUICListenAddr {
		log.Info("Creating a QUIC listener")
		tlsConfig := p.TLSConfig.Clone()
		tlsConfig.NextProtos = compatProtoDQ
		quicListen, err := quic.ListenAddr(a.String(), tlsConfig, &quic.Config{MaxIdleTimeout: maxQUICIdleTimeout})
		if err != nil {
			return fmt.Errorf("starting quic listener: %w", err)
		}

		p.quicListen = append(p.quicListen, quicListen)
		log.Info("Listening to quic://%s", quicListen.Addr())
	}
	return nil
}

// quicPacketLoop listens for incoming QUIC packets.
//
// See also the comment on Proxy.requestGoroutinesSema.
func (p *Proxy) quicPacketLoop(l quic.Listener, requestGoroutinesSema semaphore) {
	log.Info("Entering the DNS-over-QUIC listener loop on %s", l.Addr())
	for {
		conn, err := l.Accept(context.Background())
		if err != nil {
			if isQUICNonCrit(err) {
				log.Tracef("quic connection closed or timeout: %s", err)
			} else {
				log.Error("reading from quic listen: %s", err)
			}

			break
		}

		requestGoroutinesSema.acquire()
		go func() {
			p.handleQUICConnection(conn, requestGoroutinesSema)
			requestGoroutinesSema.release()
		}()
	}
}

// handleQUICConnection handles a new QUIC connection.  It waits for new streams
// and passes them to handleQUICStream.
//
// See also the comment on Proxy.requestGoroutinesSema.
func (p *Proxy) handleQUICConnection(conn quic.Connection, requestGoroutinesSema semaphore) {
	for {
		// The stub to resolver DNS traffic follows a simple pattern in which
		// the client sends a query, and the server provides a response.  This
		// design specifies that for each subsequent query on a QUIC connection
		// the client MUST select the next available client-initiated
		// bidirectional stream.
		stream, err := conn.AcceptStream(context.Background())

		if err != nil {
			if isQUICNonCrit(err) {
				log.Tracef("quic connection closed or timeout: %s", err)
			} else {
				log.Info("got error when accepting a new QUIC stream: %s", err)
			}

			// Close the connection to make sure resources are freed.
			closeQUICConn(conn, DOQCodeNoError)

			return
		}

		requestGoroutinesSema.acquire()
		go func() {
			p.handleQUICStream(stream, conn)

			// The server MUST send the response(s) on the same stream and MUST
			// indicate, after the last response, through the STREAM FIN
			// mechanism that no further data will be sent on that stream.
			_ = stream.Close()

			requestGoroutinesSema.release()
		}()
	}
}

// handleQUICStream reads DNS queries from the stream, processes them,
// and writes back the response.
func (p *Proxy) handleQUICStream(stream quic.Stream, conn quic.Connection) {
	bufPtr := p.bytesPool.Get().(*[]byte)
	defer p.bytesPool.Put(bufPtr)

	// One query - one stream.
	// The client MUST select the next available client-initiated bidirectional
	// stream for each subsequent query on a QUIC connection.

	// err is not checked here because STREAM FIN sent by the client is
	// indicated as error here.  Instead, we should check the number of bytes
	// received.
	buf := *bufPtr
	n, err := stream.Read(buf)

	if n < minDNSPacketSize {
		logShortQUICRead(err)

		return
	}

	// In theory, we should use ALPN to get the DOQ version properly. However,
	// since there are not too many versions now, we only check how the DNS
	// query is encoded. If it's sent with a 2-byte prefix, we consider this a
	// DoQ v1. Otherwise, a draft version.
	doqVersion := DOQv1
	req := &dns.Msg{}

	// Note that we support both the old drafts and the new RFC. In the old
	// draft DNS messages were not prefixed with the message length.
	packetLen := binary.BigEndian.Uint16(buf[:2])
	if packetLen == uint16(n-2) {
		err = req.Unpack(buf[2:])
	} else {
		err = req.Unpack(buf)
		doqVersion = DOQv1Draft
	}

	if err != nil {
		log.Error("unpacking quic packet: %s", err)
		closeQUICConn(conn, DOQCodeProtocolError)

		return
	}

	if !validQUICMsg(req) {
		// If a peer encounters such an error condition, it is considered a
		// fatal error. It SHOULD forcibly abort the connection using QUIC's
		// CONNECTION_CLOSE mechanism and SHOULD use the DoQ error code
		// DOQ_PROTOCOL_ERROR.
		closeQUICConn(conn, DOQCodeProtocolError)

		return
	}

	d := p.newDNSContext(ProtoQUIC, req)
	d.Addr = conn.RemoteAddr()
	d.QUICStream = stream
	d.QUICConnection = conn
	d.DOQVersion = doqVersion

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
	}
}

// respondQUIC writes a response to the QUIC stream.
func (p *Proxy) respondQUIC(d *DNSContext) error {
	resp := d.Res

	if resp == nil {
		// If no response has been written, close the QUIC connection now.
		closeQUICConn(d.QUICConnection, DOQCodeInternalError)

		return errors.New("no response to write")
	}

	bytes, err := resp.Pack()
	if err != nil {
		return fmt.Errorf("couldn't convert message into wire format: %w", err)
	}

	// Depending on the DoQ version with either write a 2-bytes prefixed message
	// or just write the message (for old draft versions).
	var buf []byte
	switch d.DOQVersion {
	case DOQv1:
		buf = proxyutil.AddPrefix(bytes)
	case DOQv1Draft:
		buf = bytes
	default:
		return fmt.Errorf("invalid protocol version: %d", d.DOQVersion)
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
func validQUICMsg(req *dns.Msg) (ok bool) {
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
				log.Debug("client sent EDNS0 TCP keepalive option")

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
func logShortQUICRead(err error) {
	if err == nil {
		log.Info("quic packet too short for dns query")

		return
	}

	if isQUICNonCrit(err) {
		log.Tracef("quic connection closed or timeout: %s", err)
	} else {
		log.Error("reading from quic stream: %s", err)
	}
}

// isQUICNonCrit returns true if err is a non-critical error, most probably
// a timeout or a closed connection.
//
// TODO(a.garipov): Inspect and rewrite with modern error handling.
func isQUICNonCrit(err error) (ok bool) {
	if err == nil {
		return false
	}

	errStr := err.Error()

	return strings.Contains(errStr, "server closed") ||
		stringutil.ContainsFold(errStr, "no recent network activity") ||
		strings.HasSuffix(errStr, "Application error 0x0") ||
		errStr == "EOF"
}

// closeQUICConn quietly closes the QUIC connection.
func closeQUICConn(conn quic.Connection, code quic.ApplicationErrorCode) {
	err := conn.CloseWithError(code, "")

	if err != nil {
		log.Debug("failed to close QUIC connection: %v", err)
	}
}
