package proxy

import (
	"context"
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
// Current draft version:
// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02
const NextProtoDQ = "doq-i02"

// compatProtoDQ is a list of ALPN tokens used by a QUIC connection.
// NextProtoDQ is the latest draft version supported by dnsproxy, but it also
// includes previous drafts.
var compatProtoDQ = []string{NextProtoDQ, "doq-i00", "dq", "doq"}

// maxQUICIdleTimeout is maximum QUIC idle timeout.  The default value in
// quic-go is 30 seconds, but our internal tests show that a higher value works
// better for clients written with ngtcp2.
const maxQUICIdleTimeout = 5 * time.Minute

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
		session, err := l.Accept(context.Background())
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
			p.handleQUICSession(session, requestGoroutinesSema)
			requestGoroutinesSema.release()
		}()
	}
}

// handleQUICSession handles a new QUIC session.  It waits for new streams and
// passes them to handleQUICStream.
//
// See also the comment on Proxy.requestGoroutinesSema.
func (p *Proxy) handleQUICSession(session quic.Session, requestGoroutinesSema semaphore) {
	for {
		// The stub to resolver DNS traffic follows a simple pattern in which
		// the client sends a query, and the server provides a response.  This
		// design specifies that for each subsequent query on a QUIC connection
		// the client MUST select the next available client-initiated
		// bidirectional stream
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			if isQUICNonCrit(err) {
				log.Tracef("quic connection closed or timeout: %s", err)
			} else {
				log.Info("got error when accepting a new QUIC stream: %s", err)
			}

			// Close the session to make sure resources are freed
			_ = session.CloseWithError(0, "")

			return
		}

		requestGoroutinesSema.acquire()
		go func() {
			p.handleQUICStream(stream, session)
			_ = stream.Close()
			requestGoroutinesSema.release()
		}()
	}
}

// handleQUICStream reads DNS queries from the stream, processes them,
// and writes back the responses
func (p *Proxy) handleQUICStream(stream quic.Stream, session quic.Session) {
	bufPtr := p.bytesPool.Get().(*[]byte)
	defer p.bytesPool.Put(bufPtr)

	// One query -- one stream
	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.

	// err is not checked here because STREAM FIN sent by the client is indicated as error here.
	// instead, we should check the number of bytes received.
	buf := *bufPtr
	n, err := proxyutil.ReadPrefixedQUIC(stream, buf)

	// The server MUST send the response on the same stream, and MUST indicate through
	// the STREAM FIN mechanism that no further data will be sent on that stream.
	defer stream.Close()

	if n < minDNSPacketSize {
		logShortQUICRead(err)

		return
	}

	req := &dns.Msg{}
	err = req.Unpack(buf)
	if err != nil {
		log.Error("unpacking quic packet: %s", err)

		return
	}

	// If any message sent on a DoQ connection contains an edns-tcp-keepalive EDNS(0) Option,
	// this is a fatal error and the recipient of the defective message MUST forcibly abort
	// the connection immediately.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.6.2
	if opt := req.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			// Check for EDNS TCP keepalive option
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				log.Debug("client sent EDNS0 TCP keepalive option")
				errorCode := quic.ApplicationErrorCode(quic.ConnectionRefused)

				// Already closing the connection so we don't care about the error.
				_ = session.CloseWithError(errorCode, "")
				return
			}
		}
	}

	d := p.newDNSContext(ProtoQUIC, req)
	d.Addr = session.RemoteAddr()
	d.QUICStream = stream
	d.QUICSession = session

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
	}
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

// Writes a response to the QUIC stream
func (p *Proxy) respondQUIC(d *DNSContext) error {
	resp := d.Res

	if resp == nil {
		// If no response has been written, close the QUIC session right away.
		errorCode := quic.ApplicationErrorCode(quic.InternalError)
		return d.QUICSession.CloseWithError(errorCode, "")
	}

	bytes, err := resp.Pack()
	if err != nil {
		return fmt.Errorf("couldn't convert message into wire format: %w", err)
	}

	n, err := proxyutil.WritePrefixedQUIC(bytes, d.QUICStream)
	if err != nil {
		return fmt.Errorf("conn.Write(): %w", err)
	}
	if n != len(bytes) {
		return fmt.Errorf("conn.Write() returned with %d != %d", n, len(bytes))
	}

	return nil
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
