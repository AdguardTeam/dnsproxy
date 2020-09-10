package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

// NextProtoDQ - During connection establishment, DNS/QUIC support is indicated
// by selecting the ALPN token "dq" in the crypto handshake.
const NextProtoDQ = "dq"

func (p *Proxy) createQUICListeners() error {
	for _, a := range p.QUICListenAddr {
		log.Info("Creating a QUIC listener")

		// TODO: find a way to call udpSetOptions
		quicListen, err := quic.ListenAddr(a.String(), p.TLSConfig, nil)
		if err != nil {
			return errorx.Decorate(err, "could not start QUIC listener")
		}
		p.quicListen = append(p.quicListen, quicListen)
		log.Info("Listening to quic://%s", quicListen.Addr())
	}
	return nil
}

// quicPacketLoop listens for incoming TCP packets
// proto is either "tcp" or "tls"
func (p *Proxy) quicPacketLoop(l quic.Listener) {
	log.Info("Entering the DNS-over-QUIC listener loop on %s", l.Addr())
	for {
		session, err := l.Accept(context.Background())
		if err != nil {
			if isQuicConnClosedErr(err) {
				log.Tracef("QUIC connection has been closed")
			} else {
				log.Info("got error when reading from QUIC listen: %s", err)
			}
			break
		} else {
			p.guardMaxGoroutines()
			go func() {
				p.handleQUICSession(session)
				p.freeMaxGoroutines()
			}()
		}
	}
}

// handleQUICSession handles a new QUIC session.
// It waits for new streams and passes it to handleQUICStream
func (p *Proxy) handleQUICSession(session quic.Session) {
	for {
		// The stub to resolver DNS traffic follows a simple pattern in which
		// the client sends a query, and the server provides a response.  This
		// design specifies that for each subsequent query on a QUIC connection
		// the client MUST select the next available client-initiated
		// bidirectional stream
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			if isQuicConnClosedErr(err) {
				log.Tracef("QUIC connection has been closed")
			} else {
				log.Info("got error when accepting a new QUIC stream: %s", err)
			}
			// Close the session to make sure resources are freed
			_ = session.CloseWithError(0, "")
			return
		}
		p.guardMaxGoroutines()
		go func() {
			p.handleQUICStream(stream, session)
			_ = stream.Close()
			p.freeMaxGoroutines()
		}()
	}
}

// handleQUICStream reads DNS queries from the stream, processes them,
// and writes back the responses
func (p *Proxy) handleQUICStream(stream quic.Stream, session quic.Session) {
	var buf []byte
	buf = p.bytesPool.Get().([]byte)

	// Linter says that the argument needs to be pointer-like
	// But it's already pointer-like
	// nolint
	defer p.bytesPool.Put(buf)

	// One query -- one stream
	// The server MUST send the response on the same stream, and MUST indicate through
	// the STREAM FIN mechanism that no further data will be sent on that stream.

	n, err := stream.Read(buf)
	if err != nil {
		if isQuicConnClosedErr(err) {
			log.Tracef("QUIC connection has been closed")
		} else {
			log.Info("got error while reading from a QUIC stream: %v", err)
		}
		return
	}

	// Make sure stream is closed after query has been processed
	defer stream.Close()

	if n < minDNSPacketSize {
		log.Info("too short packet for a DNS query")
		return
	}

	msg := dns.Msg{}
	err = msg.Unpack(buf)
	if err != nil {
		log.Info("failed to unpack a DNS query: %v", err)
	}

	d := &DNSContext{
		Proto:      ProtoQUIC,
		Req:        &msg,
		Addr:       session.RemoteAddr(),
		QUICStream: stream,
	}

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
	}
}

// Writes a response to the QUIC stream
func (p *Proxy) respondQUIC(d *DNSContext) error {
	resp := d.Res

	bytes, err := resp.Pack()
	if err != nil {
		return errorx.Decorate(err, "couldn't convert message into wire format: %s", resp.String())
	}

	n, err := d.QUICStream.Write(bytes)
	if err != nil {
		return errorx.Decorate(err, "conn.Write() returned error")
	}
	if n != len(bytes) {
		return fmt.Errorf("conn.Write() returned with %d != %d", n, len(bytes))
	}
	return nil
}

func isQuicConnClosedErr(err error) bool {
	str := err.Error()

	if strings.Contains(str, "server closed") {
		return true
	}

	if strings.HasSuffix(str, "Application error 0x0") {
		return true
	}

	return false
}
