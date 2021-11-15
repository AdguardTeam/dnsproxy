package proxy

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

// NextProtoDoT is a registered ALPN for DNS-over-TLS.
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
// However, note that we do not use it currently anywhere and do not make it
// mandatory since most of the existing clients do not send any ALPN.
// In the future we might need that for this:
// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-xfr-over-tls
const NextProtoDoT = "dot"

func (p *Proxy) createTCPListeners() error {
	for _, a := range p.TCPListenAddr {
		log.Printf("Creating a TCP server socket")
		tcpListen, err := net.ListenTCP("tcp", a)
		if err != nil {
			return errorx.Decorate(err, "couldn't listen to TCP socket")
		}
		p.tcpListen = append(p.tcpListen, tcpListen)
		log.Printf("Listening to tcp://%s", tcpListen.Addr())
	}
	return nil
}

func (p *Proxy) createTLSListeners() error {
	for _, a := range p.TLSListenAddr {
		log.Printf("Creating a TLS server socket")
		tcpListen, err := net.ListenTCP("tcp", a)
		if err != nil {
			return errorx.Decorate(err, "could not start TLS listener")
		}

		tlsConfig := p.TLSConfig.Clone()
		tlsConfig.NextProtos = []string{NextProtoDoT}

		l := tls.NewListener(tcpListen, p.TLSConfig)
		p.tlsListen = append(p.tlsListen, l)
		log.Printf("Listening to tls://%s", l.Addr())
	}
	return nil
}

// tcpPacketLoop listens for incoming TCP packets.  proto must be either "tcp"
// or "tls".
//
// See also the comment on Proxy.requestGoroutinesSema.
func (p *Proxy) tcpPacketLoop(l net.Listener, proto Proto, requestGoroutinesSema semaphore) {
	log.Printf("Entering the %s listener loop on %s", proto, l.Addr())
	for {
		clientConn, err := l.Accept()

		if err != nil {
			if proxyutil.IsConnClosed(err) {
				log.Tracef("TCP connection has been closed, exiting loop")
			} else {
				log.Info("got error when reading from TCP listen: %s", err)
			}
			break
		} else {
			requestGoroutinesSema.acquire()
			go func() {
				p.handleTCPConnection(clientConn, proto)
				requestGoroutinesSema.release()
			}()
		}
	}
}

// handleTCPConnection starts a loop that handles an incoming TCP connection
// proto is either "tcp" or "tls"
func (p *Proxy) handleTCPConnection(conn net.Conn, proto Proto) {
	log.Tracef("Start handling the new %s connection %s", proto, conn.RemoteAddr())
	defer conn.Close()

	for {
		p.RLock()
		if !p.started {
			return
		}
		p.RUnlock()

		conn.SetDeadline(time.Now().Add(defaultTimeout)) //nolint
		packet, err := proxyutil.ReadPrefixed(conn)
		if err != nil {
			return
		}

		req := &dns.Msg{}
		err = req.Unpack(packet)
		if err != nil {
			log.Info("error handling TCP packet: %s", err)
			return
		}

		d := p.newDNSContext(proto, req)
		d.Addr = conn.RemoteAddr()
		d.Conn = conn

		err = p.handleDNSRequest(d)
		if err != nil {
			log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
		}
	}
}

// Writes a response to the TCP (or TLS) client
func (p *Proxy) respondTCP(d *DNSContext) error {
	resp := d.Res
	conn := d.Conn

	if resp == nil {
		// If no response has been written, close the connection right away
		return conn.Close()
	}

	bytes, err := resp.Pack()
	if err != nil {
		return errorx.Decorate(err, "couldn't convert message into wire format: %s", resp.String())
	}

	err = proxyutil.WritePrefixed(bytes, conn)

	if proxyutil.IsConnClosed(err) {
		return err
	}
	if err != nil {
		return errorx.Decorate(err, "conn.Write() returned error")
	}

	return nil
}
