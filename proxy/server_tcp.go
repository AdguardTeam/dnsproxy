package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

func (p *Proxy) createTCPListeners() (err error) {
	for _, a := range p.TCPListenAddr {
		log.Printf("Creating a TCP server socket")

		var tcpListen *net.TCPListener
		tcpListen, err = net.ListenTCP("tcp", a)
		if err != nil {
			return fmt.Errorf("starting listening on tcp socket: %w", err)
		}

		p.tcpListen = append(p.tcpListen, tcpListen)
		log.Printf("Listening to tcp://%s", tcpListen.Addr())
	}

	return nil
}

func (p *Proxy) createTLSListeners() (err error) {
	for _, a := range p.TLSListenAddr {
		log.Printf("Creating a TLS server socket")

		var tcpListen *net.TCPListener
		tcpListen, err = net.ListenTCP("tcp", a)
		if err != nil {
			return fmt.Errorf("starting tls listener: %w", err)
		}

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
			if errors.Is(err, net.ErrClosed) {
				log.Debug("tcpPacketLoop: connection closed: %s", err)
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

// handleTCPConnection starts a loop that handles an incoming TCP connection.
// proto must be either ProtoTCP or ProtoTLS.
func (p *Proxy) handleTCPConnection(conn net.Conn, proto Proto) {
	defer log.OnPanic("proxy.handleTCPConnection")

	log.Tracef("handling tcp: started handling %s request from %s", proto, conn.RemoteAddr())
	defer func() {
		err := conn.Close()
		if err != nil {
			logWithNonCrit(err, "handling tcp: closing conn")
		}
	}()

	for {
		p.RLock()
		if !p.started {
			return
		}
		p.RUnlock()

		err := conn.SetDeadline(time.Now().Add(defaultTimeout))
		if err != nil {
			// Consider deadline errors non-critical.
			logWithNonCrit(err, "handling tcp: setting deadline")
		}

		packet, err := proxyutil.ReadPrefixed(conn)
		if err != nil {
			logWithNonCrit(err, "handling tcp: reading msg")

			break
		}

		req := &dns.Msg{}
		err = req.Unpack(packet)
		if err != nil {
			log.Error("handling tcp: unpacking msg: %s", err)

			return
		}

		d := p.newDNSContext(proto, req)
		d.Addr = conn.RemoteAddr()
		d.Conn = conn

		err = p.handleDNSRequest(d)
		if err != nil {
			log.Error("handling tcp: handling %s request: %s", d.Proto, err)
		}
	}
}

// logWithNonCrit logs the error on the appropriate level depending on whether
// err is a critical error or not.
func logWithNonCrit(err error, msg string) {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		log.Debug("%s: connection is closed; original error: %s", msg, err)
	} else if netErr := net.Error(nil); errors.As(err, &netErr) && netErr.Timeout() {
		log.Debug("%s: connection timed out; original error: %s", msg, err)
	} else {
		log.Error("%s: %s", msg, err)
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
		return fmt.Errorf("packing message: %w", err)
	}

	err = proxyutil.WritePrefixed(bytes, conn)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("writing message: %w", err)
	}

	return nil
}
