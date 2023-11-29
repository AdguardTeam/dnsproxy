package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

func (p *Proxy) createTCPListeners(ctx context.Context) (err error) {
	for _, a := range p.TCPListenAddr {
		log.Info("dnsproxy: creating tcp server socket %s", a)

		lsnr, lErr := proxynetutil.ListenConfig().Listen(ctx, "tcp", a.String())
		if lErr != nil {
			return fmt.Errorf("listening to tcp socket: %w", lErr)
		}

		tcpListener, ok := lsnr.(*net.TCPListener)
		if !ok {
			return fmt.Errorf("wrong listener type on tcp addr %s: %T", a, lsnr)
		}

		p.tcpListen = append(p.tcpListen, tcpListener)

		log.Info("dnsproxy: listening to tcp://%s", tcpListener.Addr())
	}

	return nil
}

func (p *Proxy) createTLSListeners() (err error) {
	for _, a := range p.TLSListenAddr {
		log.Info("dnsproxy: creating tls server socket %s", a)

		var tcpListen *net.TCPListener
		tcpListen, err = net.ListenTCP("tcp", a)
		if err != nil {
			return fmt.Errorf("listening on tls addr %s: %w", a, err)
		}

		l := tls.NewListener(tcpListen, p.TLSConfig)
		p.tlsListen = append(p.tlsListen, l)

		log.Info("dnsproxy: listening to tls://%s", l.Addr())
	}

	return nil
}

// tcpPacketLoop listens for incoming TCP packets.  proto must be either "tcp"
// or "tls".
//
// See also the comment on Proxy.requestGoroutinesSema.
func (p *Proxy) tcpPacketLoop(l net.Listener, proto Proto, requestGoroutinesSema semaphore) {
	log.Info("dnsproxy: entering %s listener loop on %s", proto, l.Addr())

	for {
		clientConn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Debug("dnsproxy: tcp connection %s closed", l.Addr())
			} else {
				log.Error("dnsproxy: reading from tcp: %s", err)
			}

			break
		}

		requestGoroutinesSema.acquire()
		go func() {
			p.handleTCPConnection(clientConn, proto)
			requestGoroutinesSema.release()
		}()
	}
}

// handleTCPConnection starts a loop that handles an incoming TCP connection.
// proto must be either ProtoTCP or ProtoTLS.
func (p *Proxy) handleTCPConnection(conn net.Conn, proto Proto) {
	defer log.OnPanic("proxy.handleTCPConnection")

	log.Debug("dnsproxy: handling new %s request from %s", proto, conn.RemoteAddr())

	defer func() {
		err := conn.Close()
		if err != nil {
			logWithNonCrit(err, "dnsproxy: handling tcp: closing conn")
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

		packet, err := readPrefixed(conn)
		if err != nil {
			logWithNonCrit(err, "handling tcp: reading msg")

			break
		}

		req := &dns.Msg{}
		err = req.Unpack(packet)
		if err != nil {
			log.Error("dnsproxy: handling tcp: unpacking msg: %s", err)

			return
		}

		d := p.newDNSContext(proto, req)
		d.Addr = netutil.NetAddrToAddrPort(conn.RemoteAddr())
		d.Conn = conn

		err = p.handleDNSRequest(d)
		if err != nil {
			logWithNonCrit(err, fmt.Sprintf("handling tcp: handling %s request", d.Proto))
		}
	}
}

// errTooLarge means that a DNS message is larger than 64KiB.
const errTooLarge errors.Error = "dns message is too large"

// readPrefixed reads a DNS message with a 2-byte prefix containing message
// length from conn.
func readPrefixed(conn net.Conn) (b []byte, err error) {
	l := make([]byte, 2)
	_, err = conn.Read(l)
	if err != nil {
		return nil, fmt.Errorf("reading len: %w", err)
	}

	packetLen := binary.BigEndian.Uint16(l)
	if packetLen > dns.MaxMsgSize {
		return nil, errTooLarge
	}

	b = make([]byte, packetLen)
	_, err = io.ReadFull(conn, b)
	if err != nil {
		return nil, fmt.Errorf("reading msg: %w", err)
	}

	return b, nil
}

// logWithNonCrit logs the error on the appropriate level depending on whether
// err is a critical error or not.
func logWithNonCrit(err error, msg string) {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isEPIPE(err) {
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

	err = writePrefixed(bytes, conn)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("writing message: %w", err)
	}

	return nil
}

// writePrefixed writes a DNS message to a TCP connection it first writes
// a 2-byte prefix followed by the message itself.
func writePrefixed(b []byte, conn net.Conn) (err error) {
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(b)))
	_, err = (&net.Buffers{l, b}).WriteTo(conn)

	return err
}
