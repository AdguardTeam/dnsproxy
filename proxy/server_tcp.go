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
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

func (p *Proxy) createTCPListeners(ctx context.Context) (err error) {
	for _, a := range p.TCPListenAddr {
		p.logger.Info("creating tcp server socket", "addr", a)

		lsnr, lErr := proxynetutil.ListenConfig().Listen(ctx, "tcp", a.String())
		if lErr != nil {
			return fmt.Errorf("listening to tcp socket: %w", lErr)
		}

		tcpListener, ok := lsnr.(*net.TCPListener)
		if !ok {
			return fmt.Errorf("wrong listener type on tcp addr %s: %T", a, lsnr)
		}

		p.tcpListen = append(p.tcpListen, tcpListener)

		p.logger.Info("listening to tcp", "addr", tcpListener.Addr())
	}

	return nil
}

func (p *Proxy) createTLSListeners() (err error) {
	for _, a := range p.TLSListenAddr {
		p.logger.Info("creating tls server socket", "addr", a)

		var tcpListen *net.TCPListener
		tcpListen, err = net.ListenTCP("tcp", a)
		if err != nil {
			return fmt.Errorf("listening on tls addr %s: %w", a, err)
		}

		l := tls.NewListener(tcpListen, p.TLSConfig)
		p.tlsListen = append(p.tlsListen, l)

		p.logger.Info("listening to tls", "addr", l.Addr())
	}

	return nil
}

// tcpPacketLoop listens for incoming TCP packets.  proto must be either
// [ProtoTCP] or [ProtoTLS].
//
// See also the comment on Proxy.requestsSema.
func (p *Proxy) tcpPacketLoop(l net.Listener, proto Proto, reqSema syncutil.Semaphore) {
	p.logger.Info("entering listener loop", "proto", proto, "addr", l.Addr())

	for {
		clientConn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				p.logger.Debug("tcp connection closed", "addr", l.Addr())
			} else {
				p.logger.Error("reading from tcp", slogutil.KeyError, err)
			}

			break
		}

		// TODO(d.kolyshev): Pass and use context from above.
		err = reqSema.Acquire(context.Background())
		if err != nil {
			p.logger.Error("acquiring semaphore", "proto", ProtoTCP, slogutil.KeyError, err)

			break
		}

		go p.handleTCPConnection(clientConn, proto, reqSema)
	}
}

// handleTCPConnection starts a loop that handles an incoming TCP connection.
// proto must be either [ProtoTCP] or [ProtoTLS].
func (p *Proxy) handleTCPConnection(conn net.Conn, proto Proto, reqSema syncutil.Semaphore) {
	defer slogutil.RecoverAndLog(context.TODO(), p.logger)
	defer reqSema.Release()
	defer func() {
		err := conn.Close()
		if err != nil {
			logWithNonCrit(err, "closing conn", ProtoTCP, p.logger)
		}
	}()

	p.logger.Debug("handling new request", "proto", proto, "raddr", conn.RemoteAddr())

	for p.isStarted() {
		err := conn.SetDeadline(time.Now().Add(defaultTimeout))
		if err != nil {
			// Consider deadline errors non-critical.
			logWithNonCrit(err, "setting deadline", ProtoTCP, p.logger)
		}

		req := p.readDNSReq(conn)
		if req == nil {
			return
		}

		d := p.newDNSContext(proto, req, netutil.NetAddrToAddrPort(conn.RemoteAddr()))
		d.Conn = conn

		err = p.handleDNSRequest(d)
		if err != nil {
			logWithNonCrit(err, "handling request", ProtoTCP, p.logger)
		}
	}
}

// readDNSReq returns DNS request message from the given connection or nil if
// it failed to read it.  Properly logs the error if it happened.
func (p *Proxy) readDNSReq(conn net.Conn) (req *dns.Msg) {
	packet, err := readPrefixed(conn)
	if err != nil {
		logWithNonCrit(err, "reading msg", ProtoTCP, p.logger)

		return nil
	}

	req = &dns.Msg{}
	err = req.Unpack(packet)
	if err != nil {
		p.logger.Error("handling tcp; unpacking msg", slogutil.KeyError, err)

		return nil
	}

	return req
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
