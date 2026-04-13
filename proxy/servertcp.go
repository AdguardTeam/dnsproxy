package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/fcchbjm/dnsproxy/internal/bootstrap"
	proxynetutil "github.com/fcchbjm/dnsproxy/internal/netutil"
	"github.com/miekg/dns"
)

const (
	// tcpGracefulShutdownLinger is a short delay before half-closing a TCP or
	// TLS stream so the peer can read queued data.
	tcpGracefulShutdownLinger = 80 * time.Millisecond

	// tcpReadDrainTimeout bounds how long we wait for the peer to finish the
	// close handshake after CloseWrite.
	tcpReadDrainTimeout = 2 * time.Second
)

// initTCPListeners initializes TCP listeners with configured addresses.
func (p *Proxy) initTCPListeners(ctx context.Context) (err error) {
	for _, addr := range p.TCPListenAddr {
		var ln *net.TCPListener
		ln, err = p.listenTCP(ctx, addr)
		if err != nil {
			return fmt.Errorf("listening on tcp addr %s: %w", addr, err)
		}

		p.tcpListen = append(p.tcpListen, ln)
	}

	return nil
}

// listenTCP returns a new TCP listener listening on addr.
func (p *Proxy) listenTCP(ctx context.Context, addr *net.TCPAddr) (ln *net.TCPListener, err error) {
	addrStr := addr.String()
	p.logger.InfoContext(ctx, "creating tcp server socket", "addr", addrStr)

	conf := proxynetutil.ListenConfig(p.logger)

	var listener net.Listener
	err = p.bindWithRetry(ctx, func() (listenErr error) {
		listener, listenErr = conf.Listen(ctx, bootstrap.NetworkTCP, addrStr)

		return listenErr
	})
	if err != nil {
		return nil, fmt.Errorf("listening to tcp socket: %w", err)
	}

	var ok bool
	ln, ok = listener.(*net.TCPListener)
	if !ok {
		// TODO(e.burkov):  Close the listener.

		return nil, fmt.Errorf("bad listener type: %T", listener)
	}

	p.logger.InfoContext(ctx, "listening to tcp", "addr", ln.Addr())

	return ln, nil
}

// initTLSListeners initializes TLS listeners with configured addresses.
func (p *Proxy) initTLSListeners(ctx context.Context) (err error) {
	for _, addr := range p.TLSListenAddr {
		addrStr := addr.String()
		p.logger.InfoContext(ctx, "creating tls server socket", "addr", addrStr)

		conf := proxynetutil.ListenConfigTLS(p.logger)

		var tcpListen *net.TCPListener
		err = p.bindWithRetry(ctx, func() (listenErr error) {
			var listener net.Listener
			listener, listenErr = conf.Listen(ctx, bootstrap.NetworkTCP, addrStr)
			if listenErr != nil {
				return listenErr
			}

			var ok bool
			tcpListen, ok = listener.(*net.TCPListener)
			if !ok {
				// TODO(e.burkov):  Close the listener.

				return fmt.Errorf("bad listener type: %T", listener)
			}

			return nil
		})
		if err != nil {
			return fmt.Errorf("listening on tls addr %s: %w", addr, err)
		}

		l := tls.NewListener(tcpListen, p.TLSConfig)
		p.tlsListen = append(p.tlsListen, l)

		p.logger.InfoContext(ctx, "listening to tls", "addr", l.Addr())
	}

	return nil
}

// tcpPacketLoop listens for incoming TCP packets.  proto must be either
// [ProtoTCP] or [ProtoTLS].
//
// See also the comment on Proxy.requestsSema.
func (p *Proxy) tcpPacketLoop(
	ctx context.Context,
	l net.Listener,
	proto Proto,
	reqSema syncutil.Semaphore,
) {
	p.logger.InfoContext(ctx, "entering listener loop", "proto", proto, "addr", l.Addr())

	for {
		clientConn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				p.logger.DebugContext(ctx, "tcp connection closed", "addr", l.Addr())
			} else {
				p.logger.ErrorContext(ctx, "reading from tcp", slogutil.KeyError, err)
			}

			break
		}

		err = reqSema.Acquire(ctx)
		if err != nil {
			p.logger.ErrorContext(ctx, "acquiring sema", "proto", proto, slogutil.KeyError, err)

			break
		}

		go p.handleTCPConnection(ctx, clientConn, proto, reqSema)
	}
}

// handleTCPConnection starts a loop that handles an incoming TCP connection.
// proto must be either [ProtoTCP] or [ProtoTLS].
func (p *Proxy) handleTCPConnection(
	ctx context.Context,
	conn net.Conn,
	proto Proto,
	reqSema syncutil.Semaphore,
) {
	defer slogutil.RecoverAndLog(ctx, p.logger)
	defer reqSema.Release()

	var shutdownOnce sync.Once
	clientInitiatedClose := false
	shutdown := func() {
		shutdownOnce.Do(func() {
			p.shutdownTCPConnGracefully(ctx, conn, proto, clientInitiatedClose)
		})
	}

	defer shutdown()

	// Set TCP keepalive
	var rawConn net.Conn = conn

	if tlsConn, ok := conn.(*tls.Conn); ok {
		rawConn = tlsConn.NetConn()
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		err := tcpConn.SetKeepAlive(true)
		if err != nil {
			logWithNonCrit(ctx, err, "setting keepalive", ProtoTCP, p.logger)
		} else {
			err = tcpConn.SetKeepAlivePeriod(defaultTCPKeepAlive)
			if err != nil {
				logWithNonCrit(ctx, err, "setting keepalive period", ProtoTCP, p.logger)
			}
		}
	}

	p.logger.DebugContext(ctx, "handling new request", "proto", proto, "raddr", conn.RemoteAddr())

	ctx, cancel := p.reqCtx.New(ctx)
	defer cancel()

	for p.isStarted() {
		var err error

		switch proto {
		case ProtoTLS:
			// DoT: read deadline only so outbound responses are not tied to the idle
			// read window (avoids premature full-deadline shutdown vs long-lived clients).
			err = conn.SetReadDeadline(time.Now().Add(defaultTLSTimeout))
		default:
			err = conn.SetDeadline(time.Now().Add(defaultTimeout))
		}

		if err != nil {
			// Consider deadline errors non-critical.
			msg := "setting deadline"
			if proto == ProtoTLS {
				msg = "setting read deadline"
			}

			logWithNonCrit(ctx, err, msg, proto, p.logger)
		}

		req, rerr := p.readDNSReq(ctx, conn, proto)
		if rerr != nil {
			// Only treat a confirmed EOF as a peer-initiated graceful shutdown.
			//
			// Do not infer peer shutdown from timeouts or other errors.
			if errors.Is(rerr, io.EOF) {
				clientInitiatedClose = true
			}

			return
		}
		if req == nil {
			return
		}

		d := p.newDNSContext(proto, req, netutil.NetAddrToAddrPort(conn.RemoteAddr()))
		d.Conn = conn
		d.tcpConnShutdown = shutdown

		err = p.handleDNSRequest(ctx, d)
		if err != nil {
			logWithNonCrit(ctx, err, "handling request", proto, p.logger)
		}
	}
}

// readDNSReq returns DNS request message from the given connection or nil if
// it failed to read it.  Properly logs the error if it happened.
func (p *Proxy) readDNSReq(ctx context.Context, conn net.Conn, proto Proto) (req *dns.Msg, err error) {
	packet, err := readPrefixed(conn)
	if err != nil {
		logWithNonCrit(ctx, err, "reading msg", proto, p.logger)

		return nil, err
	}

	req = &dns.Msg{}
	err = req.Unpack(packet)
	if err != nil {
		p.logger.ErrorContext(ctx, "handling tcp; unpacking msg", slogutil.KeyError, err)

		return nil, err
	}

	return req, nil
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

// shutdownTCPConnGracefully closes the connection.  For DNS-over-TLS, avoid
// CloseWrite()+TCP half-close first: that emits server-first FIN and raises tail
// RST risk with some clients in crossed shutdown; tls.Conn.Close sends
// close_notify and releases the socket.  Plain TCP keeps half-close+drain.
func (p *Proxy) shutdownTCPConnGracefully(
	ctx context.Context,
	conn net.Conn,
	proto Proto,
	clientInitiatedClose bool,
) {
	switch c := conn.(type) {
	case *tls.Conn:
		if clientInitiatedClose {
			// The peer has already closed the connection.  Avoid writing TLS
			// records (close_notify) and just close the underlying transport.
			err := c.NetConn().Close()
			if err != nil {
				logWithNonCrit(ctx, err, "closing tls net conn", proto, p.logger)
			}

			return
		}

		err := c.Close()
		if err != nil {
			logWithNonCrit(ctx, err, "closing tls conn", proto, p.logger)
		}
	case *net.TCPConn:
		time.Sleep(tcpGracefulShutdownLinger)
		err := c.CloseWrite()
		if err != nil {
			logWithNonCrit(ctx, err, "tcp close write", proto, p.logger)
		}

		_ = c.SetReadDeadline(time.Now().Add(tcpReadDrainTimeout))

		_, err = io.Copy(io.Discard, c)
		if err != nil && !errors.Is(err, io.EOF) {
			logWithNonCrit(ctx, err, "draining tcp conn", proto, p.logger)
		}

		err = c.Close()
		if err != nil {
			logWithNonCrit(ctx, err, "closing tcp conn", proto, p.logger)
		}
	default:
		err := conn.Close()
		if err != nil {
			logWithNonCrit(ctx, err, "closing conn", proto, p.logger)
		}
	}
}

// Writes a response to the TCP (or TLS) client
func (p *Proxy) respondTCP(d *DNSContext) error {
	resp := d.Res
	conn := d.Conn

	if resp == nil {
		// If no response has been written, close the connection right away.
		if d.tcpConnShutdown != nil {
			d.tcpConnShutdown()

			return nil
		}

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
