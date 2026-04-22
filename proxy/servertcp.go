package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
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

	// proxyProtocolV2HeaderLen is the minimal Proxy Protocol v2 header size.
	proxyProtocolV2HeaderLen = 16
)

var proxyProtocolV2Signature = [...]byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

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

		p.tlsListen = append(p.tlsListen, tcpListen)

		p.logger.InfoContext(ctx, "listening to tls", "addr", tcpListen.Addr())
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

	clientAddr := netutil.NetAddrToAddrPort(conn.RemoteAddr())
	conn, clientAddr, err := p.prepareConn(ctx, conn, proto)
	if err != nil {
		logWithNonCrit(ctx, err, "preparing connection", proto, p.logger)

		return
	}

	p.logger.DebugContext(ctx, "handling new request", "proto", proto, "raddr", clientAddr)

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

		d := p.newDNSContext(proto, req, clientAddr)
		d.Conn = conn
		d.tcpConnShutdown = shutdown

		err = p.handleDNSRequest(ctx, d)
		if err != nil {
			logWithNonCrit(ctx, err, "handling request", proto, p.logger)
		}
	}
}

// bufferedConn preserves bytes peeked from the reader while still exposing
// [net.Conn] methods.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read implements [net.Conn].
func (c *bufferedConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

// prepareConn applies Proxy Protocol v2 policy and performs TLS handshake
// where needed.  It returns the effective client address.
func (p *Proxy) prepareConn(
	ctx context.Context,
	conn net.Conn,
	proto Proto,
) (prepared net.Conn, clientAddr netip.AddrPort, err error) {
	clientAddr = netutil.NetAddrToAddrPort(conn.RemoteAddr())
	ppEnabled := p.proxyProtocolV2Enabled(proto)

	if proto != ProtoTCP && proto != ProtoTLS {
		return conn, clientAddr, nil
	}

	// Bound PPv2 detection/parse and (for DoT) the TLS handshake time.
	//
	// Without it, a client can connect and not send anything, blocking the
	// per-connection handler on Peek/ReadFull.
	switch proto {
	case ProtoTLS:
		err = conn.SetReadDeadline(time.Now().Add(defaultTLSTimeout))
	default:
		err = conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	}
	if err != nil {
		logWithNonCrit(ctx, err, "setting initial read deadline", proto, p.logger)
	}

	bconn := &bufferedConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}

	var hasHeader bool
	hasHeader, err = hasProxyProtocolV2Signature(bconn.reader)
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("detecting proxy protocol v2: %w", err)
	}

	if !ppEnabled && hasHeader {
		return nil, netip.AddrPort{}, errors.Error("proxy protocol v2 header is not allowed")
	}

	if ppEnabled && !hasHeader {
		return nil, netip.AddrPort{}, errors.Error("proxy protocol v2 header is required")
	}

	if hasHeader {
		clientAddr, err = p.consumeProxyProtocolV2(ctx, bconn.reader, clientAddr)
		if err != nil {
			return nil, netip.AddrPort{}, err
		}
	}

	if proto != ProtoTLS {
		return bconn, clientAddr, nil
	}

	err = bconn.SetDeadline(time.Now().Add(defaultTLSTimeout))
	if err != nil {
		logWithNonCrit(ctx, err, "setting tls handshake deadline", proto, p.logger)
	}

	tlsConn := tls.Server(bconn, p.TLSConfig)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("tls handshake: %w", err)
	}

	_ = tlsConn.SetDeadline(time.Time{})

	return tlsConn, clientAddr, nil
}

// proxyProtocolV2Enabled returns true if Proxy Protocol v2 is enabled for proto.
func (p *Proxy) proxyProtocolV2Enabled(proto Proto) (ok bool) {
	switch proto {
	case ProtoTCP:
		return p.TCPProxyProtocolV2Enabled
	case ProtoTLS:
		return p.TLSProxyProtocolV2Enabled
	default:
		return false
	}
}

// hasProxyProtocolV2Signature checks if the stream starts with the v2 signature.
func hasProxyProtocolV2Signature(r *bufio.Reader) (ok bool, err error) {
	prefix, err := r.Peek(len(proxyProtocolV2Signature))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}

		return false, fmt.Errorf("peeking signature: %w", err)
	}

	return bytes.Equal(prefix, proxyProtocolV2Signature[:]), nil
}

// consumeProxyProtocolV2 validates and consumes Proxy Protocol v2 header.
func (p *Proxy) consumeProxyProtocolV2(
	ctx context.Context,
	r *bufio.Reader,
	remoteAddr netip.AddrPort,
) (clientAddr netip.AddrPort, err error) {
	if !p.TrustedProxies.Contains(remoteAddr.Addr()) {
		return netip.AddrPort{}, fmt.Errorf("proxy protocol source %s is not trusted", remoteAddr)
	}

	header := make([]byte, proxyProtocolV2HeaderLen)
	_, err = io.ReadFull(r, header)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("reading proxy protocol v2 header: %w", err)
	}

	if !bytes.Equal(header[:len(proxyProtocolV2Signature)], proxyProtocolV2Signature[:]) {
		return netip.AddrPort{}, errors.Error("bad proxy protocol v2 signature")
	}

	verCmd := header[12]
	if verCmd>>4 != 0x2 {
		return netip.AddrPort{}, fmt.Errorf("unsupported proxy protocol version: %d", verCmd>>4)
	}

	cmd := verCmd & 0x0f
	famProto := header[13]
	payloadLen := int(binary.BigEndian.Uint16(header[14:16]))

	payload := make([]byte, payloadLen)
	_, err = io.ReadFull(r, payload)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("reading proxy protocol v2 payload: %w", err)
	}

	switch cmd {
	case 0x00:
		// LOCAL command intentionally preserves the immediate peer address.
		return remoteAddr, nil
	case 0x01:
		// PROXY command.
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported proxy protocol command: %d", cmd)
	}

	addr, parseErr := parseProxyProtocolV2Addr(famProto, payload)
	if parseErr != nil {
		return netip.AddrPort{}, parseErr
	}

	p.logger.DebugContext(ctx, "accepted proxy protocol v2 header", "proxy_addr", remoteAddr, "client_addr", addr)

	return addr, nil
}

// parseProxyProtocolV2Addr extracts source address from Proxy Protocol v2 payload.
func parseProxyProtocolV2Addr(famProto byte, payload []byte) (addr netip.AddrPort, err error) {
	switch famProto >> 4 {
	case 0x1:
		if len(payload) < 12 {
			return netip.AddrPort{}, errors.Error("proxy protocol v2 payload is too short for ipv4")
		}

		src, ok := netip.AddrFromSlice(payload[:4])
		if !ok {
			return netip.AddrPort{}, errors.Error("invalid proxy protocol v2 ipv4 source address")
		}

		port := binary.BigEndian.Uint16(payload[8:10])

		return netip.AddrPortFrom(src.Unmap(), port), nil
	case 0x2:
		if len(payload) < 36 {
			return netip.AddrPort{}, errors.Error("proxy protocol v2 payload is too short for ipv6")
		}

		src, ok := netip.AddrFromSlice(payload[:16])
		if !ok {
			return netip.AddrPort{}, errors.Error("invalid proxy protocol v2 ipv6 source address")
		}

		port := binary.BigEndian.Uint16(payload[32:34])

		return netip.AddrPortFrom(src, port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported proxy protocol v2 address family: %d", famProto>>4)
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
	case *bufferedConn:
		p.shutdownTCPConnGracefully(ctx, c.Conn, proto, clientInitiatedClose)
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
