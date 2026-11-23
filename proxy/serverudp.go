package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/miekg/dns"
)

// initUDPListeners initializes UDP listeners with configured addresses.
func (p *Proxy) initUDPListeners(ctx context.Context) (err error) {
	for _, a := range p.udpListenAddr {
		var pc *net.UDPConn
		pc, sErr := p.listenUDP(ctx, a)
		if sErr != nil {
			return fmt.Errorf("listening on udp addr %s: %w", a, sErr)
		}

		p.udpListen = append(p.udpListen, pc)
	}

	return nil
}

// listenUDP returns a new UDP connection listening on addr.  addr must not be
// nil.
func (p *Proxy) listenUDP(ctx context.Context, addr *net.UDPAddr) (conn *net.UDPConn, err error) {
	addrStr := addr.String()
	p.logger.InfoContext(ctx, "creating udp server socket", "addr", addrStr)

	conf := proxynetutil.ListenConfig(p.logger)

	var packetConn net.PacketConn
	err = p.bindWithRetry(ctx, func() (listenErr error) {
		packetConn, listenErr = conf.ListenPacket(ctx, bootstrap.NetworkUDP, addrStr)

		return listenErr
	})
	if err != nil {
		return nil, fmt.Errorf("listening to udp socket: %w", err)
	}

	// TODO(e.burkov):  Use [errors.WithDeferred] for closing errors.

	var ok bool
	conn, ok = packetConn.(*net.UDPConn)
	if !ok {
		// TODO(e.burkov):  Close the connection.

		return nil, fmt.Errorf("bad conn type: %T(%[1]v)", packetConn)
	}

	if p.udpBufferSize > 0 {
		err = conn.SetReadBuffer(p.udpBufferSize)
		if err != nil {
			p.logClose(ctx, slog.LevelDebug, conn, "closing after failed read buffer size setting")

			return nil, fmt.Errorf("setting udp buf size: %w", err)
		}
	}

	err = proxynetutil.UDPSetOptions(conn)
	if err != nil {
		p.logClose(ctx, slog.LevelDebug, conn, "closing after failed options setting")

		return nil, fmt.Errorf("setting udp opts: %w", err)
	}

	p.logger.InfoContext(ctx, "listening to udp", "addr", conn.LocalAddr())

	return conn, nil
}

// udpReopenMinIvl and udpReopenMaxIvl are the bounds of the exponential
// backoff used to reopen a UDP listener that stopped unexpectedly.
const (
	udpReopenMinIvl = 100 * time.Millisecond
	udpReopenMaxIvl = 10 * time.Second
)

// udpPacketLoop listens for incoming UDP packets and handles them.  conn and
// reqSema must not be nil.  If conn stops working while the proxy is running,
// it is replaced with a new listener on the same address.
//
// See also the comment on [Proxy.requestsSema].
func (p *Proxy) udpPacketLoop(ctx context.Context, conn *net.UDPConn, reqSema syncutil.Semaphore) {
	p.logger.InfoContext(ctx, "entering udp listener loop", "addr", conn.LocalAddr())

	b := make([]byte, dns.MaxMsgSize)
	for conn != nil && p.isStarted() {
		n, localIP, remoteAddr, err := proxynetutil.UDPRead(conn, b, p.udpOOBSize)
		// The documentation says to handle the packet even if err occurs.
		if n > 0 {
			// Make a copy of all bytes because ReadFrom() will overwrite the
			// contents of b on the next call.  We need that contents to sustain
			// the call because we're handling them in goroutines.
			packet := make([]byte, n)
			copy(packet, b)

			sErr := reqSema.Acquire(ctx)
			if sErr != nil {
				p.logger.ErrorContext(
					ctx,
					"acquiring semaphore",
					"proto", ProtoUDP,
					slogutil.KeyError, sErr,
				)

				break
			}
			// conn is replaced if it stops working, so pass the current one.
			go func(c *net.UDPConn) {
				defer reqSema.Release()

				p.udpHandlePacket(ctx, packet, localIP, remoteAddr, c)
			}(conn)
		}

		if err != nil {
			conn = p.handleUDPReadError(ctx, conn, err)
		}
	}
}

// handleUDPReadError handles err returned by a read from conn and returns the
// connection to continue reading from, or nil if the read loop should stop.  A
// timeout leaves the socket usable, so conn is returned.  On any other error,
// conn is closed, unless it is already closed.  If conn was closed by
// Shutdown, nil is returned.  Otherwise, the error is logged and a new listener
// on the same address replaces conn.  conn and err must not be nil.
//
// See https://github.com/AdguardTeam/dnsproxy/issues/525.
func (p *Proxy) handleUDPReadError(
	ctx context.Context,
	conn *net.UDPConn,
	err error,
) (next *net.UDPConn) {
	addr := conn.LocalAddr()
	if !udpReadErrIsFatal(err) {
		p.logger.DebugContext(ctx, "reading from udp timed out", "addr", addr, slogutil.KeyError, err)

		return conn
	}

	if !errors.Is(err, net.ErrClosed) {
		p.logClose(ctx, slog.LevelError, conn, "closing udp listener", "addr", addr)
	}

	// Shutdown closes the listeners and removes them from the list while
	// holding the lock, so this check waits for it to finish.
	if !p.hasUDPListener(conn) {
		p.logger.DebugContext(ctx, "udp listener closed", "addr", addr, slogutil.KeyError, err)

		return nil
	}

	p.logger.ErrorContext(
		ctx,
		"udp listener stopped unexpectedly; reopening",
		"addr", addr,
		slogutil.KeyError, err,
	)

	return p.reopenUDPListener(ctx, conn)
}

// udpReadErrIsFatal returns true if err should stop the UDP read loop.
// Timeouts are not fatal.  err must not be nil.
func udpReadErrIsFatal(err error) (fatal bool) {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}

	return true
}

// reopenUDPListener opens a new UDP listener on the address of the closed
// listener old and puts it in place of old.  It retries with exponential
// backoff until it succeeds or old is closed by Shutdown, in which case it
// returns nil.  old must not be nil.
func (p *Proxy) reopenUDPListener(ctx context.Context, old *net.UDPConn) (conn *net.UDPConn) {
	addr, _ := old.LocalAddr().(*net.UDPAddr)

	ivl := udpReopenMinIvl
	for attempt := 1; ; attempt++ {
		time.Sleep(ivl)
		if !p.hasUDPListener(old) {
			return nil
		}

		var err error
		conn, err = p.listenUDP(ctx, addr)
		if err == nil {
			return p.replaceUDPListener(ctx, old, conn)
		}

		p.logger.WarnContext(
			ctx,
			"reopening udp listener",
			"addr", addr,
			"attempt", attempt,
			slogutil.KeyError, err,
		)

		ivl = min(2*ivl, udpReopenMaxIvl)
	}
}

// hasUDPListener returns true if the proxy is started and conn is one of its
// UDP listeners.  It returns false after conn has been closed by Shutdown.
func (p *Proxy) hasUDPListener(conn *net.UDPConn) (ok bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.started && slices.Contains(p.udpListen, conn)
}

// replaceUDPListener replaces old with conn in the list of UDP listeners so
// that Shutdown closes conn.  If old is not in the list, Shutdown has closed
// it, so conn is closed and nil is returned.  old and conn must not be nil.
func (p *Proxy) replaceUDPListener(ctx context.Context, old, conn *net.UDPConn) (next *net.UDPConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	i := slices.Index(p.udpListen, old)
	if i < 0 {
		p.logClose(ctx, slog.LevelDebug, conn, "closing reopened udp listener")

		return nil
	}

	p.udpListen[i] = conn

	return conn
}

// closeUDPListeners closes conns and appends the occurred errors to errs.  A
// listener that has already been closed after a read error is not an error.
// conns must not contain nil elements.
func closeUDPListeners(errs []error, conns []*net.UDPConn) (res []error) {
	for _, c := range conns {
		err := c.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}

	return errs
}

// udpHandlePacket processes the incoming UDP packet and sends a DNS response.
// conn and raddr must not be nil.  localIP must be valid.
func (p *Proxy) udpHandlePacket(
	ctx context.Context,
	packet []byte,
	localIP netip.Addr,
	raddr *net.UDPAddr,
	conn *net.UDPConn,
) {
	ctx, cancel := p.reqCtx.New(ctx)
	defer cancel()

	l := p.logger.With("raddr", raddr, "laddr", localIP, logKeyProto, ProtoUDP)
	l.DebugContext(ctx, "handling new packet")

	req := &dns.Msg{}
	err := req.Unpack(packet)
	if err != nil {
		if req.MsgHdr == (dns.MsgHdr{}) {
			l.ErrorContext(ctx, "unpacking", slogutil.KeyError, err)

			return
		}

		l.DebugContext(ctx, "unpacking", slogutil.KeyError, err)

		// Dropping a UDP request with a valid header is considered bad practice
		// since it creates a denial-of-service (DoS) vulnerability for the
		// client.  RFC generally recommends replying with FORMERR in such
		// cases.
		//
		// See https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1.
		resp := p.messages.NewMsgFORMERR(req)
		err = p.respondUDP(resp, conn, raddr, localIP)
	} else {
		d := p.newDNSContext(ProtoUDP, req, netutil.NetAddrToAddrPort(raddr))
		d.Conn = conn
		d.localIP = localIP

		err = p.handleDNSRequest(ctx, d)
	}
	if err != nil {
		l.DebugContext(ctx, "handling request", slogutil.KeyError, err)
	}
}

// respondUDP sends the response message to the client.  It does nothing if resp
// is nil.  It returns an error if writing the response fails, or if the number
// of bytes written is not equal to the length of the packed message.  If resp
// is not nil, conn and raddr must not be nil, and laddr must be valid.
func (p *Proxy) respondUDP(
	resp *dns.Msg,
	conn *net.UDPConn,
	raddr *net.UDPAddr,
	laddr netip.Addr,
) (err error) {
	if resp == nil {
		// Do nothing if no response has been written.
		return nil
	}

	bytes, err := resp.Pack()
	if err != nil {
		return fmt.Errorf("packing message: %w", err)
	}

	n, err := proxynetutil.UDPWrite(bytes, conn, raddr, laddr)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}

		return fmt.Errorf("writing message: %w", err)
	}

	return validate.Equal("bytes written", n, len(bytes))
}
