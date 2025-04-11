package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// initUDPListeners initializes UDP listeners with configured addresses.
func (p *Proxy) initUDPListeners(ctx context.Context) (err error) {
	for _, a := range p.UDPListenAddr {
		var pc *net.UDPConn
		pc, sErr := p.listenUDP(ctx, a)
		if sErr != nil {
			return fmt.Errorf("listening on udp addr %s: %w", a, sErr)
		}

		p.udpListen = append(p.udpListen, pc)
	}

	return nil
}

// listenUDP returns a new UDP connection listening on addr.
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

	if p.Config.UDPBufferSize > 0 {
		err = conn.SetReadBuffer(p.Config.UDPBufferSize)
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

// udpPacketLoop listens for incoming UDP packets.
//
// See also the comment on Proxy.requestsSema.
func (p *Proxy) udpPacketLoop(conn *net.UDPConn, reqSema syncutil.Semaphore) {
	p.logger.Info("entering udp listener loop", "addr", conn.LocalAddr())

	b := make([]byte, dns.MaxMsgSize)
	for p.isStarted() {
		n, localIP, remoteAddr, err := proxynetutil.UDPRead(conn, b, p.udpOOBSize)
		// The documentation says to handle the packet even if err occurs.
		if n > 0 {
			// Make a copy of all bytes because ReadFrom() will overwrite the
			// contents of b on the next call.  We need that contents to sustain
			// the call because we're handling them in goroutines.
			packet := make([]byte, n)
			copy(packet, b)

			// TODO(d.kolyshev): Pass and use context from above.
			sErr := reqSema.Acquire(context.Background())
			if sErr != nil {
				p.logger.Error("acquiring semaphore", "proto", ProtoUDP, slogutil.KeyError, sErr)

				break
			}
			go func() {
				defer reqSema.Release()

				p.udpHandlePacket(packet, localIP, remoteAddr, conn)
			}()
		}

		if err != nil {
			logUDPConnError(err, conn, p.logger)

			break
		}
	}
}

// logUDPConnError writes suitable log message for given err.
func logUDPConnError(err error, conn *net.UDPConn, l *slog.Logger) {
	if errors.Is(err, net.ErrClosed) {
		l.Debug("udp connection closed", "addr", conn.LocalAddr())
	} else {
		l.Error("reading from udp", slogutil.KeyError, err)
	}
}

// udpHandlePacket processes the incoming UDP packet and sends a DNS response
func (p *Proxy) udpHandlePacket(
	packet []byte,
	localIP netip.Addr,
	remoteAddr *net.UDPAddr,
	conn *net.UDPConn,
) {
	p.logger.Debug("handling new udp packet", "raddr", remoteAddr)

	req := &dns.Msg{}
	err := req.Unpack(packet)
	if err != nil {
		p.logger.Error("unpacking udp packet", slogutil.KeyError, err)

		return
	}

	d := p.newDNSContext(ProtoUDP, req, netutil.NetAddrToAddrPort(remoteAddr))
	d.Conn = conn
	d.localIP = localIP

	err = p.handleDNSRequest(d)
	if err != nil {
		p.logger.Debug("handling dns request", "proto", d.Proto, slogutil.KeyError, err)
	}
}

// Writes a response to the UDP client
func (p *Proxy) respondUDP(d *DNSContext) error {
	resp := d.Res

	if resp == nil {
		// Do nothing if no response has been written
		return nil
	}

	bytes, err := resp.Pack()
	if err != nil {
		return fmt.Errorf("packing message: %w", err)
	}

	conn := d.Conn.(*net.UDPConn)
	rAddr := net.UDPAddrFromAddrPort(d.Addr)
	n, err := proxynetutil.UDPWrite(bytes, conn, rAddr, d.localIP)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}

		return fmt.Errorf("writing message: %w", err)
	}

	if n != len(bytes) {
		return fmt.Errorf("udpWrite() returned with %d != %d", n, len(bytes))
	}

	return nil
}
