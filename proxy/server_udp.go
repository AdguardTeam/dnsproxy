package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

func (p *Proxy) createUDPListeners(ctx context.Context) (err error) {
	for _, a := range p.UDPListenAddr {
		var pc *net.UDPConn
		pc, sErr := p.udpCreate(ctx, a)
		if sErr != nil {
			return fmt.Errorf("listening on udp addr %s: %w", a, sErr)
		}

		p.udpListen = append(p.udpListen, pc)
	}

	return nil
}

// udpCreate - create a UDP listening socket
func (p *Proxy) udpCreate(ctx context.Context, udpAddr *net.UDPAddr) (*net.UDPConn, error) {
	log.Info("dnsproxy: creating udp server socket %s", udpAddr)

	packetConn, err := proxynetutil.ListenConfig().ListenPacket(ctx, "udp", udpAddr.String())
	if err != nil {
		return nil, fmt.Errorf("listening to udp socket: %w", err)
	}

	udpListen := packetConn.(*net.UDPConn)
	if p.Config.UDPBufferSize > 0 {
		err = udpListen.SetReadBuffer(p.Config.UDPBufferSize)
		if err != nil {
			_ = udpListen.Close()

			return nil, fmt.Errorf("setting udp buf size: %w", err)
		}
	}

	err = proxynetutil.UDPSetOptions(udpListen)
	if err != nil {
		_ = udpListen.Close()

		return nil, fmt.Errorf("setting udp opts: %w", err)
	}

	log.Info("dnsproxy: listening to udp://%s", udpListen.LocalAddr())

	return udpListen, nil
}

// udpPacketLoop listens for incoming UDP packets.
//
// See also the comment on Proxy.requestsSema.
func (p *Proxy) udpPacketLoop(conn *net.UDPConn, reqSema syncutil.Semaphore) {
	log.Info("dnsproxy: entering udp listener loop on %s", conn.LocalAddr())

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
				log.Error("dnsproxy: udp: acquiring semaphore: %s", sErr)

				break
			}
			go func() {
				defer reqSema.Release()

				p.udpHandlePacket(packet, localIP, remoteAddr, conn)
			}()
		}

		if err != nil {
			logUDPConnError(err, conn)

			break
		}
	}
}

// logUDPConnError writes suitable log message for given err.
func logUDPConnError(err error, conn *net.UDPConn) {
	if errors.Is(err, net.ErrClosed) {
		log.Debug("dnsproxy: udp connection %s closed", conn.LocalAddr())
	} else {
		log.Error("dnsproxy: reading from udp: %s", err)
	}
}

// udpHandlePacket processes the incoming UDP packet and sends a DNS response
func (p *Proxy) udpHandlePacket(
	packet []byte,
	localIP netip.Addr,
	remoteAddr *net.UDPAddr,
	conn *net.UDPConn,
) {
	log.Debug("dnsproxy: handling new udp packet from %s", remoteAddr)

	req := &dns.Msg{}
	err := req.Unpack(packet)
	if err != nil {
		log.Error("dnsproxy: unpacking udp packet: %s", err)

		return
	}

	d := p.newDNSContext(ProtoUDP, req, netutil.NetAddrToAddrPort(remoteAddr))
	d.Conn = conn
	d.localIP = localIP

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Debug("dnsproxy: handling dns (proto %s) request: %s", d.Proto, err)
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
