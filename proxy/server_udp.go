package proxy

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

func (p *Proxy) createUDPListeners() error {
	for _, a := range p.UDPListenAddr {
		udpListen, err := p.udpCreate(a)
		if err != nil {
			return err
		}
		p.udpListen = append(p.udpListen, udpListen)
	}

	return nil
}

// udpCreate - create a UDP listening socket
func (p *Proxy) udpCreate(udpAddr *net.UDPAddr) (*net.UDPConn, error) {
	log.Info("Creating the UDP server socket")
	udpListen, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listening to udp socket: %w", err)
	}

	if p.Config.UDPBufferSize > 0 {
		err = udpListen.SetReadBuffer(p.Config.UDPBufferSize)
		if err != nil {
			_ = udpListen.Close()

			return nil, fmt.Errorf("setting udp buf size: %w", err)
		}
	}

	err = proxyutil.UDPSetOptions(udpListen)
	if err != nil {
		_ = udpListen.Close()

		return nil, fmt.Errorf("setting udp opts: %w", err)
	}

	log.Info("Listening to udp://%s", udpListen.LocalAddr())

	return udpListen, nil
}

// udpPacketLoop listens for incoming UDP packets.
//
// See also the comment on Proxy.requestGoroutinesSema.
func (p *Proxy) udpPacketLoop(conn *net.UDPConn, requestGoroutinesSema semaphore) {
	log.Info("Entering the UDP listener loop on %s", conn.LocalAddr())
	b := make([]byte, dns.MaxMsgSize)
	for {
		p.RLock()
		if !p.started {
			return
		}
		p.RUnlock()

		n, localIP, remoteAddr, err := proxyutil.UDPRead(conn, b, p.udpOOBSize)
		// documentation says to handle the packet even if err occurs, so do that first
		if n > 0 {
			// make a copy of all bytes because ReadFrom() will overwrite contents of b on next call
			// we need the contents to survive the call because we're handling them in goroutine
			packet := make([]byte, n)
			copy(packet, b)
			requestGoroutinesSema.acquire()
			go func() {
				p.udpHandlePacket(packet, localIP, remoteAddr, conn)
				requestGoroutinesSema.release()
			}()
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Debug("udpPacketLoop: connection closed")
			} else {
				log.Error("got error when reading from UDP listen: %s", err)
			}

			break
		}
	}
}

// udpHandlePacket processes the incoming UDP packet and sends a DNS response
func (p *Proxy) udpHandlePacket(packet []byte, localIP net.IP, remoteAddr *net.UDPAddr, conn *net.UDPConn) {
	log.Tracef("Start handling new UDP packet from %s", remoteAddr)

	req := &dns.Msg{}
	err := req.Unpack(packet)
	if err != nil {
		log.Printf("error handling UDP packet: %s", err)
		return
	}

	d := p.newDNSContext(ProtoUDP, req)
	d.Addr = remoteAddr
	d.Conn = conn
	d.localIP = localIP

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
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
	rAddr := d.Addr.(*net.UDPAddr)
	n, err := proxyutil.UDPWrite(bytes, conn, rAddr, d.localIP)
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
