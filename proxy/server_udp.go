package proxy

import (
	"fmt"
	"net"
	"runtime"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/AdguardTeam/dnsproxy/proxyutil"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
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

// supportsIPv4Mapping returns true if the OS we're running
// supports IPv4 mapping for listening UDP sockets with no issues
// Details: https://github.com/AdguardTeam/AdGuardHome/issues/3015
func (p *Proxy) supportsIPv4Mapping() bool {
	return !(runtime.GOOS == "freebsd" ||
		runtime.GOOS == "openbsd" ||
		runtime.GOOS == "netbsd" ||
		runtime.GOOS == "darwin")
}

// getUDPFamily depending on the IP address it either returns "udp" or "udp4"
// "udp4" is necessary on BSD when we listen to 0.0.0.0, check the details here:
// https://github.com/AdguardTeam/AdGuardHome/issues/3015
func (p *Proxy) getUDPFamily(udpAddr *net.UDPAddr) string {
	if p.supportsIPv4Mapping() {
		return "udp"
	}

	if udpAddr.IP.To4() != nil {
		return "udp4"
	}

	return "udp"
}

// udpCreate creates a UDP listening socket
func (p *Proxy) udpCreate(udpAddr *net.UDPAddr) (*net.UDPConn, error) {
	log.Info("Creating the UDP server socket")
	network := p.getUDPFamily(udpAddr)
	udpListen, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't listen to UDP socket")
	}

	if p.Config.UDPBufferSize > 0 {
		err = udpListen.SetReadBuffer(p.Config.UDPBufferSize)
		if err != nil {
			_ = udpListen.Close()
			return nil, errorx.Decorate(err, "setting UDP buffer size failed")
		}
	}

	err = setUDPSocketOptions(udpListen)
	if err != nil {
		_ = udpListen.Close()
		return nil, errorx.Decorate(err, "udpSetOptions failed")
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

		n, sessionUDP, err := dns.ReadFromSessionUDP(conn, b)

		// documentation says to handle the packet even if err occurs, so do that first
		if n > 0 && sessionUDP != nil {
			// make a copy of all bytes because ReadFrom() will overwrite contents of b on next call
			// we need the contents to survive the call because we're handling them in goroutine
			packet := make([]byte, n)
			copy(packet, b)
			requestGoroutinesSema.acquire()
			go func() {
				// TODO: remove
				log.Info("read from %v", sessionUDP.RemoteAddr())
				p.udpHandlePacket(packet, sessionUDP, conn)
				requestGoroutinesSema.release()
			}()
		}
		if err != nil {
			if proxyutil.IsConnClosed(err) {
				log.Info("udpListen.ReadFrom() returned because we're reading from a closed connection, exiting loop")
			} else {
				log.Info("got error when reading from UDP listen: %s", err)
			}
			break
		}
	}
}

// udpHandlePacket processes the incoming UDP packet and sends a DNS response
func (p *Proxy) udpHandlePacket(packet []byte, sessionUDP *dns.SessionUDP, conn *net.UDPConn) {
	log.Tracef("Start handling new UDP packet from %s", sessionUDP.RemoteAddr())

	msg := &dns.Msg{}
	err := msg.Unpack(packet)
	if err != nil {
		log.Printf("error handling UDP packet: %s", err)
		return
	}

	d := &DNSContext{
		Proto:      ProtoUDP,
		Req:        msg,
		Addr:       sessionUDP.RemoteAddr(),
		Conn:       conn,
		sessionUDP: sessionUDP,
	}

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
	}
}

// Writes a response to the UDP client
func (p *Proxy) respondUDP(d *DNSContext) error {
	resp := d.Res

	bytes, err := resp.Pack()
	if err != nil {
		return errorx.Decorate(err, "couldn't convert message into wire format: %s", resp.String())
	}

	conn := d.Conn.(*net.UDPConn)

	log.Info("write to %v", d.sessionUDP.RemoteAddr())
	n, err := dns.WriteToSessionUDP(conn, bytes, d.sessionUDP)
	if n == 0 && proxyutil.IsConnClosed(err) {
		return err
	}
	if err != nil {
		return errorx.Decorate(err, "udpWrite() returned error")
	}
	if n != len(bytes) {
		return fmt.Errorf("udpWrite() returned with %d != %d", n, len(bytes))
	}
	return nil
}

// setUDPSocketOptions - this is necessary to be able to use dns.ReadFromSessionUDP / dns.WriteToSessionUDP
func setUDPSocketOptions(conn *net.UDPConn) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6 connection.
	// Try enabling receiving of ECN and packet info for both IP versions.
	// We expect at least one of those syscalls to succeed.
	err6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return err4
	}
	return nil
}
