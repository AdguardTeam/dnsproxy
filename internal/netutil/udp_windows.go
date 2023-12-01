//go:build windows

package netutil

import (
	"net"
	"net/netip"
)

func udpGetOOBSize() int {
	return 0
}

func udpSetOptions(c *net.UDPConn) error {
	return nil
}

func udpRead(c *net.UDPConn, buf []byte, _ int) (int, netip.Addr, *net.UDPAddr, error) {
	n, addr, err := c.ReadFrom(buf)
	var udpAddr *net.UDPAddr
	if addr != nil {
		udpAddr = addr.(*net.UDPAddr)
	}

	return n, netip.Addr{}, udpAddr, err
}

func udpWrite(bytes []byte, conn *net.UDPConn, remoteAddr *net.UDPAddr, _ netip.Addr) (int, error) {
	return conn.WriteTo(bytes, remoteAddr)
}
