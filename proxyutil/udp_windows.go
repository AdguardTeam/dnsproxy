//go:build windows
// +build windows

package proxyutil

import "net"

func udpGetOOBSize() int {
	return 0
}

func udpSetOptions(c *net.UDPConn) error {
	return nil
}

func udpRead(c *net.UDPConn, buf []byte, _ int) (int, net.IP, *net.UDPAddr, error) {
	n, addr, err := c.ReadFrom(buf)
	var udpAddr *net.UDPAddr
	if addr != nil {
		udpAddr = addr.(*net.UDPAddr)
	}

	return n, nil, udpAddr, err
}

func udpWrite(bytes []byte, conn *net.UDPConn, remoteAddr *net.UDPAddr, _ net.IP) (int, error) {
	return conn.WriteTo(bytes, remoteAddr)
}
