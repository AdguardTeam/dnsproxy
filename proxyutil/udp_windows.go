package proxyutil

import "net"

// UDPGetOOBSize - get max. size of received OOB data
// Does nothing on Windows
func UDPGetOOBSize() int {
	return 0
}

// UDPSetOptions - set options on a UDP socket to be able to receive the necessary OOB data
// Does nothing on Windows
func UDPSetOptions(c *net.UDPConn) error {
	return nil
}

// UDPRead - receive payload from the UDP socket
func UDPRead(c *net.UDPConn, buf []byte, _ int) (int, net.IP, *net.UDPAddr, error) {
	n, addr, err := c.ReadFrom(buf)
	var udpAddr *net.UDPAddr
	if addr != nil {
		udpAddr = addr.(*net.UDPAddr)
	}
	return n, nil, udpAddr, err
}

// UDPWrite - writes to the UDP socket
func UDPWrite(bytes []byte, conn *net.UDPConn, remoteAddr *net.UDPAddr, _ net.IP) (int, error) {
	return conn.WriteTo(bytes, remoteAddr)
}
