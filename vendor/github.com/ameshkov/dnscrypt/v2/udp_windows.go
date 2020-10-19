package dnscrypt

import "net"

// udpGetOOBSize - get max. size of received OOB data
// Does nothing on Windows
func udpGetOOBSize() int {
	return 0
}

// udpSetOptions - set options on a UDP socket to be able to receive the necessary OOB data
// Does nothing on Windows
func udpSetOptions(c *net.UDPConn) error {
	return nil
}

// udpRead - receive payload from the UDP socket
func udpRead(c *net.UDPConn, buf []byte, _ int) (int, net.IP, *net.UDPAddr, error) {
	n, addr, err := c.ReadFrom(buf)
	var udpAddr *net.UDPAddr
	if addr != nil {
		udpAddr = addr.(*net.UDPAddr)
	}
	return n, nil, udpAddr, err
}

// udpWrite - writes to the UDP socket
func udpWrite(bytes []byte, conn *net.UDPConn, remoteAddr *net.UDPAddr, _ net.IP) (int, error) {
	return conn.WriteTo(bytes, remoteAddr)
}
