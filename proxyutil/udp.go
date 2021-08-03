package proxyutil

import "net"

// UDPGetOOBSize returns maximum size of the received OOB data.
func UDPGetOOBSize() (oobSize int) {
	return udpGetOOBSize()
}

// UDPSetOptions sets flag options on a UDP socket to be able to receive the
// necessary OOB data.
func UDPSetOptions(c *net.UDPConn) (err error) {
	return udpSetOptions(c)
}

// UDPRead udpRead reads the message from c using buf receives payload of size
// udpOOBSize from the UDP socket.  It returns the number of bytes copied into
// buf, the number of bytes copied with OOB and the source address of the
// message.
func UDPRead(
	c *net.UDPConn,
	buf []byte,
	udpOOBSize int,
) (n int, localIP net.IP, remoteAddr *net.UDPAddr, err error) {
	return udpRead(c, buf, udpOOBSize)
}

// UDPWrite writes the data to the remoteAddr using conn.
func UDPWrite(
	data []byte,
	conn *net.UDPConn,
	remoteAddr *net.UDPAddr,
	localIP net.IP,
) (n int, err error) {
	return udpWrite(data, conn, remoteAddr, localIP)
}
