package netutil

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

// UDPRead reads the message from conn using buf and receives a control-message
// payload of size udpOOBSize from it.  It returns the number of bytes copied
// into buf and the source address of the message.
func UDPRead(
	conn *net.UDPConn,
	buf []byte,
	udpOOBSize int,
) (n int, localIP net.IP, remoteAddr *net.UDPAddr, err error) {
	return udpRead(conn, buf, udpOOBSize)
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
