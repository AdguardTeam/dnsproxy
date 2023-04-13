package proxyutil

import (
	"net"

	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
)

// UDPGetOOBSize returns maximum size of the received OOB data.
//
// Deprecated: This function is deprecated.  Packages in module dnsproxy should
// use internal/netutil.UDPGetOOBSize instead.
func UDPGetOOBSize() (oobSize int) {
	return proxynetutil.UDPGetOOBSize()
}

// UDPSetOptions sets flag options on a UDP socket to be able to receive the
// necessary OOB data.
//
// Deprecated: This function is deprecated.  Packages in module dnsproxy should
// use internal/netutil.UDPSetOptions instead.
func UDPSetOptions(c *net.UDPConn) (err error) {
	return proxynetutil.UDPSetOptions(c)
}

// UDPRead udpRead reads the message from c using buf receives payload of size
// udpOOBSize from the UDP socket.  It returns the number of bytes copied into
// buf, the number of bytes copied with OOB and the source address of the
// message.
//
// Deprecated: This function is deprecated.  Packages in module dnsproxy should
// use internal/netutil.UDPRead instead.
func UDPRead(
	c *net.UDPConn,
	buf []byte,
	udpOOBSize int,
) (n int, localIP net.IP, remoteAddr *net.UDPAddr, err error) {
	return proxynetutil.UDPRead(c, buf, udpOOBSize)
}

// UDPWrite writes the data to the remoteAddr using conn.
//
// Deprecated: This function is deprecated.  Packages in module dnsproxy should
// use internal/netutil.UDPWrite instead.
func UDPWrite(
	data []byte,
	conn *net.UDPConn,
	remoteAddr *net.UDPAddr,
	localIP net.IP,
) (n int, err error) {
	return proxynetutil.UDPWrite(data, conn, remoteAddr, localIP)
}
