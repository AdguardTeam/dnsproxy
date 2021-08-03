//go:build aix || dragonfly || linux || netbsd || openbsd || freebsd || solaris || darwin
// +build aix dragonfly linux netbsd openbsd freebsd solaris darwin

package proxyutil

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ipv*Flags is the set of socket option flags for configuring IPv* UDP
// connection to receive an appropriate OOB data.  For both versions the flags
// are:
//
//   FlagDst
//   FlagInterface
//
const (
	ipv4Flags ipv4.ControlFlags = ipv4.FlagDst | ipv4.FlagInterface
	ipv6Flags ipv6.ControlFlags = ipv6.FlagDst | ipv6.FlagInterface
)

// udpGetOOBSize obtains the destination IP from OOB data.
func udpGetOOBSize() (oobSize int) {
	l4, l6 :=
		len(ipv4.NewControlMessage(ipv4Flags)),
		len(ipv6.NewControlMessage(ipv6Flags))

	if l4 >= l6 {
		return l4
	}

	return l6
}

func udpSetOptions(c *net.UDPConn) (err error) {
	err6 := ipv6.NewPacketConn(c).SetControlMessage(ipv6Flags, true)
	err4 := ipv4.NewPacketConn(c).SetControlMessage(ipv4Flags, true)
	if err6 != nil && err4 != nil {
		return fmt.Errorf("failed to call SetControlMessage: ipv4: %v; ipv6: %v", err4, err6)
	}

	return nil
}

func udpGetDstFromOOB(oob []byte) (dst net.IP) {
	cm6 := &ipv6.ControlMessage{}
	if cm6.Parse(oob) == nil && cm6.Dst != nil {
		return cm6.Dst
	}

	cm4 := &ipv4.ControlMessage{}
	if cm4.Parse(oob) == nil && cm4.Dst != nil {
		return cm4.Dst
	}

	return nil
}

func udpRead(
	c *net.UDPConn,
	buf []byte,
	udpOOBSize int,
) (n int, localIP net.IP, remoteAddr *net.UDPAddr, err error) {
	var oobn int
	oob := make([]byte, udpOOBSize)
	n, oobn, _, remoteAddr, err = c.ReadMsgUDP(buf, oob)
	if err != nil {
		return -1, nil, nil, err
	}

	localIP = udpGetDstFromOOB(oob[:oobn])

	return n, localIP, remoteAddr, nil
}

func udpWrite(
	data []byte,
	conn *net.UDPConn,
	remoteAddr *net.UDPAddr,
	localIP net.IP,
) (n int, err error) {
	n, _, err = conn.WriteMsgUDP(data, udpMakeOOBWithSrc(localIP), remoteAddr)

	return n, err
}
