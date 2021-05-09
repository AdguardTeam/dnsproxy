// +build aix darwin dragonfly linux netbsd openbsd solaris freebsd

package proxyutil

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/golibs/log"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// UDPGetOOBSize - get max. size of received OOB data
// It will then be used in the ReadMsgUDP function
func UDPGetOOBSize() int {
	oob4 := ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface)
	oob6 := ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface)

	if len(oob4) > len(oob6) {
		return len(oob4)
	}
	return len(oob6)
}

// UDPSetOptions - set options on a UDP socket to be able to receive the necessary OOB data
func UDPSetOptions(c *net.UDPConn) error {
	err6 := ipv6.NewPacketConn(c).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(c).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return fmt.Errorf("failed to call SetControlMessage: ipv4: %v ipv6: %v", err4, err6)
	}
	return nil
}

// UDPRead - receive payload and OOB data from the UDP socket
func UDPRead(c *net.UDPConn, buf []byte, udpOOBSize int) (int, net.IP, *net.UDPAddr, error) {
	var oobn int
	oob := make([]byte, udpOOBSize)
	var err error
	var n int
	var remoteAddr *net.UDPAddr
	n, oobn, _, remoteAddr, err = c.ReadMsgUDP(buf, oob)
	if err != nil {
		return -1, nil, nil, err
	}

	b := oob[:oobn]
	log.Info("Received OOB data")
	log.Info("%v", b)

	localIP := udpGetDstFromOOB(oob[:oobn])
	log.Info("Parsed dst IP: %v", localIP)
	return n, localIP, remoteAddr, nil
}

// UDPWrite - writes to the UDP socket and sets local IP to OOB data
func UDPWrite(bytes []byte, conn *net.UDPConn, remoteAddr *net.UDPAddr, localIP net.IP) (int, error) {
	n, _, err := conn.WriteMsgUDP(bytes, udpMakeOOBWithSrc(localIP), remoteAddr)
	return n, err
}

// udpGetDstFromOOB - get destination IP from OOB data
func udpGetDstFromOOB(oob []byte) net.IP {
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

// udpMakeOOBWithSrc - make OOB data with a specified source IP
func udpMakeOOBWithSrc(ip net.IP) []byte {
	if ip.To4() == nil {
		cm := &ipv6.ControlMessage{}
		cm.Src = ip
		return cm.Marshal()
	}

	cm := &ipv4.ControlMessage{}
	cm.Src = ip
	return cm.Marshal()
}
