// +build aix darwin dragonfly linux netbsd openbsd solaris freebsd

package proxy

import (
	"net"

	"github.com/joomcode/errorx"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// udpGetOOBSize - get max. size of received OOB data
func udpGetOOBSize() int {
	oob4 := ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface)
	oob6 := ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface)

	if len(oob4) > len(oob6) {
		return len(oob4)
	}
	return len(oob6)
}

// udpSetOptions - set options on a UDP socket to be able to receive the necessary OOB data
func udpSetOptions(c *net.UDPConn) error {
	err6 := ipv6.NewPacketConn(c).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(c).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return errorx.DecorateMany("SetControlMessage: ", err4, err6)
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

// udpRead - receive payload and OOB data from UDP socket
func (p *Proxy) udpRead(c *net.UDPConn, buf []byte) (int, net.IP, *net.UDPAddr, error) {
	var oobn int
	oob := make([]byte, p.udpOOBSize)
	var err error
	var n int
	var remoteAddr *net.UDPAddr
	n, oobn, _, remoteAddr, err = c.ReadMsgUDP(buf, oob)
	if err != nil {
		return -1, nil, nil, err
	}

	localIP := udpGetDstFromOOB(oob[:oobn])
	return n, localIP, remoteAddr, nil
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

func udpWrite(bytes []byte, d *DNSContext) (int, error) {
	conn := d.Conn.(*net.UDPConn)
	rAddr := d.Addr.(*net.UDPAddr)
	n, _, err := conn.WriteMsgUDP(bytes, udpMakeOOBWithSrc(d.localIP), rAddr)
	return n, err
}
