//go:build unix

package netutil

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/AdguardTeam/golibs/netutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// These are the set of socket option flags for configuring an IPv[46] UDP
// connection to receive an appropriate OOB data.  For both versions the flags
// are:
//
//   - FlagDst
//   - FlagInterface
const (
	ipv4Flags ipv4.ControlFlags = ipv4.FlagDst | ipv4.FlagInterface
	ipv6Flags ipv6.ControlFlags = ipv6.FlagDst | ipv6.FlagInterface
)

// udpGetOOBSize obtains the destination IP from OOB data.
func udpGetOOBSize() (oobSize int) {
	l4, l6 := len(ipv4.NewControlMessage(ipv4Flags)), len(ipv6.NewControlMessage(ipv6Flags))

	return mathutil.Max(l4, l6)
}

func udpSetOptions(c *net.UDPConn) (err error) {
	err6 := ipv6.NewPacketConn(c).SetControlMessage(ipv6Flags, true)
	err4 := ipv4.NewPacketConn(c).SetControlMessage(ipv4Flags, true)
	if err6 != nil && err4 != nil {
		return fmt.Errorf("failed to call SetControlMessage: ipv4: %v; ipv6: %v", err4, err6)
	}

	return nil
}

func udpGetDstFromOOB(oob []byte) (dst netip.Addr, err error) {
	cm6 := &ipv6.ControlMessage{}
	if cm6.Parse(oob) == nil && cm6.Dst != nil {
		return netutil.IPToAddr(cm6.Dst, netutil.AddrFamilyIPv6)
	}

	cm4 := &ipv4.ControlMessage{}
	if cm4.Parse(oob) == nil && cm4.Dst != nil {
		return netutil.IPToAddr(cm4.Dst, netutil.AddrFamilyIPv4)
	}

	return netip.Addr{}, nil
}

func udpRead(
	c *net.UDPConn,
	buf []byte,
	udpOOBSize int,
) (n int, localIP netip.Addr, remoteAddr *net.UDPAddr, err error) {
	var oobn int
	oob := make([]byte, udpOOBSize)
	n, oobn, _, remoteAddr, err = c.ReadMsgUDP(buf, oob)
	if err != nil {
		return -1, netip.Addr{}, nil, err
	}

	localIP, err = udpGetDstFromOOB(oob[:oobn])
	if err != nil {
		return -1, netip.Addr{}, nil, err
	}

	return n, localIP, remoteAddr, nil
}

func udpWrite(
	data []byte,
	conn *net.UDPConn,
	remoteAddr *net.UDPAddr,
	localIP netip.Addr,
) (n int, err error) {
	n, _, err = conn.WriteMsgUDP(data, udpMakeOOBWithSrc(localIP), remoteAddr)

	return n, err
}
