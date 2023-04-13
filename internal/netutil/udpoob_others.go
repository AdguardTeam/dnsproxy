//go:build !darwin

package netutil

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// udpMakeOOBWithSrc makes the OOB data with the specified source IP.
func udpMakeOOBWithSrc(ip net.IP) (b []byte) {
	if ip4 := ip.To4(); ip4 != nil {
		return (&ipv4.ControlMessage{
			Src: ip,
		}).Marshal()
	}

	return (&ipv6.ControlMessage{
		Src: ip,
	}).Marshal()
}
