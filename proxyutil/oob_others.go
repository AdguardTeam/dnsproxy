//go:build aix || dragonfly || linux || netbsd || openbsd || freebsd || solaris
// +build aix dragonfly linux netbsd openbsd freebsd solaris

package proxyutil

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// udpMakeOOBWithSrc makes the OOB data with a specified source IP.
func udpMakeOOBWithSrc(ip net.IP) []byte {
	if ip4 := ip.To4(); ip4 != nil {
		return (&ipv4.ControlMessage{
			Src: ip,
		}).Marshal()
	}

	return (&ipv6.ControlMessage{
		Src: ip,
	}).Marshal()
}
