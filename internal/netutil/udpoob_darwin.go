//go:build darwin

package netutil

import (
	"net"

	"golang.org/x/net/ipv6"
)

// udpMakeOOBWithSrc makes the OOB data with the specified source IP.
func udpMakeOOBWithSrc(ip net.IP) (b []byte) {
	if ip4 := ip.To4(); ip4 != nil {
		// Do not set the IPv4 source address via OOB, because it can cause the
		// address to become unspecified on darwin.
		//
		// See https://github.com/AdguardTeam/AdGuardHome/issues/2807.
		//
		// TODO(e.burkov): Develop a workaround to make it write OOB only when
		// listening on an unspecified address.
		return []byte{}
	}

	return (&ipv6.ControlMessage{
		Src: ip,
	}).Marshal()
}
