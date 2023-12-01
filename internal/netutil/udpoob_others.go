//go:build !darwin

package netutil

import (
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// udpMakeOOBWithSrc makes the OOB data with the specified source IP.
func udpMakeOOBWithSrc(ip netip.Addr) (b []byte) {
	if ip.Is4() {
		return (&ipv4.ControlMessage{
			Src: ip.AsSlice(),
		}).Marshal()
	}

	return (&ipv6.ControlMessage{
		Src: ip.AsSlice(),
	}).Marshal()
}
