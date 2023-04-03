// Package netutil contains network-related utilities common among dnsproxy
// packages.
//
// TODO(a.garipov): Move improved versions of these into netutil in module
// golibs.
package netutil

import (
	"net"

	glnetutil "github.com/AdguardTeam/golibs/netutil"
	"golang.org/x/exp/slices"
)

// SortIPAddrs sorts addrs in accordance with the protocol preferences.  Invalid
// addresses are sorted near the end.  Zones are ignored.
//
// TODO(a.garipov): Use netip.Addr instead of net.IPAddr everywhere where this
// is called.
func SortIPAddrs(addrs []net.IPAddr, preferIPv6 bool) {
	l := len(addrs)
	if l <= 1 {
		return
	}

	slices.SortStableFunc(addrs, func(addrA, addrB net.IPAddr) (sortsBefore bool) {
		// Assume that len(addrs) is mostly small, so these conversions aren't
		// as expensive as they could have been.
		a, err := glnetutil.IPToAddrNoMapped(addrA.IP)
		if err != nil {
			return false
		}

		b, err := glnetutil.IPToAddrNoMapped(addrB.IP)
		if err != nil {
			return false
		}

		aIs4 := a.Is4()
		bIs4 := b.Is4()
		if aIs4 != bIs4 {
			if aIs4 {
				return !preferIPv6
			}

			return preferIPv6
		}

		return a.Less(b)
	})
}
