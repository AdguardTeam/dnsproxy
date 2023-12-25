// Package netutil contains network-related utilities common among dnsproxy
// packages.
//
// TODO(a.garipov): Move improved versions of these into netutil in module
// golibs.
package netutil

import (
	"net/netip"
	"strings"

	"golang.org/x/exp/slices"
)

// PreferIPv4 compares two addresses, preferring IPv4 addresses over IPv6 ones.
// Invalid addresses are sorted near the end.
func PreferIPv4(a, b netip.Addr) (res int) {
	if !a.IsValid() {
		return 1
	} else if !b.IsValid() {
		return -1
	}

	if aIs4 := a.Is4(); aIs4 == b.Is4() {
		return a.Compare(b)
	} else if aIs4 {
		return -1
	}

	return 1
}

// PreferIPv6 compares two addresses, preferring IPv6 addresses over IPv4 ones.
// Invalid addresses are sorted near the end.
func PreferIPv6(a, b netip.Addr) (res int) {
	if !a.IsValid() {
		return 1
	} else if !b.IsValid() {
		return -1
	}

	if aIs6 := a.Is6(); aIs6 == b.Is6() {
		return a.Compare(b)
	} else if aIs6 {
		return -1
	}

	return 1
}

// SortNetIPAddrs sorts addrs in accordance with the protocol preferences.
// Invalid addresses are sorted near the end.  Zones are ignored.
func SortNetIPAddrs(addrs []netip.Addr, preferIPv6 bool) {
	l := len(addrs)
	if l <= 1 {
		return
	}

	slices.SortStableFunc(addrs, func(addrA, addrB netip.Addr) (res int) {
		if !addrA.IsValid() {
			return 1
		} else if !addrB.IsValid() {
			return -1
		}

		aIs4, bIs4 := addrA.Is4(), addrB.Is4()
		if aIs4 == bIs4 {
			return addrA.Compare(addrB)
		}

		if aIs4 {
			if preferIPv6 {
				return 1
			}

			return -1
		}

		if preferIPv6 {
			return -1
		}

		return 1
	})
}

// ParseSubnet parses s either as a CIDR prefix itself, or as an IP address,
// returning the corresponding single-IP CIDR prefix.
//
// TODO(e.burkov):  Move to golibs.
func ParseSubnet(s string) (p netip.Prefix, err error) {
	if strings.Contains(s, "/") {
		p, err = netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
	} else {
		var ip netip.Addr
		ip, err = netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}

		p = netip.PrefixFrom(ip, ip.BitLen())
	}

	return p, nil
}
