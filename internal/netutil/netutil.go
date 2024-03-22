// Package netutil contains network-related utilities common among dnsproxy
// packages.
//
// TODO(a.garipov): Move improved versions of these into netutil in module
// golibs.
package netutil

import (
	"net/netip"
	"strings"
)

// ParseSubnet parses s either as a CIDR prefix itself, or as an IP address,
// returning the corresponding single-IP CIDR prefix.
//
// TODO(e.burkov):  Replace usages with [netutil.Prefix].
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
