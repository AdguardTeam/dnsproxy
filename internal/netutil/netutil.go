// Package netutil contains network-related utilities common among dnsproxy
// packages.
//
// TODO(a.garipov): Move improved versions of these into netutil in module
// golibs.
package netutil

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/AdguardTeam/golibs/netutil"
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

// ExtractARPASubnet tries to convert a reversed ARPA address being a part of
// domain to an IP network.  domain must be an FQDN.
//
// TODO(e.burkov):  !! write tests.
func ExtractARPASubnet(domain string) (pref netip.Prefix, err error) {
	err = netutil.ValidateDomainName(strings.TrimSuffix(domain, "."))
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return netip.Prefix{}, err
	}

	const (
		v4Suffix = "in-addr.arpa."
		v6Suffix = "ip6.arpa."
	)

	domain = strings.ToLower(domain)

	var idx int
	switch {
	case strings.HasSuffix(domain, v4Suffix):
		idx = indexFirstV4Label(domain[:len(domain)-len(v4Suffix)])
	case strings.HasSuffix(domain, v6Suffix):
		idx = indexFirstV6Label(domain[:len(domain)-len(v6Suffix)])
	default:
		return netip.Prefix{}, &netutil.AddrError{
			Err:  netutil.ErrNotAReversedSubnet,
			Kind: netutil.AddrKindARPA,
			Addr: domain,
		}
	}

	return netutil.PrefixFromReversedAddr(domain[idx:])
}

// indexFirstV4Label returns the index at which the reversed IPv4 address
// starts, assuming the domain is pre-validated ARPA domain having in-addr and
// arpa labels removed.
func indexFirstV4Label(domain string) (idx int) {
	idx = len(domain)
	for labelsNum := 0; labelsNum < net.IPv4len && idx > 0; labelsNum++ {
		curIdx := strings.LastIndexByte(domain[:idx-1], '.') + 1
		_, parseErr := strconv.ParseUint(domain[curIdx:idx-1], 10, 8)
		if parseErr != nil {
			return idx
		}

		idx = curIdx
	}

	return idx
}

// indexFirstV6Label returns the index at which the reversed IPv6 address
// starts, assuming the domain is pre-validated ARPA domain having ip6 and arpa
// labels removed.
func indexFirstV6Label(domain string) (idx int) {
	idx = len(domain)
	for labelsNum := 0; labelsNum < net.IPv6len*2 && idx > 0; labelsNum++ {
		curIdx := idx - len("a.")
		if curIdx > 1 && domain[curIdx-1] != '.' {
			return idx
		}

		nibble := domain[curIdx]
		if (nibble < '0' || nibble > '9') && (nibble < 'a' || nibble > 'f') {
			return idx
		}

		idx = curIdx
	}

	return idx
}
