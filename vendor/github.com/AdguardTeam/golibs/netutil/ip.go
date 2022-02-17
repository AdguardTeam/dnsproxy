package netutil

import (
	"net"
	"strings"
)

// IP Address Constants And Utilities

// Bit lengths of IP addresses.
const (
	IPv4BitLen = net.IPv4len * 8
	IPv6BitLen = net.IPv6len * 8
)

// CloneIP returns a clone of an IP address that doesn't share the same
// underlying array with it.
func CloneIP(ip net.IP) (clone net.IP) {
	if ip != nil && len(ip) == 0 {
		return net.IP{}
	}

	return append(clone, ip...)
}

// CloneIPs returns a deep clone of ips.
func CloneIPs(ips []net.IP) (clone []net.IP) {
	if ips == nil {
		return nil
	}

	clone = make([]net.IP, len(ips))
	for i, ip := range ips {
		clone[i] = CloneIP(ip)
	}

	return clone
}

// IPAndPortFromAddr returns the IP address and the port from addr.  If addr is
// neither a *net.TCPAddr nor a *net.UDPAddr, it returns nil and 0.
func IPAndPortFromAddr(addr net.Addr) (ip net.IP, port int) {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return addr.IP, addr.Port
	case *net.UDPAddr:
		return addr.IP, addr.Port
	}

	return nil, 0
}

// IPv4bcast returns a new limited broadcast IPv4 address, 255.255.255.255.  It
// has the same name as the variable in package net, but the result always has
// four bytes.
func IPv4bcast() (ip net.IP) { return net.IP{255, 255, 255, 255} }

// IPv4allsys returns a new all systems (aka all hosts) IPv4 address, 224.0.0.1.
// It has the same name as the variable in package net, but the result always
// has four bytes.
func IPv4allsys() (ip net.IP) { return net.IP{224, 0, 0, 1} }

// IPv4allrouter returns a new all routers IPv4 address, 224.0.0.2.  It has the
// same name as the variable in package net, but the result always has four
// bytes.
func IPv4allrouter() (ip net.IP) { return net.IP{224, 0, 0, 2} }

// IPv4Zero returns a new unspecified (aka empty or null) IPv4 address, 0.0.0.0.
// It has the same name as the variable in package net, but the result always
// has four bytes.
func IPv4Zero() (ip net.IP) { return net.IP{0, 0, 0, 0} }

// IPv6Zero returns a new unspecified (aka empty or null) IPv6 address, [::].
// It has the same name as the variable in package net.
func IPv6Zero() (ip net.IP) {
	return net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

// ParseIP is a wrapper around net.ParseIP that returns a useful error.
//
// Any error returned will have the underlying type of *AddrError.
func ParseIP(s string) (ip net.IP, err error) {
	ip = net.ParseIP(s)
	if ip == nil {
		return nil, &AddrError{
			Kind: AddrKindIP,
			Addr: s,
		}
	}

	return ip, nil
}

// ParseIPv4 is a wrapper around net.ParseIP that makes sure that the parsed IP
// is an IPv4 address and returns a useful error.
//
// Any error returned will have the underlying type of either *AddrError.
func ParseIPv4(s string) (ip net.IP, err error) {
	ip, err = ParseIP(s)
	if err != nil {
		err.(*AddrError).Kind = AddrKindIPv4

		return nil, err
	}

	if ip = ip.To4(); ip == nil {
		return nil, &AddrError{
			Kind: AddrKindIPv4,
			Addr: s,
		}
	}

	return ip, nil
}

// CloneIPNet returns a deep clone of n.
func CloneIPNet(n *net.IPNet) (clone *net.IPNet) {
	if n == nil {
		return nil
	}

	return &net.IPNet{
		IP: CloneIP(n.IP),
		// TODO(e.burkov):  Consider adding CloneIPMask.
		Mask: net.IPMask(CloneIP(net.IP(n.Mask))),
	}
}

// ParseSubnet parses a subnet which can be either a CIDR or a single IP.  In
// the latter case, n is a single-IP subnet.
//
// Any error returned will have the underlying type of either *AddrError.
func ParseSubnet(s string) (n *net.IPNet, err error) {
	var ip net.IP

	// Detect if this is a CIDR or an IP early, so that the path to returning an
	// error is shorter.
	if strings.Contains(s, "/") {
		ip, n, err = net.ParseCIDR(s)
		if err != nil {
			// Don't include the original error here, because it is basically
			// the same as ours but worse and has no additional information.
			return nil, &AddrError{
				Kind: AddrKindCIDR,
				Addr: s,
			}
		}

		n.IP = ip

		return n, nil
	}

	ip, err = ParseIP(s)
	if err != nil {
		return nil, &AddrError{
			Err:  err,
			Kind: AddrKindCIDR,
			Addr: s,
		}
	}

	return SingleIPSubnet(ip), nil
}

// SingleIPSubnet returns an IP network that only contains ip.  If ip is not
// a valid IPv4 or IPv6 address, n is nil.
func SingleIPSubnet(ip net.IP) (n *net.IPNet) {
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{
			IP:   ip4,
			Mask: net.CIDRMask(IPv4BitLen, IPv4BitLen),
		}
	} else if len(ip) == net.IPv6len {
		return &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(IPv6BitLen, IPv6BitLen),
		}
	}

	return nil
}

// ValidateIP returns an error if ip is not a valid IPv4 or IPv6 address.
//
// Any error returned will have the underlying type of *AddrError.
func ValidateIP(ip net.IP) (err error) {
	defer makeAddrError(&err, ip.String(), AddrKindIP)

	switch l := len(ip); l {
	case 0:
		return ErrAddrIsEmpty
	case net.IPv4len, net.IPv6len:
		return nil
	default:
		return &LengthError{
			Kind:    AddrKindIP,
			Allowed: []int{net.IPv4len, net.IPv6len},
			Length:  l,
		}
	}
}
