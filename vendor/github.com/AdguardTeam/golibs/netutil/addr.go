// Package netutil contains common utilities for IP, MAC, and other kinds of
// network addresses.
//
// TODO(a.garipov): Add more examples.
package netutil

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
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

// CloneMAC returns a clone of a MAC address.
func CloneMAC(mac net.HardwareAddr) (clone net.HardwareAddr) {
	if mac != nil && len(mac) == 0 {
		return net.HardwareAddr{}
	}

	return append(clone, mac...)
}

// CloneURL returns a deep clone of u.  The User pointer of clone is the same,
// since a *url.Userinfo is effectively an immutable value.
func CloneURL(u *url.URL) (clone *url.URL) {
	if u == nil {
		return nil
	}

	cloneVal := *u

	return &cloneVal
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

// IPv4Zero returns a new unspecified (aka empty or null) IPv4 address, 0.0.0.0.
func IPv4Zero() (ip net.IP) { return net.IP{0, 0, 0, 0} }

// IPv6Zero returns a new unspecified (aka empty or null) IPv6 address, [::].
func IPv6Zero() (ip net.IP) {
	return net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

// IsValidHostInnerRune returns true if r is a valid inner—that is, neither
// initial nor final—rune for a hostname label.
func IsValidHostInnerRune(r rune) (ok bool) {
	return r == '-' || IsValidHostOuterRune(r)
}

// IsValidHostOuterRune returns true if r is a valid initial or final rune for
// a hostname label.
func IsValidHostOuterRune(r rune) (ok bool) {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9')
}

// JoinHostPort is a convenient wrapper for net.JoinHostPort with port of type
// int.
func JoinHostPort(host string, port int) (hostport string) {
	return net.JoinHostPort(host, strconv.Itoa(port))
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

// SplitHostPort is a convenient wrapper for net.SplitHostPort with port of type
// int.
func SplitHostPort(hostport string) (host string, port int, err error) {
	var portStr string
	host, portStr, err = net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}

	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("parsing port: %w", err)
	}

	return host, port, nil
}

// SplitHost is a wrapper for net.SplitHostPort for cases when the hostport may
// or may not contain a port.
func SplitHost(hostport string) (host string, err error) {
	host, _, err = net.SplitHostPort(hostport)
	if err != nil {
		// Check for the missing port error.  If it is that error, just
		// use the host as is.
		//
		// See the source code for net.SplitHostPort.
		const missingPort = "missing port in address"

		addrErr := &net.AddrError{}
		if !errors.As(err, &addrErr) || addrErr.Err != missingPort {
			return "", err
		}

		host = hostport
	}

	return host, nil
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

// ValidateMAC returns an error if mac is not a valid EUI-48, EUI-64, or
// 20-octet InfiniBand link-layer address.
//
// Any error returned will have the underlying type of *AddrError.
func ValidateMAC(mac net.HardwareAddr) (err error) {
	defer makeAddrError(&err, mac.String(), AddrKindMAC)

	switch l := len(mac); l {
	case 0:
		return ErrAddrIsEmpty
	case 6, 8, 20:
		return nil
	default:
		return &LengthError{
			Kind:    AddrKindMAC,
			Allowed: []int{6, 8, 20},
			Length:  l,
		}
	}
}

// MaxDomainLabelLen is the maximum allowed length of a domain name label
// according to RFC 1035.
const MaxDomainLabelLen = 63

// MaxDomainNameLen is the maximum allowed length of a full domain name
// according to RFC 1035.
//
// See also: https://stackoverflow.com/a/32294443/1892060.
const MaxDomainNameLen = 253

// ValidateDomainNameLabel returns an error if label is not a valid label of
// a domain name.  An empty label is considered invalid.
//
// Any error returned will have the underlying type of *AddrError.
func ValidateDomainNameLabel(label string) (err error) {
	defer makeAddrError(&err, label, AddrKindLabel)

	l := len(label)
	if l == 0 {
		return ErrLabelIsEmpty
	} else if l > MaxDomainLabelLen {
		return &LengthError{
			Kind:   AddrKindLabel,
			Max:    MaxDomainLabelLen,
			Length: l,
		}
	}

	if r := rune(label[0]); !IsValidHostOuterRune(r) {
		return &RuneError{
			Kind: AddrKindLabel,
			Rune: r,
		}
	} else if l == 1 {
		return nil
	}

	for _, r := range label[1 : l-1] {
		if !IsValidHostInnerRune(r) {
			return &RuneError{
				Kind: AddrKindLabel,
				Rune: r,
			}
		}
	}

	if r := rune(label[l-1]); !IsValidHostOuterRune(r) {
		return &RuneError{
			Kind: AddrKindLabel,
			Rune: r,
		}
	}

	return nil
}

// ValidateDomainName validates the domain name in accordance to RFC 952, RFC
// 1035, and with RFC-1123's inclusion of digits at the start of the host.  It
// doesn't validate against two or more hyphens to allow punycode and
// internationalized domains.
//
// Any error returned will have the underlying type of *AddrError.
func ValidateDomainName(name string) (err error) {
	defer makeAddrError(&err, name, AddrKindName)

	name, err = idna.ToASCII(name)
	if err != nil {
		return err
	}

	l := len(name)
	if l == 0 {
		return ErrAddrIsEmpty
	} else if l > MaxDomainNameLen {
		return &LengthError{
			Kind:   AddrKindName,
			Max:    MaxDomainNameLen,
			Length: l,
		}
	}

	labels := strings.Split(name, ".")
	for _, l := range labels {
		err = ValidateDomainNameLabel(l)
		if err != nil {
			return err
		}
	}

	return nil
}
