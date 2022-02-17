// Package netutil contains common utilities for IP, MAC, and other kinds of
// network addresses.
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

// Various Network Address Utilities

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

// SplitHostPort is a convenient wrapper for net.SplitHostPort with port of type
// int.
func SplitHostPort(hostport string) (host string, port int, err error) {
	var portStr string
	host, portStr, err = net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}

	var portUint uint64
	portUint, err = strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parsing port: %w", err)
	}

	return host, int(portUint), nil
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

// Subdomains returns all subdomains of domain, starting from domain itself.
// domain must be a valid, non-fully-qualified domain name.  If domain is empty,
// Subdomains returns nil.
func Subdomains(domain string) (sub []string) {
	if domain == "" {
		return nil
	}

	sub = []string{domain}

	for domain != "" {
		i := strings.IndexByte(domain, '.')
		if i < 0 {
			break
		}

		domain = domain[i+1:]
		sub = append(sub, domain)
	}

	return sub
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

	if label == "" {
		return ErrLabelIsEmpty
	}

	l := len(label)
	if l > MaxDomainLabelLen {
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

// ValidateDomainName validates the domain name in accordance to RFC 952,
// RFC 1035, and with RFC 1123's inclusion of digits at the start of the host.
// It doesn't validate against two or more hyphens to allow punycode and
// internationalized domains.
//
// Any error returned will have the underlying type of *AddrError.
func ValidateDomainName(name string) (err error) {
	defer makeAddrError(&err, name, AddrKindName)

	name, err = idna.ToASCII(name)
	if err != nil {
		return err
	}

	if name == "" {
		return ErrAddrIsEmpty
	} else if l := len(name); l > MaxDomainNameLen {
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

// MaxServiceLabelLen is the maximum allowed length of a service name label
// according to RFC 6335.
const MaxServiceLabelLen = 16

// ValidateServiceNameLabel returns an error if label is not a valid label of
// a service domain name.  An empty label is considered invalid.
//
// Any error returned will have the underlying type of *AddrError.
func ValidateServiceNameLabel(label string) (err error) {
	defer makeAddrError(&err, label, AddrKindSRVLabel)

	if label == "" {
		return ErrLabelIsEmpty
	} else if r := rune(label[0]); r != '_' {
		return &RuneError{
			Kind: AddrKindSRVLabel,
			Rune: r,
		}
	}

	l := len(label)
	if l > MaxServiceLabelLen {
		return &LengthError{
			Kind:   AddrKindSRVLabel,
			Max:    MaxServiceLabelLen,
			Length: l,
		}
	}

	// TODO(e.burkov):  Validate adjacent hyphens since service labels can't be
	// internationalized.  See RFC 6336 Section 5.1.
	if err := ValidateDomainNameLabel(label[1:]); err != nil {
		err = errors.Unwrap(err)
		if rerr, ok := err.(*RuneError); ok {
			rerr.Kind = AddrKindSRVLabel
		}

		return err
	}

	return nil
}

// ValidateSRVDomainName validates of domain name assuming it belongs to the
// superset of service domain names in accordance to RFC 2782 and RFC 6763.  It
// doesn't validate against two or more hyphens to allow punycode and
// internationalized domains.
//
// Any error returned will have the underlying type of *AddrError.
func ValidateSRVDomainName(name string) (err error) {
	defer makeAddrError(&err, name, AddrKindSRVName)

	name, err = idna.ToASCII(name)
	if err != nil {
		return err
	}

	if name == "" {
		return ErrAddrIsEmpty
	} else if l := len(name); l > MaxDomainNameLen {
		return &LengthError{
			Kind:   AddrKindSRVName,
			Max:    MaxDomainNameLen,
			Length: l,
		}
	}

	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l != "" && l[0] == '_' {
			err = ValidateServiceNameLabel(l)
		} else {
			err = ValidateDomainNameLabel(l)
		}
		if err != nil {
			return err
		}
	}

	return nil
}
