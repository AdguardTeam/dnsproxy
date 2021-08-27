package netutil

import (
	"net"
	"strconv"
	"strings"

	"github.com/AdguardTeam/golibs/stringutil"
)

// Reversed ARPA Addresses

// fromHexByte converts a single hexadecimal ASCII digit character into an
// integer from 0 to 15.  For all other characters it returns 0xff.
func fromHexByte(c byte) (n byte) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xff
	}
}

// ARPA reverse address domains.
const (
	arpaV4Suffix = ".in-addr.arpa"
	arpaV6Suffix = ".ip6.arpa"
)

// The maximum lengths of the ARPA-formatted reverse addresses.
//
// An example of IPv4 with a maximum length:
//
//   49.91.20.104.in-addr.arpa
//
// An example of IPv6 with a maximum length:
//
//   1.3.b.5.4.1.8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.7.4.6.0.6.2.ip6.arpa
//
const (
	arpaV4MaxIPLen = len("000.000.000.000")
	arpaV6MaxIPLen = len("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0")

	arpaV4MaxLen = arpaV4MaxIPLen + len(arpaV4Suffix)
	arpaV6MaxLen = arpaV6MaxIPLen + len(arpaV6Suffix)
)

// reverseIP inverts the order of bytes in an IP address in-place.
func reverseIP(ip net.IP) {
	l := len(ip)
	for i := range ip[:l/2] {
		ip[i], ip[l-i-1] = ip[l-i-1], ip[i]
	}
}

// ipv6FromReversedAddr parses an IPv6 reverse address.  It assumes that arpa is
// a valid domain name.
func ipv6FromReversedAddr(arpa string) (ip net.IP, err error) {
	const kind = "arpa domain name"

	ip = make(net.IP, net.IPv6len)

	const addrStep = len("0.0.")
	for i := range ip {
		// Get the two half-byte and merge them together.  Validate the
		// dots between them since while arpa is assumed to be a valid
		// domain name, those labels can still be invalid on their own.
		sIdx := i * addrStep

		c := arpa[sIdx]
		lo := fromHexByte(c)
		if lo == 0xff {
			return nil, &RuneError{
				Kind: kind,
				Rune: rune(c),
			}
		}

		c = arpa[sIdx+2]
		hi := fromHexByte(c)
		if hi == 0xff {
			return nil, &RuneError{
				Kind: kind,
				Rune: rune(c),
			}
		}

		if arpa[sIdx+1] != '.' || arpa[sIdx+3] != '.' {
			return nil, ErrNotAReversedIP
		}

		ip[net.IPv6len-i-1] = hi<<4 | lo
	}

	return ip, nil
}

// IPFromReversedAddr tries to convert a full reversed ARPA address to a normal
// IP address.  arpa can be domain name or an FQDN.
//
// Any error returned will have the underlying type of *AddrError.
func IPFromReversedAddr(arpa string) (ip net.IP, err error) {
	arpa = strings.TrimSuffix(arpa, ".")
	err = ValidateDomainName(arpa)
	if err != nil {
		bdErr := err.(*AddrError)
		bdErr.Kind = AddrKindARPA

		return nil, bdErr
	}

	defer makeAddrError(&err, arpa, AddrKindARPA)

	// TODO(a.garipov): Add stringutil.HasSuffixFold and remove this.
	arpa = strings.ToLower(arpa)

	if strings.HasSuffix(arpa, arpaV4Suffix) {
		ipStr := arpa[:len(arpa)-len(arpaV4Suffix)]
		ip, err = ParseIPv4(ipStr)
		if err != nil {
			return nil, err
		}

		reverseIP(ip)

		return ip, nil
	}

	if strings.HasSuffix(arpa, arpaV6Suffix) {
		if l := len(arpa); l != arpaV6MaxLen {
			return nil, &LengthError{
				Kind:    AddrKindARPA,
				Allowed: []int{arpaV6MaxLen},
				Length:  l,
			}
		}

		ip, err = ipv6FromReversedAddr(arpa)
		if err != nil {
			return nil, err
		}

		return ip, nil
	}

	return nil, ErrNotAReversedIP
}

// IPToReversedAddr returns the reversed ARPA address of ip suitable for reverse
// DNS (PTR) record lookups.  This is a modified version of function ReverseAddr
// from package github.com/miekg/dns package that accepts an IP.
//
// Any error returned will have the underlying type of *AddrError.
func IPToReversedAddr(ip net.IP) (arpa string, err error) {
	const dot = "."

	var l int
	var suffix string
	var writeByte func(val byte)
	b := &strings.Builder{}
	if ip4 := ip.To4(); ip4 != nil {
		l, suffix = arpaV4MaxLen, arpaV4Suffix[1:]
		ip = ip4
		writeByte = func(val byte) {
			stringutil.WriteToBuilder(b, strconv.Itoa(int(val)), dot)
		}
	} else if ip6 := ip.To16(); ip6 != nil {
		l, suffix = arpaV6MaxLen, arpaV6Suffix[1:]
		ip = ip6
		writeByte = func(val byte) {
			stringutil.WriteToBuilder(
				b,
				strconv.FormatUint(uint64(val&0x0f), 16),
				dot,
				strconv.FormatUint(uint64(val>>4), 16),
				dot,
			)
		}
	} else {
		return "", &AddrError{
			Kind: AddrKindIP,
			Addr: ip.String(),
		}
	}

	b.Grow(l)
	for i := len(ip) - 1; i >= 0; i-- {
		writeByte(ip[i])
	}

	stringutil.WriteToBuilder(b, suffix)

	return b.String(), nil
}
