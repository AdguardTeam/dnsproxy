// Package proxyutil contains helper functions that are used in all other
// dnsproxy packages.
package proxyutil

import (
	"encoding/binary"
	"net"

	"github.com/miekg/dns"
)

// AddPrefix adds a 2-byte prefix with the DNS message length.
func AddPrefix(b []byte) (m []byte) {
	m = make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)

	return m
}

// IPFromRR returns the IP address from rr if any.
func IPFromRR(rr dns.RR) (ip net.IP) {
	switch rr := rr.(type) {
	case *dns.A:
		ip = rr.A.To4()
	case *dns.AAAA:
		ip = rr.AAAA
	default:
		// Go on.
	}

	return ip
}
