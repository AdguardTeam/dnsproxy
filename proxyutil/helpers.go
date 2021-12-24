// Package proxyutil contains helper functions that are used
// in all other dnsproxy packages
package proxyutil

import (
	"bytes"
	"net"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// IsConnClosed returns true if the error signals of a closed server connecting.
//
// Deprecated: This function is deprecated.  Use errors.Is(err, net.ErrClosed)
// instead.
func IsConnClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// GetIPFromDNSRecord - extracts IP address for a DNS record
// returns null if the record is of a wrong type
func GetIPFromDNSRecord(r dns.RR) net.IP {
	switch addr := r.(type) {
	case *dns.A:
		return addr.A.To4()

	case *dns.AAAA:
		return addr.AAAA
	}

	return nil
}

// ContainsIP checks if the specified IP is in the array
func ContainsIP(ips []net.IP, ip net.IP) bool {
	for _, i := range ips {
		if i.Equal(ip) {
			return true
		}
	}

	return false
}

// AppendIPAddrs appends the IP addresses got from dns.RR to the specified array
func AppendIPAddrs(ipAddrs *[]net.IPAddr, answers []dns.RR) {
	for _, ans := range answers {
		if a, ok := ans.(*dns.A); ok {
			ip := net.IPAddr{IP: a.A}
			*ipAddrs = append(*ipAddrs, ip)
		} else if a, ok := ans.(*dns.AAAA); ok {
			ip := net.IPAddr{IP: a.AAAA}
			*ipAddrs = append(*ipAddrs, ip)
		}
	}
}

// SortIPAddrs sorts the specified IP addresses array
// IPv4 addresses go first, then IPv6 addresses
func SortIPAddrs(ipAddrs []net.IPAddr) []net.IPAddr {
	if len(ipAddrs) < 2 {
		return ipAddrs
	}

	// Very simple bubble sort
	arrLen := len(ipAddrs)
	var buf net.IPAddr
	swapCnt := 0

	for i := 0; i < arrLen; {
		if i+1 != arrLen && compareIPAddrs(ipAddrs[i], ipAddrs[i+1]) > 0 {
			buf = ipAddrs[i]
			ipAddrs[i] = ipAddrs[i+1]
			ipAddrs[i+1] = buf
			swapCnt = 1
		}
		i++
		if i == arrLen && swapCnt == 1 {
			swapCnt = 0
			i = 0
		}
	}

	return ipAddrs
}

func compareIPAddrs(left net.IPAddr, right net.IPAddr) int {
	l4 := left.IP.To4()
	r4 := right.IP.To4()
	if l4 != nil && r4 == nil {
		return -1 // IPv4 addresses first
	} else if l4 == nil && r4 != nil {
		return 1 // IPv4 addresses first
	}
	return bytes.Compare(left.IP, right.IP)
}
