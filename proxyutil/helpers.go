// Package proxyutil contains helper functions that are used
// in all other dnsproxy packages
package proxyutil

import (
	"bytes"
	"net"

	"github.com/miekg/dns"
)

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
	return bytes.Compare(left.IP, right.IP)
}
