// Package proxyutil contains helper functions that are used
// in all other dnsproxy packages
package proxyutil

import (
	"bytes"
	"net"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

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

// ContainsIP returns true if any of nets contains ip.
func ContainsIP(nets []*net.IPNet, ip net.IP) (ok bool) {
	if netutil.ValidateIP(ip) != nil {
		return false
	}

	for _, n := range nets {
		if n.Contains(ip) {
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
	l := len(ipAddrs)
	if l <= 1 {
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

func compareIPAddrs(a, b net.IPAddr) int {
	l4 := a.IP.To4()
	r4 := b.IP.To4()
	if l4 != nil && r4 == nil {
		return -1 // IPv4 addresses first
	} else if l4 == nil && r4 != nil {
		return 1 // IPv4 addresses first
	}
	return bytes.Compare(a.IP, b.IP)
}
