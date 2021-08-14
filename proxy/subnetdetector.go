package proxy

import (
	"fmt"
	"net"
)

// subnetDetector is used to check addresses for containing in the set of IP
// networks.
//
// TODO(e.burkov):  There is an exact copy of this functionality in
// github.com/AdguardTeam/AdGuardHome.  Maybe bring it into the golibs.
type subnetDetector struct {
	// nets stores the networks against which the IP address should be
	// checked.
	nets []*net.IPNet
}

// detect returns true if IP address is contained by any of the IP address
// registries.  It's safe for concurrent use.
//
// TODO(e.burkov): Think about memoization.
func (sd *subnetDetector) detect(ip net.IP) (ok bool) {
	for _, ipnet := range sd.nets {
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

// parseIPAsCIDR makes a 1/256 C-class network of IP address parsed from ipStr.
func parseIPAsCIDR(ipStr string) (network *net.IPNet) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// bits is the number of ones in 1/256 C-class CIDR.
	const bits = 8 * net.IPv6len

	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(bits, bits),
	}
}

// newSubnetDetector returns a new IP detector initialized with nets.  nets'
// strings could be either a CIDR or an IP address.
func newSubnetDetector(nets []string) (sd *subnetDetector, err error) {
	sd = &subnetDetector{
		nets: make([]*net.IPNet, len(nets)),
	}

	for i, ipnetStr := range nets {
		var ipnet *net.IPNet
		_, ipnet, err = net.ParseCIDR(ipnetStr)
		if err != nil {
			if ipnet = parseIPAsCIDR(ipnetStr); ipnet == nil {
				return nil, fmt.Errorf("bad CIDR or IP at index %d: %w", i, err)
			}
		}

		sd.nets[i] = ipnet
	}

	return sd, nil
}
