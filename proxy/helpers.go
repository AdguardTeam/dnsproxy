package proxy

import (
	"net"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

const retryNoError = 60 // Retry time for NoError SOA

// CheckDisabledAAAARequest checks if AAAA requests should be disabled or not and sets NoError empty response to given DNSContext if needed
func CheckDisabledAAAARequest(ctx *DNSContext, ipv6Disabled bool) bool {
	if ipv6Disabled && ctx.Req.Question[0].Qtype == dns.TypeAAAA {
		log.Debug("IPv6 is disabled. Reply with NoError to %s AAAA request", ctx.Req.Question[0].Name)
		ctx.Res = genEmptyNoError(ctx.Req)
		return true
	}

	return false
}

// GenEmptyMessage generates empty message with given response code and retry time
func GenEmptyMessage(request *dns.Msg, rCode int, retry uint32) *dns.Msg {
	resp := dns.Msg{}
	resp.SetRcode(request, rCode)
	resp.RecursionAvailable = true
	resp.Ns = genSOA(request, retry)
	return &resp
}

// genEmptyNoError returns response without answer and NoError RCode
func genEmptyNoError(request *dns.Msg) *dns.Msg {
	return GenEmptyMessage(request, dns.RcodeSuccess, retryNoError)
}

// genSOA returns SOA for an authority section
func genSOA(request *dns.Msg, retry uint32) []dns.RR {
	zone := ""
	if len(request.Question) > 0 {
		zone = request.Question[0].Name
	}

	soa := dns.SOA{
		// values copied from verisign's nonexistent .com domain
		// their exact values are not important in our use case because they are used for domain transfers between primary/secondary DNS servers
		Refresh: 1800,
		Retry:   retry,
		Expire:  604800,
		Minttl:  86400,
		// copied from AdGuard DNS
		Ns:     "fake-for-negative-caching.adguard.com.",
		Serial: 100500,
		// rest is request-specific
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Ttl:    10,
			Class:  dns.ClassINET,
		},
	}
	soa.Mbox = "hostmaster."
	if len(zone) > 0 && zone[0] != '.' {
		soa.Mbox += zone
	}
	return []dns.RR{&soa}
}

// ecsFromMsg returns the subnet from EDNS Client-Subnet option of m if any.
func ecsFromMsg(m *dns.Msg) (subnet *net.IPNet, scope int) {
	opt := m.IsEdns0()
	if opt == nil {
		return nil, 0
	}

	var ip net.IP
	var mask net.IPMask
	for _, e := range opt.Option {
		sn, ok := e.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}

		switch sn.Family {
		case 1:
			ip = sn.Address.To4()
			mask = net.CIDRMask(int(sn.SourceNetmask), netutil.IPv4BitLen)
		case 2:
			ip = sn.Address
			mask = net.CIDRMask(int(sn.SourceNetmask), netutil.IPv6BitLen)
		default:
			continue
		}

		return &net.IPNet{IP: ip, Mask: mask}, int(sn.SourceScope)
	}

	return nil, 0
}

// setECS sets the EDNS client subnet option based on ip and scope into m.  It
// returns masked IP and mask length.
func setECS(m *dns.Msg, ip net.IP, scope uint8) (subnet *net.IPNet) {
	const (
		// defaultECSv4 is the default length of network mask for IPv4 address
		// in EDNS client subnet option.
		defaultECSv4 = 24

		// defaultECSv6 is the default length of network mask for IPv6 address
		// in EDNS client subnet option.  The size of 7 octets is chosen as a
		// reasonable minimum since at least Google's public DNS refuses
		// requests containing the options with longer network masks.
		defaultECSv6 = 56
	)

	e := &dns.EDNS0_SUBNET{
		Code:        dns.EDNS0SUBNET,
		SourceScope: scope,
	}

	subnet = &net.IPNet{}
	if ip4 := ip.To4(); ip4 != nil {
		e.Family = 1
		e.SourceNetmask = defaultECSv4
		subnet.Mask = net.CIDRMask(defaultECSv4, netutil.IPv4BitLen)
		ip = ip4
	} else {
		// Assume the IP address has already been validated.
		e.Family = 2
		e.SourceNetmask = defaultECSv6
		subnet.Mask = net.CIDRMask(defaultECSv6, netutil.IPv6BitLen)
	}
	subnet.IP = ip.Mask(subnet.Mask)
	e.Address = subnet.IP

	// If OPT record already exists so just add EDNS option inside it.  Note
	// that servers may return FORMERR if they meet several OPT RRs.
	if opt := m.IsEdns0(); opt != nil {
		opt.Option = append(opt.Option, e)

		return subnet
	}

	// Create an OPT record and add EDNS option inside it.
	o := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
		Option: []dns.EDNS0{e},
	}
	o.SetUDPSize(4096)
	m.Extra = append(m.Extra, o)

	return subnet
}

// isPublicIP returns true if ip is within public Internet IP range.
//
// TODO(e.burkov, a.garipov):  Add an interface-based subnet detector to the
// netutil.
//
// nolint (gocyclo)
func isPublicIP(ip net.IP) (ok bool) {
	if ip = ip.To4(); ip == nil {
		return !ip.IsLoopback() && !ip.IsLinkLocalMulticast() && !ip.IsLinkLocalUnicast()
	}

	switch ip[0] {
	case 0, 10, 127:
		// Software, private network, loopback.
		return false
	case 169:
		// Link-local.
		return ip[1] != 254
	case 172:
		// Private network.
		return ip[1] < 16 || ip[1] > 31
	case 192:
		switch ip[1] {
		case 0:
			// Private network, documentation.
			return ip[2] != 0 && ip[2] != 2
		case 88:
			// Reserved.
			return ip[2] != 99
		case 168:
			// Private network.
			return false
		default:
			return true
		}
	case 198:
		// Private network, documentation.
		return (ip[1] != 18 && ip[2] != 19) && (ip[1] != 51 && ip[2] != 100)
	case 203:
		// Documentation.
		return ip[1] != 0 || ip[2] != 113
	case 224:
		// Multicast.
		return ip[1] != 0 || ip[2] != 0
	case 255:
		// Broadcast.
		return ip[1] != 255 || ip[2] != 255 || ip[3] != 255
	default:
		return true
	}
}
