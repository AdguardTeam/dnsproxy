package proxy

import (
	"net"

	"github.com/AdguardTeam/golibs/log"
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

// parseECS parses the EDNS client subnet option from m.
func parseECS(m *dns.Msg) (addr net.IP, mask uint8, scope uint8) {
	opt := m.IsEdns0()
	if opt == nil {
		return nil, 0, 0
	}

	for _, e := range opt.Option {
		sn, ok := e.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}

		switch sn.Family {
		case 1:
			return sn.Address.To4(), sn.SourceNetmask, sn.SourceScope
		case 2:
			return sn.Address, sn.SourceNetmask, sn.SourceScope
		default:
			// Go on.
		}
	}

	return nil, 0, 0
}

// setECS sets the EDNS client subnet option based on ip and scope into m.  It
// returns masked IP and mask length.
func setECS(m *dns.Msg, ip net.IP, scope uint8) (net.IP, uint8) {
	const (
		// defaultECSv4 is the default length of network mask for IPv4 address
		// in EDNS client subnet option.
		defaultECSv4 = 24
		// defaultECSv6 is the default length of network mask for IPv6 address
		// in EDNS client subnet option.  The size of 7 bytes is chosen as a
		// reasonable minimum since at least Google's public DNS refuses
		// requests containing the options with longer network masks.
		defaultECSv6 = 56
	)

	e := &dns.EDNS0_SUBNET{
		Code:        dns.EDNS0SUBNET,
		SourceScope: scope,
	}
	if ip4 := ip.To4(); ip4 != nil {
		e.Family = 1
		e.SourceNetmask = defaultECSv4
		e.Address = ip4.Mask(net.CIDRMask(defaultECSv4, net.IPv4len*8))
	} else {
		// Assume the IP address has already been validated.
		e.Family = 2
		e.SourceNetmask = defaultECSv6
		e.Address = ip.Mask(net.CIDRMask(defaultECSv6, net.IPv6len*8))
	}

	// If OPT record already exists so just add EDNS option inside it.  Note
	// that servers may return FORMERR if they meet several OPT RRs.
	if opt := m.IsEdns0(); opt != nil {
		opt.Option = append(opt.Option, e)

		return e.Address, e.SourceNetmask
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

	return e.Address, e.SourceNetmask
}

// Return TRUE if IP is within public Internet IP range
// nolint (gocyclo)
func isPublicIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 != nil {
		switch ip4[0] {
		case 0:
			return false // software
		case 10:
			return false // private network
		case 127:
			return false // loopback
		case 169:
			if ip4[1] == 254 {
				return false // link-local
			}
		case 172:
			if ip4[1] >= 16 && ip4[1] <= 31 {
				return false // private network
			}
		case 192:
			if (ip4[1] == 0 && ip4[2] == 0) || // private network
				(ip4[1] == 0 && ip4[2] == 2) || // documentation
				(ip4[1] == 88 && ip4[2] == 99) || // reserved
				(ip4[1] == 168) { // private network
				return false
			}
		case 198:
			if (ip4[1] == 18 || ip4[2] == 19) || // private network
				(ip4[1] == 51 || ip4[2] == 100) { // documentation
				return false
			}
		case 203:
			if ip4[1] == 0 && ip4[2] == 113 { // documentation
				return false
			}
		case 224:
			if ip4[1] == 0 && ip4[2] == 0 { // multicast
				return false
			}
		case 255:
			if ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 { // subnet
				return false
			}
		}
	} else {
		if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
			return false
		}
	}

	return true
}
