package proxy

import (
	"net"
	"strings"

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

// getIPString is a helper function that extracts IP address from net.Addr
func getIPString(addr net.Addr) string {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return addr.IP.String()
	case *net.TCPAddr:
		return addr.IP.String()
	}
	return ""
}

// Parse ECS option from DNS response
// Return IP, mask, scope
func parseECS(m *dns.Msg) (net.IP, uint8, uint8) {
	for _, ex := range m.Extra {
		opt, ok := ex.(*dns.OPT)
		if !ok {
			continue
		}
		for _, e := range opt.Option {
			sn, ok := e.(*dns.EDNS0_SUBNET)
			if !ok {
				continue
			}
			switch sn.Family {
			case 0, 1:
				return sn.Address.To4(), sn.SourceNetmask, sn.SourceScope
			case 2:
				return sn.Address, sn.SourceNetmask, sn.SourceScope
			}
		}
	}
	return nil, 0, 0
}

// Set EDNS Client Subnet option in DNS request object
// Return masked IP and mask
func setECS(m *dns.Msg, ip net.IP, scope uint8) (net.IP, uint8) {
	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	if ip.To4() != nil {
		e.Family = 1
		e.SourceNetmask = ednsCSDefaultNetmaskV4
		e.Address = ip.To4().Mask(net.CIDRMask(int(e.SourceNetmask), 32))
	} else {
		e.Family = 2
		e.SourceNetmask = ednsCSDefaultNetmaskV6
		e.Address = ip.Mask(net.CIDRMask(int(e.SourceNetmask), 128))
	}
	e.SourceScope = scope

	// If OPT record already exists - add EDNS option inside it
	// Note that servers may return FORMERR if they meet 2 OPT records.
	for _, ex := range m.Extra {
		if ex.Header().Rrtype == dns.TypeOPT {
			opt := ex.(*dns.OPT)
			opt.Option = append(opt.Option, e)
			return e.Address, e.SourceNetmask
		}
	}

	// Create an OPT record and add EDNS option inside it
	o := new(dns.OPT)
	o.SetUDPSize(4096)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.Option = append(o.Option, e)
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

// split string by a byte and return the first chunk
// Whitespace is trimmed
func splitNext(str *string, splitBy byte) string {
	i := strings.IndexByte(*str, splitBy)
	s := ""
	if i != -1 {
		s = (*str)[0:i]
		*str = (*str)[i+1:]
	} else {
		s = *str
		*str = ""
	}
	return strings.TrimSpace(s)
}
