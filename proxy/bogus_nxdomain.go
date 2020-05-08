package proxy

import (
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/miekg/dns"
)

// isBogusNXDomain - checks if the specified DNS message
// contains ONLY ip addresses from the Proxy.BogusNXDomain list
func (p *Proxy) isBogusNXDomain(reply *dns.Msg) bool {
	if reply == nil ||
		len(p.BogusNXDomain) == 0 ||
		len(reply.Answer) == 0 ||
		(reply.Question[0].Qtype != dns.TypeA &&
			reply.Question[0].Qtype != dns.TypeAAAA) {
		return false
	}

	for _, rr := range reply.Answer {
		ip := proxyutil.GetIPFromDNSRecord(rr)
		if !proxyutil.ContainsIP(p.BogusNXDomain, ip) {
			return false
		}
	}

	// All IPs are bogus if we got here
	return true
}
