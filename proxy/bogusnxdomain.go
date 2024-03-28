package proxy

import (
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// isBogusNXDomain returns true if m contains at least a single IP address in
// the Answer section contained in BogusNXDomain subnets of p.
func (p *Proxy) isBogusNXDomain(m *dns.Msg) (ok bool) {
	if m == nil || len(p.BogusNXDomain) == 0 || len(m.Question) == 0 {
		return false
	} else if qt := m.Question[0].Qtype; qt != dns.TypeA && qt != dns.TypeAAAA {
		return false
	}

	set := netutil.SliceSubnetSet(p.BogusNXDomain)
	for _, rr := range m.Answer {
		ip := proxyutil.IPFromRR(rr)
		if set.Contains(ip) {
			return true
		}
	}

	return false
}
