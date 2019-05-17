package mobile

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/joomcode/errorx"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/urlfilter"

	"github.com/miekg/dns"
)

// filtersListJSON represents filters list with list id
type filtersListJSON struct {
	ListID         int    `json:"id"`
	FilteringRules string `json:"contents"`
}

// decodeFilteringRulesMap decodes filtersJSON and returns filters map
func decodeFilteringRulesMap(filtersJSON string) (map[int]string, error) {
	var filters []filtersListJSON
	err := json.NewDecoder(strings.NewReader(filtersJSON)).Decode(&filters)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to decode filters json")
	}

	filtersMap := map[int]string{}
	for _, filter := range filters {
		filtersMap[filter.ListID] = filter.FilteringRules
	}

	return filtersMap, err
}

// handleDNSRequest is a custom handler for proxy with filtering
func (d *DNSProxy) handleDNSRequest(p *proxy.Proxy, ctx *proxy.DNSContext) error {
	rule, blocked, err := d.filterRequest(ctx)
	if err != nil {
		handleDNSResponse(ctx, rule, err)
		return err
	}

	if blocked {
		handleDNSResponse(ctx, rule, nil)
		return nil
	}

	err = p.Resolve(ctx)
	handleDNSResponse(ctx, rule, err)
	return err
}

// filterRequest filters DNSContext request and returns true if request was blocked
func (d *DNSProxy) filterRequest(ctx *proxy.DNSContext) (urlfilter.Rule, bool, error) {
	// filter request
	if d.dnsEngine == nil {
		return nil, false, nil
	}

	reqType := ctx.Req.Question[0].Qtype
	host := strings.TrimSuffix(ctx.Req.Question[0].Name, ".")

	rules, ok := d.dnsEngine.Match(host)
	if !ok {
		return nil, false, nil
	}

	// DNSEngine Match func returns array of filtering rules. Let's check their kind
	for _, rule := range rules {
		if r, ok := rule.(*urlfilter.NetworkRule); ok {
			// It's a network rule. If it's not a whitelist rule - generate NXDomain
			// Otherwise just set filtering rule to DNSContext and try to resolve it
			log.Tracef("Network filtering rule for %s was found: %s, ListId: %d", host, rule.Text(), rule.GetFilterListID())
			if !r.Whitelist {
				ctx.Res = genNXDomain(ctx.Req)
				return r, true, nil
			}
			return r, false, nil

		} else if r, ok := rule.(*urlfilter.HostRule); ok {
			// It's a host rule. Generate a host rule answer for it:
			// - A request and IPv4 rule
			// - AAAA request and IPv6 rule
			if (r.IP.To4() != nil && reqType == dns.TypeA) || (r.IP.To4() == nil && reqType == dns.TypeAAAA) {
				log.Tracef("Host filtering rule for %s was found: %s, ListId: %d", host, rule.Text(), rule.GetFilterListID())
				res, err := genHostRuleAnswer(ctx.Req, r.IP)
				if err != nil {
					err = fmt.Errorf("failed to filter request to %s with rule %s cause %v", host, r.RuleText, err)
					return r, false, err
				}
				ctx.Res = res
				return r, true, nil
			}

			log.Tracef("Ignore host filtering rule %s for %s request type", r.RuleText, dns.Type(reqType).String())
		}
	}

	return nil, false, nil
}

// genNXDomain returns NXDomain response
func genNXDomain(request *dns.Msg) *dns.Msg {
	resp := dns.Msg{}
	resp.SetRcode(request, dns.RcodeNameError)
	resp.RecursionAvailable = true
	resp.Ns = genSOA(request)
	return &resp
}

// genSOA returns SOA for an authority section
func genSOA(request *dns.Msg) []dns.RR {
	zone := ""
	if len(request.Question) > 0 {
		zone = request.Question[0].Name
	}

	soa := dns.SOA{
		// values copied from verisign's nonexistent .com domain
		// their exact values are not important in our use case because they are used for domain transfers between primary/secondary DNS servers
		Refresh: 1800,
		Retry:   900,
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

// genHostRuleAnswer returns answer based on ip from urlfilter.HostRule
func genHostRuleAnswer(req *dns.Msg, ip net.IP) (*dns.Msg, error) {
	res := dns.Msg{}
	res.Question = []dns.Question{}
	res.Question = append(res.Question, req.Question[0])
	res.Answer = []dns.RR{}
	res.Id = req.Id
	res.RecursionAvailable = false
	name := req.Question[0].Name
	switch req.Question[0].Qtype {
	case dns.TypeA:
		res.Answer = append(res.Answer, genAHostAnswer(name, ip))
	case dns.TypeAAAA:
		res.Answer = append(res.Answer, genAAAAHostAnswer(name, ip))
	default:
		return nil, fmt.Errorf("unknown IP type: %v", ip)
	}

	return &res, nil
}

func genAHostAnswer(name string, ip net.IP) *dns.A {
	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Ttl: 3600, Class: dns.ClassINET}
	rr.A = ip
	return rr
}

func genAAAAHostAnswer(name string, ip net.IP) *dns.AAAA {
	rr := new(dns.AAAA)
	rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Ttl: 3600, Class: dns.ClassINET}
	rr.AAAA = ip
	return rr
}
