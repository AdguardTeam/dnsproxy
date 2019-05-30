package mobile

import (
	"bytes"
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
	var rule urlfilter.Rule
	var err error
	var blocked bool
	if d.filteringEngine != nil {
		rule, blocked, err = d.filteringEngine.filterRequest(ctx)
		if err != nil {
			handleDNSResponse(ctx, rule, err)
			return err
		}

		if blocked {
			handleDNSResponse(ctx, rule, nil)
			return nil
		}
	}

	err = p.Resolve(ctx)
	handleDNSResponse(ctx, rule, err)
	return err
}

// filteringEngine is a wrapper for urlfilter structures and filtering options
type filteringEngine struct {
	dnsEngine         *urlfilter.DNSEngine    // Filtering Engine
	rulesStorage      *urlfilter.RulesStorage // serialized filtering rules rulesStorage
	blockWithNXDomain bool                    // If true requests which were filtered with network rules will be blocked with NXDomain message instead of undefined IP
}

// match returns result of DNSEngine Match() func
func (e *filteringEngine) match(hostname string) ([]urlfilter.Rule, bool) {
	return e.dnsEngine.Match(hostname)
}

// close and destroy rules storage if it exists
func (e *filteringEngine) close() error {
	if e.rulesStorage == nil {
		return nil
	}

	err := e.rulesStorage.Close()
	e.rulesStorage = nil
	return err
}

// filterRequest filters DNSContext request and returns true if request was blocked
func (e *filteringEngine) filterRequest(ctx *proxy.DNSContext) (urlfilter.Rule, bool, error) {
	// filter request
	reqType := ctx.Req.Question[0].Qtype
	host := strings.TrimSuffix(ctx.Req.Question[0].Name, ".")

	rules, ok := e.match(host)
	if !ok {
		return nil, false, nil
	}

	// DNSEngine Match func returns array of filtering rules. Let's check their kind
	for _, rule := range rules {
		if netRule, ok := rule.(*urlfilter.NetworkRule); ok {
			// It's a network rule. If it's not a whitelist rule - generate NXDomain
			// Otherwise just set filtering rule to DNSContext and try to resolve it
			log.Tracef("Network filtering rule for %s was found: %s, ListId: %d", host, rule.Text(), rule.GetFilterListID())
			if !netRule.Whitelist {
				var res *dns.Msg
				var err error
				if e.blockWithNXDomain {
					// Generate NXDomain if request should be blocked with it
					res = genNXDomain(ctx.Req)
				} else {
					// Otherwise generate undefined IP
					ip := net.IPv4zero
					if reqType == dns.TypeAAAA {
						ip = net.IPv6zero
					}

					res, err = genHostRuleAnswer(ctx.Req, ip)
					if err != nil {
						err = fmt.Errorf("failed to filter request to %s with rule %s cause %v", host, netRule.RuleText, err)
						return netRule, false, err
					}
				}

				ctx.Res = res
				return netRule, true, nil
			}
			return netRule, false, nil

		} else if hostRule, ok := rule.(*urlfilter.HostRule); ok {
			// It's a host rule. We should generate a host rule answer for it.
			// Let's copy IP from the rule first. We need to do it cause hostRule is a pointer, and IP may be changed for AAAA request
			ip := hostRule.IP

			// - A request and IPv4 rule
			// - AAAA request and IPv6 rule or zero IPv4 rule
			ip4 := ip.To4()
			matchARequest := reqType == dns.TypeA && ip4 != nil
			matchAAAARequest := reqType == dns.TypeAAAA && ip4 == nil
			matchAAAARequestWithZeroIPv4Rule := reqType == dns.TypeAAAA && ip4 != nil && bytes.Equal(ip4, []byte{0, 0, 0, 0})

			if matchARequest || matchAAAARequest || matchAAAARequestWithZeroIPv4Rule {
				log.Tracef("Host filtering rule for %s was found: %s, ListId: %d", host, rule.Text(), rule.GetFilterListID())

				// Let's replace zero IPv4 with IPv6Zero for AAAA request
				if matchAAAARequestWithZeroIPv4Rule {
					ip = net.IPv6zero
				}

				res, err := genHostRuleAnswer(ctx.Req, ip)
				if err != nil {
					err = fmt.Errorf("failed to filter request to %s with rule %s cause %v", host, hostRule.RuleText, err)
					return hostRule, false, err
				}
				ctx.Res = res
				return hostRule, true, nil
			}

			log.Tracef("Ignore host filtering rule %s for %s request type", hostRule.RuleText, dns.Type(reqType).String())
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
