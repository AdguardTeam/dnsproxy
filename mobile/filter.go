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

const (
	// BlockTypeRule - respond with NXDomain for Network filtering rules and with IP for Host rules
	BlockTypeRule = iota

	// BlockTypeNXDomain - respond with NXDomain for all kind of filtering rules
	BlockTypeNXDomain = iota

	// BlockTypeUnspecifiedIP - respond with Unspecified IP for Network filtering rules
	BlockTypeUnspecifiedIP = iota

	// Retry time for NXDomain SOA
	retryNXDomain = 900
)

// stringRuleListJSON represents filters list with list id
type stringRuleListJSON struct {
	ListID         int    `json:"id"`
	FilteringRules string `json:"contents"`
}

// fileRuleListJSON represents filters list path with list id
type fileRuleListJSON struct {
	ListID int    `json:"id"`
	Path   string `json:"path"`
}

// addStringRuleLists parses filtersJSON and adds StringRuleLists to ruleList slice
func addStringRuleLists(listJSON string, ruleList *[]urlfilter.RuleList) error {
	// do nothing if empty string was passed
	if len(listJSON) == 0 {
		return nil
	}

	// decode JSON to stringRuleListJSON
	var filterLists []stringRuleListJSON
	err := json.NewDecoder(strings.NewReader(listJSON)).Decode(&filterLists)
	if err != nil {
		return errorx.Decorate(err, "Failed to decode string rule lists json")
	}

	// Add each StringRuleList to ruleList
	for _, filterList := range filterLists {
		list := &urlfilter.StringRuleList{
			ID:             filterList.ListID,
			RulesText:      filterList.FilteringRules,
			IgnoreCosmetic: false,
		}

		*ruleList = append(*ruleList, list)
	}

	return nil
}

// addFileRuleLists parses listJSON and adds FileRuleLists to ruleList slice
func addFileRuleLists(listJSON string, ruleList *[]urlfilter.RuleList) error {
	// do nothing if empty string was passed
	if len(listJSON) == 0 {
		return nil
	}

	// decode JSON to fileRuleListJSON
	var filterLists []fileRuleListJSON
	err := json.NewDecoder(strings.NewReader(listJSON)).Decode(&filterLists)
	if err != nil {
		return errorx.Decorate(err, "Failed to decode file rule lists json")
	}

	// Add each FileRuleList to ruleList
	for _, filterList := range filterLists {
		list, err := urlfilter.NewFileRuleList(filterList.ListID, filterList.Path, false)
		if err != nil {
			return errorx.Decorate(err, "Failed to init FileRuleList with ID %d from %s", filterList.ListID, filterList.Path)
		}

		*ruleList = append(*ruleList, list)
	}

	return nil
}

// handleDNSRequest is a custom handler for proxy with filtering
func (d *DNSProxy) handleDNSRequest(p *proxy.Proxy, ctx *proxy.DNSContext) error {
	var rule urlfilter.Rule
	var err error
	var blocked bool

	// Block AAAA requests if needed
	if proxy.CheckDisabledAAAARequest(ctx, d.Config.IPv6Disabled) {
		return nil
	}

	// Block 'use-application-dns.net.' to disable Mozilla DoH
	if (ctx.Req.Question[0].Qtype == dns.TypeA || ctx.Req.Question[0].Qtype == dns.TypeAAAA) &&
		ctx.Req.Question[0].Name == "use-application-dns.net." {
		ctx.Res = genNXDomain(ctx.Req)
		return nil
	}

	d.RLock()
	// Synchronize access to d.filteringEngine so it won't be suddenly uninitialized while in use.
	// This could happen after proxy server has been stopped, but its workers are not yet exited.
	//
	// A better approach is for proxy.Stop() to wait until all its workers exit,
	//  but this would require the Upstream interface to have Close() function
	//  (to prevent from hanging while waiting for unresponsive DNS server to respond).
	if d.filteringEngine != nil {
		rule, blocked, err = d.filteringEngine.filterRequest(ctx)
		d.RUnlock()
		if err != nil {
			handleDNSResponse(ctx, rule, err)
			return err
		}

		if blocked {
			handleDNSResponse(ctx, rule, nil)
			return nil
		}
	} else {
		d.RUnlock()
	}

	err = p.Resolve(ctx)
	handleDNSResponse(ctx, rule, err)
	return err
}

// filteringEngine is a wrapper for urlfilter structures and filtering options
type filteringEngine struct {
	dnsEngine    *urlfilter.DNSEngine   // Filtering Engine
	rulesStorage *urlfilter.RuleStorage // Serialized filtering rules storage
	blockType    int                    // Block type
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

// setBlockingResponse sets proxy.DNSContext.Res to the proper blocking response
// depending on the "blockType" it can be either NXDOMAIN or the IP (0.0.0.0 or ::)
func (e *filteringEngine) setBlockingResponse(ctx *proxy.DNSContext, netRule *urlfilter.NetworkRule) error {
	reqType := ctx.Req.Question[0].Qtype
	host := strings.TrimSuffix(ctx.Req.Question[0].Name, ".")

	var res *dns.Msg
	var err error
	if e.blockType != BlockTypeUnspecifiedIP {
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
			return err
		}
	}

	ctx.Res = res
	return nil
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
				err := e.setBlockingResponse(ctx, netRule)
				return netRule, err == nil, err
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

				if e.blockType == BlockTypeNXDomain {
					// Generate NXDomain if request should be blocked with it
					ctx.Res = genNXDomain(ctx.Req)
					return hostRule, true, nil
				}

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
	return proxy.GenEmptyMessage(request, dns.RcodeNameError, retryNXDomain)
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
