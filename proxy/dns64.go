package proxy

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// isIpv6ResponseEmpty checks AAAA answer to be empty
// returns true if NAT64 prefix already calculated and there are no answers for AAAA question
func (p *Proxy) isIpv6ResponseEmpty(resp, req *dns.Msg) bool {
	return p.isNAT64PrefixAvailable() && req.Question[0].Qtype == dns.TypeAAAA && (resp == nil || len(resp.Answer) == 0)
}

// isNAT64PrefixAvailable returns true if NAT64 prefix was calculated
func (p *Proxy) isNAT64PrefixAvailable() bool {
	p.nat64Lock.Lock()
	prefixSize := len(p.nat64Prefix)
	p.nat64Lock.Unlock()
	return prefixSize == 12
}

// SetNAT64Prefix sets NAT64 prefix
func (p *Proxy) SetNAT64Prefix(prefix []byte) {
	if len(prefix) != 12 {
		return
	}

	// Check if proxy is started and has no prefix yet
	p.nat64Lock.Lock()
	if len(p.nat64Prefix) == 0 {
		p.RLock()
		if p.started {
			p.nat64Prefix = prefix
			log.Printf("NAT64 prefix: %v", prefix)
		}
		p.RUnlock()
	}
	p.nat64Lock.Unlock()
}

// createModifiedARequest returns modified question to make A DNS request
func createModifiedARequest(d *dns.Msg) (*dns.Msg, error) {
	if d.Question[0].Qtype != dns.TypeAAAA {
		return nil, fmt.Errorf("question is not AAAA, do nothing")
	}

	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: d.Question[0].Name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	return &req, nil
}

// createDNS64MappedResponse adds NAT 64 mapped answer to the old message
// res is new A response. req is old AAAA request
func (p *Proxy) createDNS64MappedResponse(res, req *dns.Msg) (*dns.Msg, error) {
	// do nothing if prefix is not valid
	if !p.isNAT64PrefixAvailable() {
		return nil, fmt.Errorf("can not create DNS64 mapped response: NAT64 prefix was not calculated")
	}

	// check if there are no answers
	if len(res.Answer) == 0 {
		return nil, fmt.Errorf("no ipv4 answer")
	}

	// this bug occurs only ones
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	req.Answer = []dns.RR{}
	// add NAT 64 prefix for each ipv4 answer
	for _, ans := range res.Answer {
		i, ok := ans.(*dns.A)
		if !ok {
			continue
		}

		// new ip address
		mappedAddress := make(net.IP, net.IPv6len)

		// add NAT 64 prefix and append ipv4 record
		copy(mappedAddress, p.nat64Prefix)
		for index, b := range i.A {
			mappedAddress[12+index] = b
		}

		// create new response and fill it
		rr := new(dns.AAAA)
		rr.Hdr = dns.RR_Header{Name: res.Question[0].Name, Rrtype: dns.TypeAAAA, Ttl: ans.Header().Ttl, Class: dns.ClassINET}
		rr.AAAA = mappedAddress
		req.Answer = append(req.Answer, rr)
	}
	return req, nil
}

// checkDNS64 is called when there is no answer for AAAA request and NAT64 prefix available.
// this function creates modified A request, exchanges it and returns DNS64 mapped response
func (p *Proxy) checkDNS64(oldReq, oldResp *dns.Msg, upstreams []upstream.Upstream) (*dns.Msg, upstream.Upstream, error) {
	// Let's create A request to the same hostname
	req, err := createModifiedARequest(oldReq)
	if err != nil {
		log.Tracef("Failed to create DNS64 mapped request %s", err)
		return oldReq, nil, err
	}

	// Exchange new A request with selected upstreams
	resp, u, err := p.exchange(req, upstreams)
	if err != nil {
		log.Tracef("Failed to exchange DNS64 request: %s", err)
		return oldReq, nil, err
	}

	// A response should be mapped with NAT64 prefix
	response, err := p.createDNS64MappedResponse(resp, oldResp)
	if err != nil {
		log.Tracef("Failed to create DNS64 mapped request %s", err)
		return oldReq, u, err
	}
	return response, u, nil
}
