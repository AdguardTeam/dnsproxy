package proxy

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// NAT64PrefixLength is the length of a NAT64 prefix
const NAT64PrefixLength = 12

// isEmptyAAAAResponse checks if there are no AAAA records in response
func (p *Proxy) isEmptyAAAAResponse(resp, req *dns.Msg) bool {
	return (resp == nil || len(resp.Answer) == 0) &&
		req.Question[0].Qtype == dns.TypeAAAA
}

// isNAT64PrefixAvailable returns true if NAT64 prefix was calculated
func (p *Proxy) isNAT64PrefixAvailable() bool {
	p.nat64PrefixLock.Lock()
	prefixSize := len(p.nat64Prefix)
	p.nat64PrefixLock.Unlock()
	return prefixSize == NAT64PrefixLength
}

// SetNAT64Prefix sets NAT64 prefix
func (p *Proxy) SetNAT64Prefix(prefix []byte) {
	if len(prefix) != NAT64PrefixLength {
		return
	}

	p.nat64PrefixLock.Lock()
	p.nat64Prefix = prefix
	p.nat64PrefixLock.Unlock()

	ip := [net.IPv6len]byte{}
	copy(ip[:NAT64PrefixLength], prefix)
	log.Info("NAT64 prefix: %v", net.IP(ip[:]).String())
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

// createDNS64MappedResponse adds a NAT64 mapped answer to the old message
// newAResp is new A response. oldAAAAResp is old *dns.Msg with AAAA request and empty answer
func (p *Proxy) createDNS64MappedResponse(newAResp, oldAAAAResp *dns.Msg) (*dns.Msg, error) {
	var nat64Prefix []byte
	p.nat64PrefixLock.Lock()
	nat64Prefix = p.nat64Prefix
	p.nat64PrefixLock.Unlock()

	if len(nat64Prefix) != NAT64PrefixLength {
		return nil, errors.Error("cannot create a mapped response, no NAT64 prefix specified")
	}

	// check if there are no answers
	if len(newAResp.Answer) == 0 {
		return nil, fmt.Errorf("no ipv4 answer")
	}

	oldAAAAResp.Answer = []dns.RR{}
	// add NAT 64 prefix for each ipv4 answer
	for _, ans := range newAResp.Answer {
		i, ok := ans.(*dns.A)
		if !ok {
			continue
		}

		// new ip address
		mappedAddress := make(net.IP, net.IPv6len)

		// add NAT 64 prefix and append ipv4 record
		copy(mappedAddress, nat64Prefix)
		for index, b := range i.A {
			mappedAddress[NAT64PrefixLength+index] = b
		}

		// create new response and fill it
		rr := new(dns.AAAA)
		rr.Hdr = dns.RR_Header{Name: newAResp.Question[0].Name, Rrtype: dns.TypeAAAA, Ttl: ans.Header().Ttl, Class: dns.ClassINET}
		rr.AAAA = mappedAddress
		oldAAAAResp.Answer = append(oldAAAAResp.Answer, rr)
	}
	return oldAAAAResp, nil
}

// checkDNS64 is called when there is no answer for AAAA request and a NAT64 prefix is configured.
// this function creates modified A request from oldAAAAReq, exchanges it and returns DNS64 mapped response
// oldAAAAReq is message with AAAA Question. oldAAAAResp is response for oldAAAAReq with empty answer section
func (p *Proxy) checkDNS64(oldAAAAReq, oldAAAAResp *dns.Msg, upstreams []upstream.Upstream) (*dns.Msg, upstream.Upstream, error) {
	// Let's create A request to the same hostname
	modifiedAReq, err := createModifiedARequest(oldAAAAReq)
	if err != nil {
		log.Tracef("Failed to create DNS64 mapped request %s", err)
		return nil, nil, err
	}

	// Exchange new A request with selected upstreams
	newAResp, u, err := p.exchange(modifiedAReq, upstreams)
	if err != nil {
		log.Tracef("Failed to exchange DNS64 request: %s", err)
		return nil, nil, err
	}

	// Check if oldAAAAResp is nil
	if oldAAAAResp == nil {
		oldAAAAResp = &dns.Msg{}
		oldAAAAResp.Id = oldAAAAReq.Id
		oldAAAAResp.RecursionDesired = oldAAAAReq.RecursionDesired
		oldAAAAResp.Question = []dns.Question{oldAAAAReq.Question[0]}
	}

	// new A response should be mapped with NAT64 prefix
	mappedAAAAResponse, err := p.createDNS64MappedResponse(newAResp, oldAAAAResp)
	if err != nil {
		log.Tracef("Failed to create DNS64 mapped request %s", err)
		return nil, u, err
	}
	return mappedAAAAResponse, u, nil
}
