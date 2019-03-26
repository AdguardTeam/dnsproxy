package proxy

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

// Byte representation of IPv4 addresses we are looking for after NAT64 prefix while dns response parsing
// It's two "well-known IPv4" addresses defined for Pref64::/n
// https://tools.ietf.org/html/rfc7050#section-2.2
var wellKnownIpv4First = []byte{192, 0, 0, 171}  //nolint
var wellKnownIpv4Second = []byte{192, 0, 0, 170} //nolint

// createIpv4ArpaMessage creates AAAA request for the "Well-Known IPv4-only Name"
// this request should be exchanged with DNS64 upstreams.
func createIpv4ArpaMessage() *dns.Msg {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "ipv4only.arpa.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
	}
	return &req
}

// getNAT64PrefixFromResponse parses a response for NAT64 prefix
// valid answer should contains the following AAAA record:
//
// - 16 bytes record
// - first 12 bytes is ipv6 prefix
// - last 4 bytes are required Ipv4: wellKnownIpv4First or wellKnownIpv4Second
// we use simplified algorithm and consider the first matched record to be valid
func getNAT64PrefixFromResponse(r *dns.Msg) ([]byte, error) {
	var prefix []byte
	for _, reply := range r.Answer {
		a, ok := reply.(*dns.AAAA)
		if !ok {
			log.Tracef("Answer is not AAAA record")
			continue
		}
		ip := a.AAAA

		// Let's separate IPv4 part from NAT64 prefix
		ipv4 := ip[12:]
		if len(ipv4) != net.IPv4len {
			continue
		}

		// Compare bytes in IPv4 part to wellKnownIpv4First and wellKnownIpv4Second
		valid := true
		for i, b := range ipv4 {
			// Compare
			if b != wellKnownIpv4First[i] && b != wellKnownIpv4Second[i] {
				valid = false
				break
			}
		}

		if !valid {
			continue
		}

		// Set NAT64 prefix and break loop
		fmt.Printf("got prefix from response. answer is: %s\n", ip.String())
		prefix = ip[:12]
		break
	}

	if len(prefix) == 0 {
		return nil, fmt.Errorf("no NAT64 prefix in answers")
	}
	return prefix, nil
}

// isIpv6ResponseEmpty checks AAAA answer to be empty
// returns true if NAT64 prefix already calculated and there are no answers for AAAA question
func (p *Proxy) isIpv6ResponseEmpty(resp, req *dns.Msg) bool {
	return p.isNAT64PrefixAvailable() && req.Question[0].Qtype == dns.TypeAAAA && (resp == nil || len(resp.Answer) == 0)
}

// isNAT64PrefixAvailable returns true if nat64 prefix was calculated
func (p *Proxy) isNAT64PrefixAvailable() bool {
	p.nat64Lock.Lock()
	prefixSize := len(p.nat64Prefix)
	p.nat64Lock.Unlock()
	return prefixSize == 12
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

// nat64Result is a result of NAT64 prefix calculation
type nat64Result struct {
	prefix   []byte
	upstream upstream.Upstream
	err      error
}

// getNAT64PrefixAsync sends result of getNAT64PrefixWithUpstream to the channel
func getNAT64PrefixAsync(req *dns.Msg, u upstream.Upstream, ch chan nat64Result) {
	ch <- getNAT64PrefixWithUpstream(req, u)
}

// getNAT64PrefixWithUpstream returns result of NAT64 prefix calculation with one upstream
func getNAT64PrefixWithUpstream(req *dns.Msg, u upstream.Upstream) nat64Result {
	resp, err := u.Exchange(req)
	if err != nil {
		return nat64Result{upstream: u, err: err}
	}

	prefix, err := getNAT64PrefixFromResponse(resp)
	if err != nil {
		return nat64Result{upstream: u, err: err}
	}

	return nat64Result{prefix: prefix, upstream: u}
}

// getNAT64PrefixParallel starts parallel NAT64 prefix calculation with all available upstreams
func (p *Proxy) getNAT64PrefixParallel() nat64Result {
	size := len(p.DNS64Upstreams)
	req := createIpv4ArpaMessage()
	if size == 1 {
		return getNAT64PrefixWithUpstream(req, p.DNS64Upstreams[0])
	}

	errs := []error{}
	ch := make(chan nat64Result, size)
	for _, u := range p.DNS64Upstreams {
		go getNAT64PrefixAsync(req, u, ch)
	}

	for {
		select {
		case rep := <-ch:
			if rep.err != nil {
				errs = append(errs, rep.err)
			}

			if len(errs) == size {
				return nat64Result{err: errorx.DecorateMany("Failed to get NAT64 prefix with all upstreams:", errs...)}
			}

			if len(rep.prefix) == 12 && rep.err == nil {
				return rep
			}
		}
	}
}

// getNAT64Prefix exchanges ipv4 arpa request with DNS64 upstreams and sets NAT64 prefix to the proxy
func (p *Proxy) getNAT64Prefix() {
	// First check if no DNS64 upstreams specified
	if len(p.DNS64Upstreams) == 0 {
		log.Tracef("no DNS64 upstream specified")
		return
	}

	// Do nothing if NAT64 prefix was not calculated
	if p.isNAT64PrefixAvailable() {
		return
	}

	res := p.getNAT64PrefixParallel()
	if res.err != nil {
		log.Tracef("Failed to calculate NAT64 prefix: %s", res.err)
		return
	}

	log.Tracef("Use %s server NAT64 prefix", res.upstream.Address())
	p.nat64Lock.Lock()
	p.nat64Prefix = res.prefix
	p.nat64Lock.Unlock()
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

	// add NAT 64 prefix for each ipv4 answer
	for _, ans := range res.Answer {
		i, ok := ans.(*dns.A)
		if !ok {
			continue
		}

		// new ip address
		mappedAddress := make(net.IP, net.IPv6len)

		// add NAT 64 prefix and append ipv4 record
		p.nat64Lock.Lock()
		copy(mappedAddress, p.nat64Prefix)
		p.nat64Lock.Unlock()
		for index, b := range i.A {
			mappedAddress[12+index] = b
		}

		// check if answer length not equals to IPv6len
		if len(mappedAddress) != net.IPv6len {
			return nil, fmt.Errorf("wrong count of bytes in the answer after DNS64 mapping: %d", len(mappedAddress))
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
