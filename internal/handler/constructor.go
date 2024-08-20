package handler

import (
	"net/netip"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/miekg/dns"
)

// messageConstructor is an extension of the [proxy.MessageConstructor]
// interface that also provides methods for creating DNS responses.
type messageConstructor interface {
	proxy.MessageConstructor

	// NewCompressedResponse creates a new compressed response message for req
	// with the given response code.
	NewCompressedResponse(req *dns.Msg, code int) (resp *dns.Msg)

	// NewPTRAnswer creates a new resource record for PTR response with the
	// given FQDN and PTR domain.
	NewPTRAnswer(fqdn, ptrDomain string) (ans *dns.PTR)

	// NewIPResponse creates a new A/AAAA response message for req with the
	// given IP addresses.  All IP addresses must be of the same family.
	NewIPResponse(req *dns.Msg, ips []netip.Addr) (resp *dns.Msg)
}

// defaultConstructor is a wrapper for [proxy.MessageConstructor] that also
// implements the [messageConstructor] interface.
//
// TODO(e.burkov):  This implementation reflects the one from AdGuard Home,
// consider moving it to [golibs].
type defaultConstructor struct {
	proxy.MessageConstructor
}

// type check
var _ messageConstructor = defaultConstructor{}

// NewCompressedResponse implements the [messageConstructor] interface for
// defaultConstructor.
func (defaultConstructor) NewCompressedResponse(req *dns.Msg, code int) (resp *dns.Msg) {
	resp = reply(req, code)
	resp.Compress = true

	return resp
}

// NewPTRAnswer implements the [messageConstructor] interface for
// [defaultConstructor].
func (defaultConstructor) NewPTRAnswer(fqdn, ptrDomain string) (ans *dns.PTR) {
	return &dns.PTR{
		Hdr: hdr(fqdn, dns.TypePTR),
		Ptr: ptrDomain,
	}
}

// NewIPResponse implements the [messageConstructor] interface for
// [defaultConstructor]
func (c defaultConstructor) NewIPResponse(req *dns.Msg, ips []netip.Addr) (resp *dns.Msg) {
	var ans []dns.RR
	switch req.Question[0].Qtype {
	case dns.TypeA:
		ans = genAnswersWithIPv4s(req, ips)
	case dns.TypeAAAA:
		for _, ip := range ips {
			if ip.Is6() {
				ans = append(ans, newAnswerAAAA(req, ip))
			}
		}
	default:
		// Go on and return an empty response.
	}

	resp = c.NewCompressedResponse(req, dns.RcodeSuccess)
	resp.Answer = ans

	return resp
}

// defaultResponseTTL is the default TTL for the DNS responses in seconds.
const defaultResponseTTL = 10

// hdr creates a new DNS header with the given name and RR type.
func hdr(name string, rrType uint16) (h dns.RR_Header) {
	return dns.RR_Header{
		Name:   name,
		Rrtype: rrType,
		Ttl:    defaultResponseTTL,
		Class:  dns.ClassINET,
	}
}

// reply creates a DNS response for req.
func reply(req *dns.Msg, code int) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetRcode(req, code)
	resp.RecursionAvailable = true

	return resp
}

// newAnswerA creates a DNS A answer for req with the given IP address.
func newAnswerA(req *dns.Msg, ip netip.Addr) (ans *dns.A) {
	return &dns.A{
		Hdr: hdr(req.Question[0].Name, dns.TypeA),
		A:   ip.AsSlice(),
	}
}

// newAnswerAAAA creates a DNS AAAA answer for req with the given IP address.
func newAnswerAAAA(req *dns.Msg, ip netip.Addr) (ans *dns.AAAA) {
	return &dns.AAAA{
		Hdr:  hdr(req.Question[0].Name, dns.TypeAAAA),
		AAAA: ip.AsSlice(),
	}
}

// genAnswersWithIPv4s generates DNS A answers provided IPv4 addresses.  If any
// of the IPs isn't an IPv4 address, genAnswersWithIPv4s logs a warning and
// returns nil,
func genAnswersWithIPv4s(req *dns.Msg, ips []netip.Addr) (ans []dns.RR) {
	for _, ip := range ips {
		if !ip.Is4() {
			return nil
		}

		ans = append(ans, newAnswerA(req, ip))
	}

	return ans
}
