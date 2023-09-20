package proxy

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

const (
	// maxNAT64PrefixBitLen is the maximum length of a NAT64 prefix in bits.
	// See https://datatracker.ietf.org/doc/html/rfc6147#section-5.2.
	maxNAT64PrefixBitLen = 96

	// NAT64PrefixLength is the length of a NAT64 prefix in bytes.
	NAT64PrefixLength = net.IPv6len - net.IPv4len

	// maxDNS64SynTTL is the maximum TTL for synthesized DNS64 responses with no
	// SOA records in seconds.
	//
	// If the SOA RR was not delivered with the negative response to the AAAA
	// query, then the DNS64 SHOULD use the TTL of the original A RR or 600
	// seconds, whichever is shorter.
	//
	// See https://datatracker.ietf.org/doc/html/rfc6147#section-5.1.7.
	maxDNS64SynTTL uint32 = 600
)

// setupDNS64 initializes DNS64 settings, the NAT64 prefixes in particular.  If
// the DNS64 feature is enabled and no prefixes are configured, the default
// Well-Known Prefix is used, just like Section 5.2 of RFC 6147 prescribes.  Any
// configured set of prefixes discards the default Well-Known prefix unless it
// is specified explicitly.  Each prefix also validated to be a valid IPv6 CIDR
// with a maximum length of 96 bits.  The first specified prefix is then used to
// synthesize AAAA records.
func (p *Proxy) setupDNS64() (err error) {
	if !p.Config.UseDNS64 {
		return nil
	}

	l := len(p.Config.DNS64Prefs)
	if l == 0 {
		p.dns64Prefs = []netip.Prefix{dns64WellKnownPref}

		return nil
	}

	for i, pref := range p.Config.DNS64Prefs {
		if !pref.Addr().Is6() {
			return fmt.Errorf("prefix at index %d: %q is not an IPv6 prefix", i, pref)
		}

		if pref.Bits() > maxNAT64PrefixBitLen {
			return fmt.Errorf("prefix at index %d: %q is too long for DNS64", i, pref)
		}

		p.dns64Prefs = append(p.dns64Prefs, pref.Masked())
	}

	return nil
}

// checkDNS64 checks if DNS64 should be performed.  It returns a DNS64 request
// to resolve or nil if DNS64 is not desired.  It also filters resp to not
// contain any NAT64 excluded addresses in the answer section, if needed.  Both
// req and resp must not be nil.
//
// See https://datatracker.ietf.org/doc/html/rfc6147.
func (p *Proxy) checkDNS64(req, resp *dns.Msg) (dns64Req *dns.Msg) {
	if len(p.dns64Prefs) == 0 {
		return nil
	}

	q := req.Question[0]
	if q.Qtype != dns.TypeAAAA || q.Qclass != dns.ClassINET {
		// DNS64 operation for classes other than IN is undefined, and a DNS64
		// MUST behave as though no DNS64 function is configured.
		return nil
	}

	switch resp.Rcode {
	case dns.RcodeNameError:
		// A result with RCODE=3 (Name Error) is handled according to normal DNS
		// operation (which is normally to return the error to the client).
		return nil
	case dns.RcodeSuccess:
		// If resolver receives an answer with at least one AAAA record
		// containing an address outside any of the excluded range(s), then it
		// by default SHOULD build an answer section for a response including
		// only the AAAA record(s) that do not contain any of the addresses
		// inside the excluded ranges.
		var hasAnswers bool
		if resp.Answer, hasAnswers = p.filterNAT64Answers(resp.Answer); hasAnswers {
			return nil
		}
	default:
		// Any other RCODE is treated as though the RCODE were 0 and the answer
		// section were empty.
	}

	dns64Req = req.Copy()
	dns64Req.Id = dns.Id()
	dns64Req.Question[0].Qtype = dns.TypeA

	return dns64Req
}

// filterNAT64Answers filters out AAAA records that are within one of NAT64
// exclusion prefixes.  hasAnswers is true if the filtered slice contains at
// least a single AAAA answer not within the prefixes or a CNAME.
//
// TODO(e.burkov):  Remove prefs from args when old API is removed.
func (p *Proxy) filterNAT64Answers(
	rrs []dns.RR,
) (filtered []dns.RR, hasAnswers bool) {
	filtered = make([]dns.RR, 0, len(rrs))
	for _, ans := range rrs {
		switch ans := ans.(type) {
		case *dns.AAAA:
			addr, err := netutil.IPToAddrNoMapped(ans.AAAA)
			if err != nil {
				log.Error("proxy: bad aaaa record: %s", err)

				continue
			}

			if p.withinDNS64(addr) {
				// Filter the record.
				continue
			}

			filtered, hasAnswers = append(filtered, ans), true
		case *dns.CNAME, *dns.DNAME:
			// If the response contains a CNAME or a DNAME, then the CNAME or
			// DNAME chain is followed until the first terminating A or AAAA
			// record is reached.
			//
			// Just treat CNAME and DNAME responses as passable answers since
			// AdGuard Home doesn't follow any of these chains except the
			// dnsrewrite-defined ones.
			filtered, hasAnswers = append(filtered, ans), true
		default:
			filtered = append(filtered, ans)
		}
	}

	return filtered, hasAnswers
}

// synthDNS64 synthesizes a DNS64 response using the original response as a
// basis and modifying it with data from resp.  It returns true if the response
// was actually modified.
func (p *Proxy) synthDNS64(origReq, origResp, resp *dns.Msg) (ok bool) {
	if len(resp.Answer) == 0 {
		// If there is an empty answer, then the DNS64 responds to the original
		// querying client with the answer the DNS64 received to the original
		// (initiator's) query.
		return false
	}

	// The Time to Live (TTL) field is set to the minimum of the TTL of the
	// original A RR and the SOA RR for the queried domain.  If the original
	// response contains no SOA records, the minimum of the TTL of the original
	// A RR and [maxDNS64SynTTL] should be used.  See [maxDNS64SynTTL].
	soaTTL := maxDNS64SynTTL
	for _, rr := range origResp.Ns {
		if hdr := rr.Header(); hdr.Rrtype == dns.TypeSOA && hdr.Name == origReq.Question[0].Name {
			soaTTL = hdr.Ttl

			break
		}
	}

	newAns := make([]dns.RR, 0, len(resp.Answer))
	for _, ans := range resp.Answer {
		rr := p.synthRR(ans, soaTTL)
		if rr == nil {
			// The error should have already been logged.
			return false
		}

		newAns = append(newAns, rr)
	}

	origResp.Answer = newAns
	origResp.Ns = resp.Ns
	origResp.Extra = resp.Extra

	return true
}

// dns64WellKnownPref is the default prefix to use in an algorithmic mapping for
// DNS64.  See https://datatracker.ietf.org/doc/html/rfc6052#section-2.1.
var dns64WellKnownPref = netip.MustParsePrefix("64:ff9b::/96")

// withinDNS64 checks if ip is within one of the configured DNS64 prefixes.
//
// TODO(e.burkov):  We actually using bytes of only the first prefix from the
// set to construct the answer, so consider using some implementation of a
// prefix set for the rest.
func (p *Proxy) withinDNS64(ip netip.Addr) (ok bool) {
	for _, n := range p.dns64Prefs {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// shouldStripDNS64 returns true if DNS64 is enabled and ip has either one of
// custom DNS64 prefixes or the Well-Known one.  This is intended to be used
// with PTR requests.
//
// The requirement is to match any Pref64::/n used at the site, and not merely
// the locally configured Pref64::/n.  This is because end clients could ask for
// a PTR record matching an address received through a different (site-provided)
// DNS64.
//
// See https://datatracker.ietf.org/doc/html/rfc6147#section-5.3.1.
func (p *Proxy) shouldStripDNS64(ip net.IP) (ok bool) {
	if len(p.dns64Prefs) == 0 {
		return false
	}

	addr, err := netutil.IPToAddr(ip, netutil.AddrFamilyIPv6)
	if err != nil {
		return false
	}

	switch {
	case p.withinDNS64(addr):
		log.Debug("proxy: %s is within DNS64 custom prefix set", ip)
	case dns64WellKnownPref.Contains(addr):
		log.Debug("proxy: %s is within DNS64 well-known prefix", ip)
	default:
		return false
	}

	return true
}

// mapDNS64 maps addr to IPv6 address using configured DNS64 prefix.  addr must
// be a valid IPv4.  It panics, if there are no configured DNS64 prefixes,
// because synthesis should not be performed unless DNS64 function enabled.
//
// TODO(e.burkov):  Remove pref from args when old API is removed.
func (p *Proxy) mapDNS64(addr netip.Addr) (mapped net.IP) {
	// Don't mask the address here since it should have already been masked on
	// initialization stage.
	prefData := p.dns64Prefs[0].Addr().As16()
	addrData := addr.As4()

	mapped = make(net.IP, net.IPv6len)
	copy(mapped[:NAT64PrefixLength], prefData[:])
	copy(mapped[NAT64PrefixLength:], addrData[:])

	return mapped
}

// synthRR synthesizes a DNS64 resource record in compliance with RFC 6147.  If
// rr is not an A record, it's returned as is.  A records are modified to become
// a DNS64-synthesized AAAA records, and the TTL is set according to the
// original TTL of a record and soaTTL.  It returns nil on invalid A records.
func (p *Proxy) synthRR(rr dns.RR, soaTTL uint32) (result dns.RR) {
	aResp, ok := rr.(*dns.A)
	if !ok {
		return rr
	}

	addr, err := netutil.IPToAddr(aResp.A, netutil.AddrFamilyIPv4)
	if err != nil {
		log.Error("proxy: bad a record: %s", err)

		return nil
	}

	aaaa := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   aResp.Hdr.Name,
			Rrtype: dns.TypeAAAA,
			Class:  aResp.Hdr.Class,
			Ttl:    mathutil.Min(aResp.Hdr.Ttl, soaTTL),
		},
		AAAA: p.mapDNS64(addr),
	}

	return aaaa
}

// performDNS64 returns the upstream that was used to perform DNS64 request, or
// nil, if the request was not performed.
func (p *Proxy) performDNS64(
	origReq *dns.Msg,
	origResp *dns.Msg,
	upstreams []upstream.Upstream,
) (u upstream.Upstream) {
	if origResp == nil {
		return nil
	}

	dns64Req := p.checkDNS64(origReq, origResp)
	if dns64Req == nil {
		return nil
	}

	host := origReq.Question[0].Name
	log.Debug("proxy: received an empty aaaa response for %q, checking dns64", host)

	dns64Resp, u, err := p.exchange(dns64Req, upstreams)
	if err != nil {
		log.Error("proxy: dns64 request failed: %s", err)

		return nil
	}

	if dns64Resp != nil && p.synthDNS64(origReq, origResp, dns64Resp) {
		log.Debug("dnsforward: synthesized aaaa response for %q", host)

		return u
	}

	return nil
}
