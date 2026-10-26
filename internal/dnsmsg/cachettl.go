package dnsmsg

import (
	"context"
	"log/slog"
	"math"
	"slices"

	"github.com/miekg/dns"
)

// ServFailMaxCacheTTL is the maximum time-to-live value for caching
// SERVFAIL responses in seconds.  It's consistent with the upper constraint
// of 5 minutes given by RFC 2308.
//
// See https://datatracker.ietf.org/doc/html/rfc2308#section-7.1.
const ServFailMaxCacheTTL = 30

// CacheTTL returns the number of seconds for which m is valid to be cached.
// For negative answers it follows RFC 2308 on how to cache NXDOMAIN and NODATA
// kinds of responses.  l must not be nil.
//
// See https://datatracker.ietf.org/doc/html/rfc2308#section-2.1,
// https://datatracker.ietf.org/doc/html/rfc2308#section-2.2.
func CacheTTL(ctx context.Context, l *slog.Logger, m *dns.Msg) (ttl uint32) {
	switch {
	case m == nil:
		return 0
	case m.Truncated:
		l.DebugContext(ctx, "truncated message; not caching")

		return 0
	case len(m.Question) != 1:
		l.DebugContext(ctx, "message with wrong number of questions; not caching")

		return 0
	default:
		ttl = calculateTTL(m)
		if ttl == 0 {
			l.DebugContext(ctx, "ttl calculated to be 0; not caching")

			return 0
		}
	}

	switch rcode := m.Rcode; rcode {
	case dns.RcodeSuccess:
		if isCacheableSucceded(m) {
			return ttl
		}

		l.DebugContext(ctx, "not a cacheable noerror response; not caching")
	case dns.RcodeNameError:
		if isCacheableNegative(m) {
			return ttl
		}

		l.DebugContext(ctx, "not a cacheable nxdomain response; not caching")
	case dns.RcodeServerFailure:
		l.DebugContext(ctx, "server failure response; caching", "ttl", ttl)

		return ttl
	default:
		l.DebugContext(ctx, "response code; not caching", "rcode", dns.RcodeToString[rcode])
	}

	return 0
}

// calculateTTL returns the number of seconds for which m could be cached.  It's
// usually the lowest TTL among all m's resource records.  It returns 0 if m
// isn't cacheable according to it's contents.
func calculateTTL(m *dns.Msg) (ttl uint32) {
	// Use the maximum value as a guard value.  If the inner loop is entered,
	// it's going to be rewritten with an actual TTL value that is lower than
	// MaxUint32.  If the inner loop isn't entered, catch that and return zero.
	ttl = math.MaxUint32
	for _, rrset := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range rrset {
			ttl = minTTL(rr.Header(), ttl)
			if ttl == 0 {
				return 0
			}
		}
	}

	switch {
	case m.Rcode == dns.RcodeServerFailure && ttl > ServFailMaxCacheTTL:
		return ServFailMaxCacheTTL
	case ttl == math.MaxUint32:
		return 0
	default:
		return ttl
	}
}

// minTTL returns the minimum of h's ttl and the passed ttl.
func minTTL(h *dns.RR_Header, ttl uint32) uint32 {
	switch {
	case h.Rrtype == dns.TypeOPT:
		return ttl
	case h.Ttl < ttl:
		return h.Ttl
	default:
		return ttl
	}
}

// isCacheableSucceded returns true if m contains useful data to be cached
// treating it as a successful response.
func isCacheableSucceded(m *dns.Msg) (ok bool) {
	qType := m.Question[0].Qtype

	return (qType != dns.TypeA && qType != dns.TypeAAAA) || hasIPAns(m) || isCacheableNegative(m)
}

// hasIPAns check the m for containing at least one A or AAAA RR in answer
// section.  m must not be nil.
func hasIPAns(m *dns.Msg) (ok bool) {
	return slices.ContainsFunc(m.Answer, func(rr dns.RR) bool {
		t := rr.Header().Rrtype

		return t == dns.TypeA || t == dns.TypeAAAA
	})
}

// isCacheableNegative returns true if m's header has at least a single SOA RR
// and no NS records so that it can be declared authoritative.  m must not be
// nil.
//
// See https://datatracker.ietf.org/doc/html/rfc2308#section-5 for the
// information on the responses from the authoritative server that should be
// cached by the forwarder.
func isCacheableNegative(m *dns.Msg) (ok bool) {
	for _, rr := range m.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			ok = true
		case dns.TypeNS:
			return false
		default:
			// Go on.
		}
	}

	return ok
}
