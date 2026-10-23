package dnsmsg_test

import (
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// testTimeout is the common timeout value for tests.
var testTimeout = 1 * time.Second

// testTTL is the common TTL value for tests.
const testTTL = 3600

// Shared consts.
const (
	anotherHostname = "ANOTHER.EXAMPLE."
	mbox            = "HOSTMASTER.NS1.XX."
	ns1, ns2        = "NS1.XX.", "NS2.XX."
	xx              = "XX."
)

func TestCacheTTL(t *testing.T) {
	const (
		hostname = "AN.EXAMPLE."
		cname    = "TRIPPLE.XX."
	)

	// See https://datatracker.ietf.org/doc/html/rfc2308.
	testCases := []struct {
		req     *dns.Msg
		name    string
		wantTTL uint32
	}{{
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeNameError),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
			Ns: []dns.RR{
				soaAns(xx, ns1, mbox),
				nsAns(xx, ns1),
				nsAns(xx, ns2),
			},
			Extra: []dns.RR{
				aAns(ns1, net.IP{127, 0, 0, 2}),
				aAns(ns2, net.IP{127, 0, 0, 3}),
			},
		},
		name:    "rfc2308_nxdomain_response_type_1",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeNameError),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
			Ns:       []dns.RR{soaAns("XX.", ns1, mbox)},
		},
		name:    "rfc2308_nxdomain_response_type_2",
		wantTTL: testTTL,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeNameError),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
		},
		name:    "rfc2308_nxdomain_response_type_3",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeNameError),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
			Ns: []dns.RR{
				nsAns(xx, ns1),
				nsAns(xx, ns2),
			},
			Extra: []dns.RR{
				aAns(ns1, net.IP{127, 0, 0, 2}),
				aAns(ns2, net.IP{127, 0, 0, 3}),
			},
		},
		name:    "rfc2308_nxdomain_response_type_4",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeSuccess),
			Question: aQuestions(hostname),
			Answer:   []dns.RR{cnameAns(hostname, cname)},
			Ns: []dns.RR{
				nsAns(xx, ns1),
				nsAns(xx, ns2),
			},
			Extra: []dns.RR{
				aAns(ns1, net.IP{127, 0, 0, 2}),
				aAns(ns2, net.IP{127, 0, 0, 3}),
			},
		},
		name:    "rfc2308_nxdomain_referral_response",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   msgHdr(dns.RcodeServerFailure),
			Question: aQuestions(anotherHostname),
		},
		name:    "servfail_response",
		wantTTL: dnsmsg.ServFailMaxCacheTTL,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			assert.Equal(t, tc.wantTTL, dnsmsg.CacheTTL(ctx, testLogger, tc.req))
		})
	}
}

func TestCacheTTL_nodata_responses(t *testing.T) {
	testCases := []struct {
		req     *dns.Msg
		name    string
		wantTTL uint32
	}{
		{
			req: &dns.Msg{
				MsgHdr:   msgHdr(dns.RcodeSuccess),
				Question: aQuestions(anotherHostname),
				Ns: []dns.RR{
					soaAns(xx, ns1, mbox),
					nsAns(xx, ns1),
					nsAns(xx, ns2),
				},
				Extra: []dns.RR{
					aAns(ns1, net.IP{127, 0, 0, 2}),
					aAns(ns2, net.IP{127, 0, 0, 3}),
				},
			},
			name:    "rfc2308_nodata_response_type_1",
			wantTTL: 0,
		}, {
			req: &dns.Msg{
				MsgHdr:   msgHdr(dns.RcodeSuccess),
				Question: aQuestions(anotherHostname),
				Ns:       []dns.RR{soaAns(xx, ns1, mbox)},
			},
			name:    "rfc2308_nodata_response_type_2",
			wantTTL: testTTL,
		}, {
			req: &dns.Msg{
				MsgHdr:   msgHdr(dns.RcodeSuccess),
				Question: aQuestions(anotherHostname),
			},
			name:    "rfc2308_nodata_response_type_3",
			wantTTL: 0,
		}, {
			req: &dns.Msg{
				MsgHdr:   msgHdr(dns.RcodeSuccess),
				Question: aQuestions(anotherHostname),
				Ns: []dns.RR{
					nsAns(xx, ns1),
					nsAns(xx, ns2),
				},
				Extra: []dns.RR{
					aAns(ns1, net.IP{127, 0, 0, 2}),
					aAns(ns2, net.IP{127, 0, 0, 3}),
				},
			},
			name:    "rfc2308_nodata_referral_response",
			wantTTL: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			assert.Equal(t, tc.wantTTL, dnsmsg.CacheTTL(ctx, testLogger, tc.req))
		})
	}
}

// msgHdr creates a new DNS message header with the given response code.
func msgHdr(rcode int) (hdr dns.MsgHdr) {
	return dns.MsgHdr{Id: dns.Id(), Rcode: rcode}
}

// aQuestions creates a slice containing a single DNS question for the given
// name with type A and class INET.
func aQuestions(name string) (q []dns.Question) {
	return []dns.Question{{
		Name:   name,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
}

// cnameAns creates a CNAME DNS resource record with the given name and target
// CNAME.
func cnameAns(name, cname string) (rr dns.RR) {
	return &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    testTTL,
		},
		Target: cname,
	}
}

// soaAns creates an SOA DNS resource record with the given name, primary NS,
// and mailbox.
func soaAns(name, ns, mbox string) (rr dns.RR) {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    testTTL,
		},
		Ns:   ns,
		Mbox: mbox,
	}
}

// nsAns creates an NS DNS resource record with the given name and authoritative
// NS.
func nsAns(name, ns string) (rr dns.RR) {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    testTTL,
		},
		Ns: ns,
	}
}

// aAns creates an A DNS resource record with the given name and IP address.
func aAns(name string, a net.IP) (rr dns.RR) {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    testTTL,
		},
		A: a,
	}
}
