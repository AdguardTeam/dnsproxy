package dnsmsg_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
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

// Common IP address strings for cache tests.
const (
	testCacheIPStr1 = "192.0.2.65"
	testCacheIPStr2 = "192.0.2.129"
)

// Common parsed IP addresses for cache tests.
var (
	testCacheIP1 net.IP = netip.MustParseAddr(testCacheIPStr1).AsSlice()
	testCacheIP2 net.IP = netip.MustParseAddr(testCacheIPStr2).AsSlice()
)

func TestCacheTTL(t *testing.T) {
	t.Parallel()

	question := []dns.Question{{
		Name:   dnsproxytest.FQDN,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}

	cnameRR := dnsproxytest.NewRR(
		t,
		dnsproxytest.FQDN,
		dns.TypeCNAME,
		testTTL,
		"alias."+dnsproxytest.FQDN,
	)
	soa := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeSOA, testTTL, nil)
	nsRR1 := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeNS, testTTL, "ns1."+dnsproxytest.FQDN)
	nsRR2 := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeNS, testTTL, "ns2."+dnsproxytest.FQDN)
	extra := []dns.RR{
		dnsproxytest.NewRR(t, "ns1."+dnsproxytest.FQDN, dns.TypeA, testTTL, testCacheIP1),
		dnsproxytest.NewRR(t, "ns2."+dnsproxytest.FQDN, dns.TypeA, testTTL, testCacheIP2),
	}

	// See https://datatracker.ietf.org/doc/html/rfc2308.
	testCases := []struct {
		req     *dns.Msg
		name    string
		wantTTL uint32
	}{{
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeNameError},
			Question: question,
			Answer:   []dns.RR{cnameRR},
			Ns:       []dns.RR{soa, nsRR1, nsRR2},
			Extra:    extra,
		},
		name:    "rfc2308_nxdomain_response_type_1",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeNameError},
			Question: question,
			Answer:   []dns.RR{cnameRR},
			Ns:       []dns.RR{soa},
		},
		name:    "rfc2308_nxdomain_response_type_2",
		wantTTL: testTTL,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeNameError},
			Question: question,
			Answer:   []dns.RR{cnameRR},
		},
		name:    "rfc2308_nxdomain_response_type_3",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeNameError},
			Question: question,
			Answer:   []dns.RR{cnameRR},
			Ns:       []dns.RR{nsRR1, nsRR2},
			Extra:    extra,
		},
		name:    "rfc2308_nxdomain_response_type_4",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Question: question,
			Answer:   []dns.RR{cnameRR},
			Ns:       []dns.RR{nsRR1, nsRR2},
			Extra:    extra,
		},
		name:    "rfc2308_nxdomain_referral_response",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeServerFailure},
			Question: question,
		},
		name:    "servfail_response",
		wantTTL: dnsmsg.ServFailMaxCacheTTL,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			assert.Equal(t, tc.wantTTL, dnsmsg.CacheTTL(ctx, testLogger, tc.req))
		})
	}
}

func TestCacheTTL_nodata(t *testing.T) {
	t.Parallel()

	question := dnsproxytest.NewTestRequest().Question
	soa := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeSOA, testTTL, nil)
	nsRR1 := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeNS, testTTL, "ns1."+dnsproxytest.FQDN)
	nsRR2 := dnsproxytest.NewRR(t, dnsproxytest.FQDN, dns.TypeNS, testTTL, "ns2."+dnsproxytest.FQDN)
	extra := []dns.RR{
		dnsproxytest.NewRR(t, "ns1."+dnsproxytest.FQDN, dns.TypeA, testTTL, testCacheIP1),
		dnsproxytest.NewRR(t, "ns2."+dnsproxytest.FQDN, dns.TypeA, testTTL, testCacheIP2),
	}

	// See https://datatracker.ietf.org/doc/html/rfc2308.
	testCases := []struct {
		req     *dns.Msg
		name    string
		wantTTL uint32
	}{{
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Question: question,
			Ns: []dns.RR{
				soa, nsRR1, nsRR2,
			},
			Extra: extra,
		},
		name:    "rfc2308_nodata_response_type_1",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Question: question,
			Ns:       []dns.RR{soa},
		},
		name:    "rfc2308_nodata_response_type_2",
		wantTTL: testTTL,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Question: question,
		},
		name:    "rfc2308_nodata_response_type_3",
		wantTTL: 0,
	}, {
		req: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Question: question,
			Ns:       []dns.RR{nsRR1, nsRR2},
			Extra:    extra,
		},
		name:    "rfc2308_nodata_referral_response",
		wantTTL: 0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			assert.Equal(t, tc.wantTTL, dnsmsg.CacheTTL(ctx, testLogger, tc.req))
		})
	}
}
