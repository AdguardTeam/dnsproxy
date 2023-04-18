package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_IsBogusNXDomain(t *testing.T) {
	prx := createTestProxy(t, nil)
	prx.CacheEnabled = true

	prx.BogusNXDomain = []*net.IPNet{{
		IP:   net.IP{4, 3, 2, 1},
		Mask: net.CIDRMask(24, netutil.IPv4BitLen),
	}, {
		IP:   net.IPv4(1, 2, 3, 4),
		Mask: net.IPv4Mask(255, 0, 0, 0),
	}, {
		IP:   net.IP{10, 11, 12, 13},
		Mask: net.CIDRMask(netutil.IPv4BitLen, netutil.IPv4BitLen),
	}, {
		IP:   net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Mask: net.CIDRMask(120, netutil.IPv6BitLen),
	}}

	testCases := []struct {
		name      string
		ans       []dns.RR
		wantRcode int
	}{{
		name: "bogus_subnet",
		ans: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 10},
			A:   net.ParseIP("4.3.2.1"),
		}},
		wantRcode: dns.RcodeNameError,
	}, {
		name: "bogus_big_subnet",
		ans: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 10},
			A:   net.ParseIP("1.254.254.254"),
		}},
		wantRcode: dns.RcodeNameError,
	}, {
		name: "bogus_single_ip",
		ans: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 10},
			A:   net.ParseIP("10.11.12.13"),
		}},
		wantRcode: dns.RcodeNameError,
	}, {
		name: "bogus_6",
		ans: []dns.RR{&dns.AAAA{
			Hdr:  dns.RR_Header{Rrtype: dns.TypeAAAA, Name: "host.", Ttl: 10},
			AAAA: net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 99},
		}},
		wantRcode: dns.RcodeNameError,
	}, {
		name: "non-bogus",
		ans: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 10},
			A:   net.ParseIP("10.11.12.14"),
		}},
		wantRcode: dns.RcodeSuccess,
	}, {
		name: "non-bogus_6",
		ans: []dns.RR{&dns.AAAA{
			Hdr:  dns.RR_Header{Rrtype: dns.TypeAAAA, Name: "host.", Ttl: 10},
			AAAA: net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 15},
		}},
		wantRcode: dns.RcodeSuccess,
	}}

	u := testUpstream{}
	prx.UpstreamConfig.Upstreams = []upstream.Upstream{&u}

	err := prx.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, prx.Stop)

	d := &DNSContext{
		Req: createHostTestMessage("host"),
	}

	for _, tc := range testCases {
		u.ans = tc.ans

		t.Run(tc.name, func(t *testing.T) {
			err = prx.Resolve(d)
			require.NoError(t, err)
			require.NotNil(t, d.Res)

			assert.Equal(t, tc.wantRcode, d.Res.Rcode)
		})
	}
}

func TestContainsIP(t *testing.T) {
	nets := []*net.IPNet{{
		// IPv4.
		IP:   net.IP{1, 2, 3, 0},
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}, {
		// IPv6 from IPv4.
		IP:   net.IPv4(1, 2, 4, 0),
		Mask: net.CIDRMask(16, 32),
	}, {
		// IPv6.
		IP:   net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0},
		Mask: net.CIDRMask(120, net.IPv6len*8),
	}}

	testCases := []struct {
		name string
		want assert.BoolAssertionFunc
		ip   net.IP
	}{{
		name: "ipv4_yes",
		want: assert.True,
		ip:   net.IP{1, 2, 3, 255},
	}, {
		name: "ipv4_6_yes",
		want: assert.True,
		ip:   net.IPv4(1, 2, 4, 254),
	}, {
		name: "ipv6_yes",
		want: assert.True,
		ip:   net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}, {
		name: "ipv6_4_yes",
		want: assert.True,
		ip:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 0},
	}, {
		name: "ipv4_no",
		want: assert.False,
		ip:   net.IP{2, 1, 3, 255},
	}, {
		name: "ipv4_6_no",
		want: assert.False,
		ip:   net.IPv4(2, 1, 4, 254),
	}, {
		name: "ipv6_no",
		want: assert.False,
		ip:   net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 15},
	}, {
		name: "ipv6_4_no",
		want: assert.False,
		ip:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 2, 1, 4, 0},
	}, {
		name: "nil_no",
		want: assert.False,
		ip:   nil,
	}, {
		name: "bad_ip",
		want: assert.False,
		ip:   net.IP{42},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.want(t, containsIP(nets, tc.ip))
		})
	}
}
