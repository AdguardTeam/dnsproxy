package proxy

import (
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_IsBogusNXDomain(t *testing.T) {
	prx := createTestProxy(t, nil)
	prx.CacheEnabled = true

	prx.BogusNXDomain = []netip.Prefix{
		netip.MustParsePrefix("4.3.2.1/24"),
		netip.MustParsePrefix("1.2.3.4/8"),
		netip.MustParsePrefix("10.11.12.13/32"),
		netip.MustParsePrefix("102:304:506:708:90a:b0c:d0e:f10/120"),
	}

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
	nets := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.0/24"),
		netip.MustParsePrefix("ffff::1.2.4.0/112"),
		netip.MustParsePrefix("102:304:506:708:90a:b0c:d0e:f00/120"),
	}

	testCases := []struct {
		want assert.BoolAssertionFunc
		ip   netip.Addr
		name string
	}{{
		name: "ipv4_yes",
		want: assert.True,
		ip:   netip.MustParseAddr("1.2.3.255"),
	}, {
		name: "ipv4_6_yes",
		want: assert.True,
		ip:   netip.MustParseAddr("ffff::1.2.4.254"),
	}, {
		name: "ipv6_yes",
		want: assert.True,
		ip:   netip.MustParseAddr("102:304:506:708:90a:b0c:d0e:f0f"),
	}, {
		name: "ipv6_4_yes",
		want: assert.True,
		ip:   netip.MustParseAddr("ffff::1.2.3.0"),
	}, {
		name: "ipv4_no",
		want: assert.False,
		ip:   netip.MustParseAddr("2.1.3.255"),
	}, {
		name: "ipv4_6_no",
		want: assert.False,
		ip:   netip.MustParseAddr("2.1.4.254"),
	}, {
		name: "ipv6_no",
		want: assert.False,
		ip:   netip.MustParseAddr("102:304:506:708:90a:b0c:d0e:10f"),
	}, {
		name: "ipv6_4_no",
		want: assert.False,
		ip:   netip.MustParseAddr("ffff::2.1.4.0"),
	}, {
		name: "invalid",
		want: assert.False,
		ip:   netip.Addr{},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.want(t, containsIP(nets, tc.ip))
		})
	}
}
