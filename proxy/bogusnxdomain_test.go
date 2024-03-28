package proxy

import (
	"context"
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
	prx := mustNew(t, &Config{
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		CacheEnabled:           true,
		BogusNXDomain: []netip.Prefix{
			netip.MustParsePrefix("4.3.2.1/24"),
			netip.MustParsePrefix("1.2.3.4/8"),
			netip.MustParsePrefix("10.11.12.13/32"),
			netip.MustParsePrefix("102:304:506:708:90a:b0c:d0e:f10/120"),
		},
	})

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

	ctx := context.Background()
	err := prx.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return prx.Shutdown(ctx) })

	d := &DNSContext{
		Req: newHostTestMessage("host"),
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
