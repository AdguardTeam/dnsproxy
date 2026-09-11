package proxy

import (
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_IsBogusNXDomain(t *testing.T) {
	var ans []dns.RR

	onExchange := newECSReplyHandler(&ans, nil, nil)
	u := newTestECSUpstream(onExchange)

	upsConf := newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr)
	upsConf.Upstreams = []upstream.Upstream{u}

	prx := mustNew(t, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: upsConf,
		TrustedProxies: defaultTrustedProxies,
		CacheEnabled:   true,
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

	servicetest.RequireRun(t, prx, testTimeout)

	d := &DNSContext{
		Req: newHostTestMessage("host"),
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ans = tc.ans

			err := prx.Resolve(testutil.ContextWithTimeout(t, defaultTimeout), d)
			require.NoError(t, err)
			require.NotNil(t, d.Res)

			assert.Equal(t, tc.wantRcode, d.Res.Rcode)
		})
	}
}
