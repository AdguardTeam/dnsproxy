package upstream

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachingResolver_staleness(t *testing.T) {
	ip4 := netip.MustParseAddr("1.2.3.4")
	ip6 := netip.MustParseAddr("2001:db8::1")

	const (
		smallTTL = 10 * time.Second
		largeTTL = 1000 * time.Second

		fqdn = "test.fully.qualified.name."
	)

	onExchange := func(req *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(req)

		hdr := dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: req.Question[0].Qtype,
			Class:  dns.ClassINET,
		}
		var rr dns.RR
		switch q := req.Question[0]; q.Qtype {
		case dns.TypeA:
			hdr.Ttl = uint32(smallTTL.Seconds())
			rr = &dns.A{Hdr: hdr, A: ip4.AsSlice()}
		case dns.TypeAAAA:
			hdr.Ttl = uint32(largeTTL.Seconds())
			rr = &dns.AAAA{Hdr: hdr, AAAA: ip6.AsSlice()}
		default:
			require.Contains(testutil.PanicT{}, []uint16{dns.TypeA, dns.TypeAAAA}, q.Qtype)
		}
		resp.Answer = append(resp.Answer, rr)

		return resp, nil
	}

	ups := &dnsproxytest.FakeUpstream{
		OnAddress:  func() (_ string) { panic("not implemented") },
		OnClose:    func() (_ error) { panic("not implemented") },
		OnExchange: onExchange,
	}

	r := NewCachingResolver(&UpstreamResolver{Upstream: ups})

	require.True(t, t.Run("resolve", func(t *testing.T) {
		testCases := []struct {
			name    string
			network bootstrap.Network
			want    []netip.Addr
		}{{
			name:    "ip4",
			network: bootstrap.NetworkIP4,
			want:    []netip.Addr{ip4},
		}, {
			name:    "ip6",
			network: bootstrap.NetworkIP6,
			want:    []netip.Addr{ip6},
		}, {
			name:    "both",
			network: bootstrap.NetworkIP,
			want:    []netip.Addr{ip4, ip6},
		}}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if tc.name != "both" {
					t.Skip(`TODO(e.burkov):  Bootstrap now only uses "ip" network, see TODO there.`)
				}

				res, err := r.LookupNetIP(context.Background(), tc.network, fqdn)
				require.NoError(t, err)

				assert.ElementsMatch(t, tc.want, res)
			})
		}
	}))

	t.Run("staleness", func(t *testing.T) {
		now := time.Now()
		cached := r.findCached(fqdn, now)
		require.ElementsMatch(t, []netip.Addr{ip4, ip6}, cached)

		cached = r.findCached(fqdn, now.Add(smallTTL+time.Second))
		require.Empty(t, cached)
	})
}
