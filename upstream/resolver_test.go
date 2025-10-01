package upstream_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUpstreamResolver(t *testing.T) {
	ups := &dnsproxytest.Upstream{
		OnAddress: func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(req)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: netip.MustParseAddr("1.2.3.4").AsSlice(),
			}}

			return resp, nil
		},
	}

	r := &upstream.UpstreamResolver{Upstream: ups}

	ipAddrs, err := r.LookupNetIP(context.Background(), "ip", "cloudflare-dns.com")
	require.NoError(t, err)

	assert.NotEmpty(t, ipAddrs)
}

func TestNewUpstreamResolver_validity(t *testing.T) {
	t.Parallel()

	withTimeoutOpt := &upstream.Options{
		Logger:  slogutil.NewDiscardLogger(),
		Timeout: 3 * time.Second,
	}

	testCases := []struct {
		name       string
		addr       string
		wantErrMsg string
	}{{
		name:       "udp",
		addr:       "1.1.1.1:53",
		wantErrMsg: "",
	}, {
		name:       "dot",
		addr:       "tls://1.1.1.1",
		wantErrMsg: "",
	}, {
		name:       "doh",
		addr:       "https://1.1.1.1/dns-query",
		wantErrMsg: "",
	}, {
		name:       "sdns",
		addr:       "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		wantErrMsg: "",
	}, {
		name:       "tcp",
		addr:       "tcp://9.9.9.9",
		wantErrMsg: "",
	}, {
		name: "invalid_tls",
		addr: "tls://dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_https",
		addr: "https://dns.adguard.com/dns-query",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_tcp",
		addr: "tcp://dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_no_scheme",
		addr: "dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := upstream.NewUpstreamResolver(tc.addr, withTimeoutOpt)
			if tc.wantErrMsg != "" {
				assert.Equal(t, tc.wantErrMsg, err.Error())
				if nberr := (&upstream.NotBootstrapError{}); errors.As(err, &nberr) {
					assert.NotNil(t, r)
				}

				return
			}

			require.NoError(t, err)

			addrs, err := r.LookupNetIP(context.Background(), "ip", "cloudflare-dns.com")
			require.NoError(t, err)

			assert.NotEmpty(t, addrs)
		})
	}
}

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

	ups := &dnsproxytest.Upstream{
		OnAddress:  func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:    func() (_ error) { panic(testutil.UnexpectedCall()) },
		OnExchange: onExchange,
	}

	r := upstream.NewCachingResolver(&upstream.UpstreamResolver{Upstream: ups})

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
		cached := r.FindCached(fqdn, now)
		require.ElementsMatch(t, []netip.Addr{ip4, ip6}, cached)

		cached = r.FindCached(fqdn, now.Add(smallTTL+time.Second))
		require.Empty(t, cached)
	})
}
