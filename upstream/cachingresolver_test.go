package upstream_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	proxytest "github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachingResolver_staleness(t *testing.T) {
	ip4 := netip.MustParseAddr("192.0.2.1")
	ip6 := netip.MustParseAddr("2001:db8::1")

	const (
		smallTTL = 10 * time.Second
		largeTTL = 1000 * time.Second
	)

	onExchange := func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
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
			pt := testutil.NewPanicT(t)
			require.Contains(pt, []uint16{dns.TypeA, dns.TypeAAAA}, q.Qtype)
		}
		resp.Answer = append(resp.Answer, rr)

		return resp, nil
	}

	ups := &dnsproxytest.Upstream{
		OnAddress:  func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:    func() (_ error) { panic(testutil.UnexpectedCall()) },
		OnExchange: onExchange,
	}

	r := upstream.NewCachingResolver(&upstream.UpstreamResolver{
		Clock:    &timeutil.SystemClock{},
		Upstream: ups,
	})

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
				ctx := testutil.ContextWithTimeout(t, testTimeout)
				res, err := r.LookupNetIP(ctx, tc.network, proxytest.FQDN)
				require.NoError(t, err)

				assert.ElementsMatch(t, tc.want, res)
			})
		}
	}))

	t.Run("staleness", func(t *testing.T) {
		now := time.Now()
		cached := r.FindCached(proxytest.FQDN, bootstrap.NetworkIP, now)
		require.ElementsMatch(t, []netip.Addr{ip4, ip6}, cached)

		cached = r.FindCached(
			proxytest.FQDN,
			bootstrap.NetworkIP,
			now.Add(smallTTL+time.Second),
		)
		require.Empty(t, cached)
	})
}

// newTestUpstreamResolver returns a new upstream resolver with the upstream
// mock that answers using onExchange.
func newTestUpstreamResolver(
	tb testing.TB,
	clock timeutil.Clock,
	onExchange func(req *dns.Msg) (resp *dns.Msg),
) (r *upstream.UpstreamResolver) {
	tb.Helper()

	ups := &dnsproxytest.Upstream{
		OnAddress: func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
		OnExchange: func(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			return onExchange(req), nil
		},
	}

	return &upstream.UpstreamResolver{
		Upstream: ups,
		Logger:   testLogger,
		Clock:    clock,
	}
}

// newOnExchange returns a new Exchange function for the upstream mock that
// always responds with the given rcode.
func newOnExchange(tb testing.TB, rcode int) (f func(req *dns.Msg) (resp *dns.Msg)) {
	tb.Helper()

	onExchange := func(req *dns.Msg) (resp *dns.Msg) {
		resp = (&dns.Msg{}).SetReply(req)
		resp.Rcode = rcode

		return resp
	}

	return onExchange
}

const soaTTL = 40

// onExchangeWithSOA is a common Exchange function for the upstream mock that
// always responds with NXDOMAIN and includes a SOA record.
var onExchangeWithSOA = func(req *dns.Msg) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetReply(req)
	resp.Rcode = dns.RcodeNameError

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   proxytest.FQDN,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    soaTTL,
		},
		Ns:      "ns." + proxytest.FQDN,
		Mbox:    "hostmaster." + proxytest.FQDN,
		Serial:  1,
		Refresh: 1,
		Retry:   1,
		Expire:  1,
		Minttl:  1,
	}

	resp.Ns = []dns.RR{soa}

	return resp
}

func TestUpstreamResolver_RequestResult_expire(t *testing.T) {
	const servFailTTL = 30

	now := time.Now()
	clock := &faketime.Clock{
		OnNow: func() time.Time {
			return now
		},
	}

	testCases := []struct {
		resolver   *upstream.UpstreamResolver
		name       string
		wantExpire time.Duration
	}{{
		name:       "empty_no_error",
		resolver:   newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeSuccess)),
		wantExpire: 0,
	}, {
		name:       "nxdomain_no_soa",
		resolver:   newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeNameError)),
		wantExpire: 0,
	}, {
		name:       "nxdomain_with_soa",
		resolver:   newTestUpstreamResolver(t, clock, onExchangeWithSOA),
		wantExpire: soaTTL * time.Second,
	}, {
		name:       "servfail",
		resolver:   newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeServerFailure)),
		wantExpire: servFailTTL * time.Second,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			addrs, expire, err := tc.resolver.RequestResult(
				ctx,
				proxytest.FQDN,
				bootstrap.NetworkIP4,
			)
			require.Empty(t, addrs)
			require.NotNil(t, addrs)
			require.Equal(t, now.Add(tc.wantExpire), expire)
			require.NoError(t, err)
		})
	}
}

func TestCachingResolver_LookupNetIP_empty(t *testing.T) {
	now := time.Now()
	clock := &faketime.Clock{
		OnNow: func() time.Time {
			return now
		},
	}

	testCases := []struct {
		resolver *upstream.UpstreamResolver
		name     string
	}{{
		name:     "empty_no_error",
		resolver: newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeSuccess)),
	}, {
		name:     "nxdomain_no_soa",
		resolver: newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeNameError)),
	}, {
		name:     "nxdomain_with_soa",
		resolver: newTestUpstreamResolver(t, clock, onExchangeWithSOA),
	}, {
		name:     "servfail",
		resolver: newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeServerFailure)),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := upstream.NewCachingResolver(tc.resolver)

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			addrs, err := r.LookupNetIP(ctx, bootstrap.NetworkIP, proxytest.FQDN)
			require.NoError(t, err)
			require.Empty(t, addrs)

			// The first call to LookupNetIP should not cache the result because
			// it is empty.  Thus, the cache should not contain any entry for
			// this query. Therefore, the result should be nil.
			require.Nil(t, r.FindCached(proxytest.FQDN, bootstrap.NetworkIP, now))
		})
	}
}
