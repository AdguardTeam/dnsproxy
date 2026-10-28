package upstream_test

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	intdnsproxytest "github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testIPv4 is a common IPv4 for tests.
const testIPv4 = "192.0.2.1"

func TestCachingResolver_staleness(t *testing.T) {
	ip4 := netip.MustParseAddr(testIPv4)
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
			require.Contains(t, []uint16{dns.TypeA, dns.TypeAAAA}, q.Qtype)
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
		Upstream: ups,
		Logger:   testLogger,
		Clock:    &timeutil.SystemClock{},
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
				res, err := r.LookupNetIP(ctx, tc.network, intdnsproxytest.FQDN)
				require.NoError(t, err)

				assert.ElementsMatch(t, tc.want, res)
			})
		}
	}))

	t.Run("staleness", func(t *testing.T) {
		now := time.Now()
		cached := r.FindCached(intdnsproxytest.FQDN, bootstrap.NetworkIP4, now)
		require.ElementsMatch(t, []netip.Addr{ip4}, cached)

		cached = r.FindCached(
			intdnsproxytest.FQDN,
			bootstrap.NetworkIP4,
			now.Add(smallTTL+time.Second),
		)
		require.Empty(t, cached)
	})
}

// newTestUpstreamResolver returns a new upstream resolver with the upstream
// mock that answers using onExchange and panics on if Exchange is called more
// than maxCalls times.
func newTestUpstreamResolver(
	tb testing.TB,
	clock timeutil.Clock,
	onExchange func(req *dns.Msg) (resp *dns.Msg, err error),
	maxCalls int32,
) (r *upstream.UpstreamResolver) {
	tb.Helper()

	cnt := &atomic.Int32{}

	ups := &dnsproxytest.Upstream{
		OnAddress: func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
		OnExchange: func(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			if cnt.Load() >= maxCalls {
				panic(testutil.UnexpectedCall(ctx, req))
			}

			cnt.Add(1)

			return onExchange(req)
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
func newOnExchange(tb testing.TB, rcode int) (f func(req *dns.Msg) (resp *dns.Msg, err error)) {
	tb.Helper()

	onExchange := func(req *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(req)
		resp.Rcode = rcode

		return resp, nil
	}

	return onExchange
}

const soaTTL = 40

// onExchangeWithSOA is a common Exchange function for the upstream mock that
// always responds with NXDOMAIN and includes a SOA record.
var onExchangeWithSOA = func(req *dns.Msg) (resp *dns.Msg, err error) {
	resp = (&dns.Msg{}).SetReply(req)
	resp.Rcode = dns.RcodeNameError

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   intdnsproxytest.FQDN,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    soaTTL,
		},
		Ns:      "ns." + intdnsproxytest.FQDN,
		Mbox:    "hostmaster." + intdnsproxytest.FQDN,
		Serial:  1,
		Refresh: 1,
		Retry:   1,
		Expire:  1,
		Minttl:  1,
	}

	resp.Ns = []dns.RR{soa}

	return resp, nil
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
		resolver:   newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeSuccess), 1),
		wantExpire: 0,
	}, {
		name:       "nxdomain_no_soa",
		resolver:   newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeNameError), 1),
		wantExpire: 0,
	}, {
		name:       "nxdomain_with_soa",
		resolver:   newTestUpstreamResolver(t, clock, onExchangeWithSOA, 1),
		wantExpire: soaTTL * time.Second,
	}, {
		name:       "servfail",
		resolver:   newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeServerFailure), 1),
		wantExpire: servFailTTL * time.Second,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			addrs, expire, err := tc.resolver.RequestResult(
				ctx,
				intdnsproxytest.FQDN,
				bootstrap.NetworkIP4,
			)
			require.Empty(t, addrs)
			require.Equal(t, now.Add(tc.wantExpire), expire)
			require.NoError(t, err)
		})
	}
}

func TestCachingResolver_LookupNetIP(t *testing.T) {
	now := time.Now()
	clock := &faketime.Clock{
		OnNow: func() time.Time {
			return now
		},
	}

	testCases := []struct {
		resolver   *upstream.UpstreamResolver
		name       string
		wantCached bool
	}{{
		name:       "empty_no_error",
		resolver:   newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeSuccess), 2),
		wantCached: false,
	}, {
		name:       "nxdomain_no_soa",
		resolver:   newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeNameError), 2),
		wantCached: false,
	}, {
		name:       "nxdomain_with_soa",
		resolver:   newTestUpstreamResolver(t, clock, onExchangeWithSOA, 2),
		wantCached: true,
	}, {
		name:       "servfail",
		resolver:   newTestUpstreamResolver(t, clock, newOnExchange(t, dns.RcodeServerFailure), 2),
		wantCached: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := upstream.NewCachingResolver(tc.resolver)

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			addrs, err := r.LookupNetIP(ctx, bootstrap.NetworkIP, intdnsproxytest.FQDN)
			require.NoError(t, err)
			require.Empty(t, addrs)

			// TODO(m.kazantsev): !! This should panic, as we don't cache empty
			// responses anymore.  There are exact four calls to the Exchange
			// method, two for each call to LookupNetIP.  Some reason, panic is
			// not caught as expected and the test fails.
			/*
				require.Panics(t, func() {
					addrs, err = r.LookupNetIP(ctx, bootstrap.NetworkIP, intdnsproxytest.FQDN)
				})
				require.NoError(t, err)
				require.Empty(t, addrs)
			*/
		})
	}
}

func TestCachingResolver_LookupNetIP_concurrent(t *testing.T) {
	t.Parallel()

	const attemptNum = 3

	now := time.Now()
	clock := &faketime.Clock{
		OnNow: func() time.Time {
			return now
		},
	}

	addr := netip.MustParseAddr(testIPv4)
	ip := addr.AsSlice()

	onExchange := func(req *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(req)
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: ip,
		})

		return resp, nil
	}

	r := upstream.NewCachingResolver(
		newTestUpstreamResolver(t, clock, onExchange, 1),
	)

	wg := &sync.WaitGroup{}
	pt := testutil.NewPanicT(t)

	for range attemptNum {
		wg.Go(func() {
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			addrs, err := r.LookupNetIP(ctx, bootstrap.NetworkIP4, intdnsproxytest.FQDN)

			require.NoError(pt, err)
			require.Len(pt, addrs, 1)
			assert.Equal(pt, addr, addrs[0])
		})
	}

	wg.Wait()
}
