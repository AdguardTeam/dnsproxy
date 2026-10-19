package upstream_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/dnsproxytest"
	dpt "github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExchangeParallel(t *testing.T) {
	t.Parallel()

	const publicDNSAddr = "8.8.8.8:53"

	var upstreams []upstream.Upstream
	upstreamList := []string{
		"1.2.3.4:55",
		"8.8.8.1",
		publicDNSAddr,
	}

	for _, s := range upstreamList {
		u, err := upstream.AddressToUpstream(s, &upstream.Options{
			Logger:  testLogger,
			Timeout: testTimeout,
		})
		require.NoError(t, err)

		upstreams = append(upstreams, u)
	}

	req := newTestMessage()
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	resp, u, err := upstream.ExchangeParallel(ctx, upstreams, req)
	require.NoError(t, err)
	require.Equal(t, u.Address(), publicDNSAddr)

	require.NotNil(t, resp)
	require.Len(t, resp.Answer, 1)

	assert.Equal(t, req.Id, resp.Id)

	a := testutil.RequireTypeAssert[*dns.A](t, resp.Answer[0])
	assert.Equal(t, net.IPv4(8, 8, 8, 8), a.A.To16())
}

func TestExchangeParallel_noReply(t *testing.T) {
	t.Parallel()

	noReply := dnsproxytest.NewUpstream()
	noReply.OnExchange = func(_ context.Context, _ *dns.Msg) (resp *dns.Msg, err error) {
		return nil, nil
	}

	testCases := []struct {
		name string
		want string
		ups  []upstream.Upstream
	}{{
		name: "no_upstreams",
		want: "no upstream specified",
		ups:  []upstream.Upstream{},
	}, {
		name: "single_upstream",
		want: upstream.ErrNoReply.Error(),
		ups: []upstream.Upstream{
			noReply,
		},
	}, {
		name: "multiple_upstreams",
		want: "none of upstream servers responded",
		ups: []upstream.Upstream{
			noReply,
			noReply,
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := newTestMessage()
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			resp, up, err := upstream.ExchangeParallel(ctx, tc.ups, req)
			testutil.AssertErrorMsg(t, tc.want, err)
			assert.Nil(t, resp)
			assert.Nil(t, up)
		})
	}
}

func TestExchangeParallel_servfail(t *testing.T) {
	t.Parallel()

	servfail := dnsproxytest.NewUpstream()
	servfail.OnExchange = func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		resp = &dns.Msg{}
		resp.SetRcode(req, dns.RcodeServerFailure)

		return resp, nil
	}

	servfailDelay := dnsproxytest.NewUpstream()
	servfailDelay.OnExchange = func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		time.Sleep(100 * time.Millisecond)

		resp = &dns.Msg{}
		resp.SetRcode(req, dns.RcodeServerFailure)

		return resp, nil
	}

	valid := dnsproxytest.NewUpstream()
	valid.OnExchange = func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		time.Sleep(100 * time.Millisecond)

		resp = &dns.Msg{}
		resp.SetRcode(req, dns.RcodeSuccess)
		resp.Answer = append(resp.Answer, &dns.A{
			A: netip.MustParseAddr("1.1.1.1").AsSlice(),
		})

		return resp, nil
	}

	testCases := []struct {
		want      upstream.Upstream
		name      string
		ups       []upstream.Upstream
		wantRcode int
	}{{
		want: valid,
		name: "valid",
		ups: []upstream.Upstream{
			servfail,
			valid,
		},
		wantRcode: dns.RcodeSuccess,
	}, {
		want: servfail,
		name: "servfail",
		ups: []upstream.Upstream{
			servfail,
			servfailDelay,
		},
		wantRcode: dns.RcodeServerFailure,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := newTestMessage()
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			resp, up, err := upstream.ExchangeParallel(ctx, tc.ups, req)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, tc.wantRcode, resp.Rcode)
			assert.Same(t, tc.want, up)
		})
	}
}

func TestExchangeAll(t *testing.T) {
	delayedAnsAddr := netip.MustParseAddr("1.1.1.1")
	ansAddr := netip.MustParseAddr("3.3.3.3")

	valid := dnsproxytest.NewUpstream()
	valid.OnExchange = func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		resp = &dns.Msg{}
		resp.SetRcode(req, dns.RcodeSuccess)
		resp.Answer = append(resp.Answer, &dns.A{
			A: ansAddr.AsSlice(),
		})

		return resp, nil
	}

	delayed := dnsproxytest.NewUpstream()
	delayed.OnExchange = func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		time.Sleep(100 * time.Millisecond)

		resp = &dns.Msg{}
		resp.SetRcode(req, dns.RcodeSuccess)
		resp.Answer = append(resp.Answer, &dns.A{
			A: delayedAnsAddr.AsSlice(),
		})

		return resp, nil
	}

	errExchange := dnsproxytest.NewUpstream()
	errExchange.OnExchange = func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		return nil, assert.AnError
	}

	ups := []upstream.Upstream{
		delayed,
		errExchange,
		valid,
	}

	req := dpt.NewTestRequestWithHost("test.org")
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	res, err := upstream.ExchangeAll(ctx, ups, req)
	require.NoError(t, err)
	require.Len(t, res, 2)

	resp := res[0].Resp
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Answer)

	ip := testutil.RequireTypeAssert[*dns.A](t, resp.Answer[0]).A
	assert.Equal(t, ansAddr.AsSlice(), []byte(ip))

	resp = res[1].Resp
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Answer)

	ip = testutil.RequireTypeAssert[*dns.A](t, resp.Answer[0]).A
	assert.Equal(t, delayedAnsAddr.AsSlice(), []byte(ip))
}

// newTestMessage creates a [*dns.Msg] that we use for tests.
func newTestMessage() (m *dns.Msg) {
	return dpt.NewTestRequestWithHost("google-public-dns-a.google.com")
}
