package upstream_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
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

func TestExchangeParallel_empty(t *testing.T) {
	ups := []upstream.Upstream{
		&testUpstream{empty: true},
		&testUpstream{empty: true},
	}

	req := newTestMessage()
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	resp, up, err := upstream.ExchangeParallel(ctx, ups, req)
	require.Error(t, err)

	assert.Nil(t, resp)
	assert.Nil(t, up)
}

func TestExchangeParallel_servFail(t *testing.T) {
	valid := &testUpstream{
		addr:  netip.MustParseAddr("1.1.1.1"),
		sleep: 100 * time.Millisecond,
	}
	ups := []upstream.Upstream{
		&testUpstream{rcode: dns.RcodeServerFailure},
		valid,
	}

	req := newTestMessage()
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	resp, up, err := upstream.ExchangeParallel(ctx, ups, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.Same(t, valid, up)
}

func TestExchangeParallel_servFailAll(t *testing.T) {
	first := &testUpstream{rcode: dns.RcodeServerFailure}
	ups := []upstream.Upstream{
		first,
		&testUpstream{
			rcode: dns.RcodeServerFailure,
			sleep: 100 * time.Millisecond,
		},
	}

	req := newTestMessage()
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	resp, up, err := upstream.ExchangeParallel(ctx, ups, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, dns.RcodeServerFailure, resp.Rcode)
	assert.Same(t, first, up)
}

// testUpstream represents a mock upstream structure.
type testUpstream struct {
	// addr is a mock A record IP address to be returned.
	addr netip.Addr

	// err is a mock error to be returned.
	err bool

	// empty indicates if a nil response is returned.
	empty bool

	// rcode is the response code to be set in the response.
	rcode int

	// sleep is a delay before response.
	sleep time.Duration
}

// type check
var _ upstream.Upstream = (*testUpstream)(nil)

// Exchange implements the [Upstream] interface for *testUpstream.
func (u *testUpstream) Exchange(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	if u.sleep != 0 {
		time.Sleep(u.sleep)
	}

	if u.empty {
		return nil, nil
	}

	if u.err {
		return nil, fmt.Errorf("upstream error")
	}

	resp = &dns.Msg{}
	resp.SetRcode(req, u.rcode)

	if u.addr != (netip.Addr{}) {
		a := dns.A{
			A: u.addr.AsSlice(),
		}

		resp.Answer = append(resp.Answer, &a)
	}

	return resp, nil
}

// Address implements the [Upstream] interface for *testUpstream.
func (u *testUpstream) Address() (addr string) {
	return ""
}

// Close implements the [Upstream] interface for *testUpstream.
func (u *testUpstream) Close() (err error) {
	return nil
}

func TestExchangeAll(t *testing.T) {
	delayedAnsAddr := netip.MustParseAddr("1.1.1.1")
	ansAddr := netip.MustParseAddr("3.3.3.3")

	ups := []upstream.Upstream{&testUpstream{
		addr:  delayedAnsAddr,
		sleep: 100 * time.Millisecond,
	}, &testUpstream{
		err: true,
	}, &testUpstream{
		addr: ansAddr,
	}}

	req := dnsproxytest.NewTestRequestWithHost("test.org")
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
	return dnsproxytest.NewTestRequestWithHost("google-public-dns-a.google.com")
}
