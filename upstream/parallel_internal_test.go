package upstream

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExchangeParallel launches several parallel exchanges
func TestExchangeParallel(t *testing.T) {
	upstreams := []Upstream{}
	upstreamList := []string{"1.2.3.4:55", "8.8.8.1", "8.8.8.8:53"}

	for _, s := range upstreamList {
		u, err := AddressToUpstream(s, &Options{
			Logger:  testLogger,
			Timeout: testTimeout,
		})
		if err != nil {
			t.Fatalf("cannot create upstream: %s", err)
		}
		upstreams = append(upstreams, u)
	}

	req := createTestMessage()
	start := time.Now()
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	resp, u, err := ExchangeParallel(ctx, upstreams, req)
	if err != nil {
		t.Fatalf("no response from test upstreams: %s", err)
	}

	if u.Address() != "8.8.8.8:53" {
		t.Fatalf("shouldn't happen. This upstream can't resolve DNS request: %s", u.Address())
	}

	requireResponse(t, req, resp)
	elapsed := time.Since(start)
	if elapsed > testTimeout {
		t.Fatalf("exchange took more time than the configured timeout: %v", elapsed)
	}
}

func TestExchangeParallel_empty(t *testing.T) {
	ups := []Upstream{
		&testUpstream{empty: true},
		&testUpstream{empty: true},
	}

	req := createTestMessage()
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	resp, up, err := ExchangeParallel(ctx, ups, req)
	require.Error(t, err)

	assert.Nil(t, resp)
	assert.Nil(t, up)
}

func TestExchangeParallel_servFail(t *testing.T) {
	valid := &testUpstream{
		addr:  netip.MustParseAddr("1.1.1.1"),
		sleep: 100 * time.Millisecond,
	}
	ups := []Upstream{
		&testUpstream{rcode: dns.RcodeServerFailure},
		valid,
	}

	req := createTestMessage()
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	resp, up, err := ExchangeParallel(ctx, ups, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.Same(t, valid, up)
}

func TestExchangeParallel_servFailAll(t *testing.T) {
	first := &testUpstream{rcode: dns.RcodeServerFailure}
	ups := []Upstream{
		first,
		&testUpstream{
			rcode: dns.RcodeServerFailure,
			sleep: 100 * time.Millisecond,
		},
	}

	req := createTestMessage()
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	resp, up, err := ExchangeParallel(ctx, ups, req)
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
var _ Upstream = (*testUpstream)(nil)

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

	ups := []Upstream{&testUpstream{
		addr:  delayedAnsAddr,
		sleep: 100 * time.Millisecond,
	}, &testUpstream{
		err: true,
	}, &testUpstream{
		addr: ansAddr,
	}}

	req := createHostTestMessage("test.org")
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	res, err := ExchangeAll(ctx, ups, req)
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
