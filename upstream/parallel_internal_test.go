package upstream

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	timeout = 5 * time.Second
)

// TestExchangeParallel launches several parallel exchanges
func TestExchangeParallel(t *testing.T) {
	upstreams := []Upstream{}
	upstreamList := []string{"1.2.3.4:55", "8.8.8.1", "8.8.8.8:53"}

	for _, s := range upstreamList {
		u, err := AddressToUpstream(s, &Options{Timeout: timeout})
		if err != nil {
			t.Fatalf("cannot create upstream: %s", err)
		}
		upstreams = append(upstreams, u)
	}

	req := createTestMessage()
	start := time.Now()
	resp, u, err := ExchangeParallel(upstreams, req)
	if err != nil {
		t.Fatalf("no response from test upstreams: %s", err)
	}

	if u.Address() != "8.8.8.8:53" {
		t.Fatalf("shouldn't happen. This upstream can't resolve DNS request: %s", u.Address())
	}

	requireResponse(t, req, resp)
	elapsed := time.Since(start)
	if elapsed > timeout {
		t.Fatalf("exchange took more time than the configured timeout: %v", elapsed)
	}
}

func TestLookupParallel(t *testing.T) {
	resolvers := []Resolver{}
	bootstraps := []string{"1.2.3.4:55", "8.8.8.1:555", "8.8.8.8:53"}

	for _, boot := range bootstraps {
		resolver, _ := NewUpstreamResolver(boot, &Options{Timeout: timeout})
		resolvers = append(resolvers, resolver)
	}

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	start := time.Now()
	answer, err := LookupParallel(ctx, resolvers, "google.com")
	if err != nil || answer == nil {
		t.Fatalf("failed to lookup %s", err)
	}

	elapsed := time.Since(start)
	if elapsed > timeout {
		t.Fatalf("lookup took more time than the configured timeout: %v", elapsed)
	}
}

func TestLookupParallelEmpty(t *testing.T) {
	resolvers := []Resolver{
		&UpstreamResolver{Upstream: &testUpstream{}},
		&UpstreamResolver{Upstream: &testUpstream{}},
	}

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	addrs, err := LookupParallel(ctx, resolvers, "google.com")
	require.NoError(t, err)
	assert.Len(t, addrs, 0)
}

func TestExchangeParallelEmpty(t *testing.T) {
	ups := []Upstream{
		&testUpstream{empty: true},
		&testUpstream{empty: true},
	}

	req := createTestMessage()
	resp, up, err := ExchangeParallel(ups, req)
	require.Error(t, err)

	assert.Nil(t, resp)
	assert.Nil(t, up)
}

// testUpstream represents a mock upstream structure.
type testUpstream struct {
	// addr is a mock A record IP address to be returned.
	addr netip.Addr

	// err is a mock error to be returned.
	err bool

	// empty indicates if a nil response is returned.
	empty bool

	// sleep is a delay before response.
	sleep time.Duration
}

// type check
var _ Upstream = (*testUpstream)(nil)

// Exchange implements the [Upstream] interface for *testUpstream.
func (u *testUpstream) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
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
	resp.SetReply(req)

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
	res, err := ExchangeAll(ups, req)
	require.NoError(t, err)
	require.Len(t, res, 2)

	resp := res[0].Resp
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Answer)
	require.IsType(t, new(dns.A), resp.Answer[0])

	ip := resp.Answer[0].(*dns.A).A
	assert.Equal(t, ansAddr.AsSlice(), []byte(ip))

	resp = res[1].Resp
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Answer)
	require.IsType(t, new(dns.A), resp.Answer[0])

	ip = resp.Answer[0].(*dns.A).A
	assert.Equal(t, delayedAnsAddr.AsSlice(), []byte(ip))
}
