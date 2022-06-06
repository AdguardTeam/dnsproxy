package upstream

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
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
	resolvers := []*Resolver{}
	bootstraps := []string{"1.2.3.4:55", "8.8.8.1:555", "8.8.8.8:53"}

	for _, boot := range bootstraps {
		resolver, _ := NewResolver(boot, &Options{Timeout: timeout})
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
	u1 := testUpstream{}
	u2 := testUpstream{}

	resolvers := []*Resolver{}
	resolvers = append(resolvers, &Resolver{upstream: &u1})
	resolvers = append(resolvers, &Resolver{upstream: &u2})

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	a, err := LookupParallel(ctx, resolvers, "google.com")
	assert.Nil(t, err)
	assert.Equal(t, 0, len(a))
}

func TestExchangeParallelEmpty(t *testing.T) {
	u1 := testUpstream{}
	u1.empty = true
	u2 := testUpstream{}
	u2.empty = true
	u := []Upstream{&u1, &u2}

	req := createTestMessage()
	a, up, err := ExchangeParallel(u, req)
	assert.NotNil(t, err)
	assert.Nil(t, a)
	assert.Nil(t, up)
}

type testUpstream struct {
	a     net.IP
	err   bool
	empty bool
	sleep time.Duration // a delay before response
}

func (u *testUpstream) Exchange(req *dns.Msg) (*dns.Msg, error) {
	if u.sleep != 0 {
		time.Sleep(u.sleep)
	}

	if u.empty {
		return nil, nil
	}

	resp := &dns.Msg{}
	resp.SetReply(req)

	if len(u.a) != 0 {
		a := dns.A{}
		a.A = u.a
		resp.Answer = append(resp.Answer, &a)
	}

	if u.err {
		return nil, fmt.Errorf("upstream error")
	}

	return resp, nil
}

func (u *testUpstream) Address() string {
	return ""
}

func TestExchangeAll(t *testing.T) {
	u1 := testUpstream{}
	u1.a = net.ParseIP("1.1.1.1")
	u1.sleep = 100 * time.Millisecond

	u2 := testUpstream{}
	u2.err = true

	u3 := testUpstream{}
	u3.a = net.ParseIP("3.3.3.3")

	ups := []Upstream{&u1, &u2, &u3}
	req := createHostTestMessage("test.org")
	res, err := ExchangeAll(ups, req)
	assert.True(t, err == nil)
	assert.True(t, len(res) == 2)

	a := res[0].Resp.Answer[0].(*dns.A)
	assert.True(t, a.A.To4().Equal(net.ParseIP("3.3.3.3").To4()))

	a = res[1].Resp.Answer[0].(*dns.A)
	assert.True(t, a.A.To4().Equal(net.ParseIP("1.1.1.1").To4()))
}
