package upstream

import (
	"context"
	"testing"
	"time"
)

const (
	timeout = 10 * time.Second
)

// TestExchangeParallel launches several parallel exchanges
func TestExchangeParallel(t *testing.T) {
	upstreams := []Upstream{}
	upstreamList := []string{"1.2.3.4:55", "8.8.8.1", "8.8.8.8:53"}

	for _, s := range upstreamList {
		u, err := AddressToUpstream(s, Options{Timeout: timeout})
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

	assertResponse(t, resp)
	elapsed := time.Since(start)
	if elapsed > timeout {
		t.Fatalf("exchange took more time than the configured timeout: %v", elapsed)
	}
}

func TestLookupParallel(t *testing.T) {
	resolvers := []*Resolver{}
	bootstraps := []string{"1.2.3.4:55", "8.8.8.1:555", "8.8.8.8:53"}

	for _, boot := range bootstraps {
		resolver := NewResolver(boot, timeout)
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
