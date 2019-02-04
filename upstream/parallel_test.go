package upstream

import (
	"context"
	"net"
	"testing"
	"time"
)

const (
	timeout = 5 * time.Second
)

// TestExchangeParallel launches several parallel exchanges
func TestExchangeParallel(t *testing.T) {
	upstreams := []Upstream{}
	upstreamList := []string{"1.2.3.4:55", "8.8.8.1", "8.8.8.8:53"}
	for _, s := range upstreamList {
		// Specifying some wrong port instead so that bootstrap DNS timed out for sure
		u, err := AddressToUpstream(s, []string{}, timeout)
		if err != nil {
			t.Fatalf("cannot create upstream: %s", err)
		}
		upstreams = append(upstreams, u)
	}

	req := createTestMessage()
	start := time.Now()
	resp, err := ExchangeParallel(upstreams, req)
	if err != nil || resp == nil {
		t.Fatalf("no response from test upstreams: %s", err)
	}

	elapsed := time.Since(start)
	if elapsed > 2*timeout {
		t.Fatalf("exchange took more time than the configured timeout: %v", elapsed)
	}
}

func TestLookupParallel(t *testing.T) {
	resolvers := []*net.Resolver{}
	bootstraps := []string{"1.2.3.4:55", "8.8.8.1", "8.8.8.8:53"}

	for _, b := range bootstraps {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, network, b)
			},
		}
		resolvers = append(resolvers, resolver)
	}

	ctx := context.TODO()
	answer, err := LookupParallel(ctx, resolvers, "google.com")
	if err != nil || answer == nil {
		t.Fatalf("failed to lookup %s", err)
	}
}
