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
		u, err := AddressToUpstream(s, []string{}, timeout)
		if err != nil {
			t.Fatalf("cannot create upstream: %s", err)
		}
		upstreams = append(upstreams, u)
	}

	req := createTestMessage()
	start := time.Now()
	_, err := ExchangeParallel(upstreams, req)
	if err != nil {
		t.Fatalf("no response from test upstreams: %s", err)
	}

	elapsed := time.Since(start)
	if elapsed > timeout {
		t.Fatalf("exchange took more time than the configured timeout: %v", elapsed)
	}
}

func TestLookupParallel(t *testing.T) {
	resolvers := []resolverWithAddress{}
	bootstraps := []string{"1.2.3.4:55", "8.8.8.1", "8.8.8.8:53"}

	for _, b := range bootstraps {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, network, b)
			},
		}

		resolvers = append(resolvers, resolverWithAddress{
			resolver: resolver,
			address:  b,
		})
	}

	ctx := context.TODO()

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
