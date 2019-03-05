package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRatelimitingProxy(t *testing.T) {
	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.Ratelimit = 1 // just one request per second is allowed

	// Start listening
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	// Send the first message (not blocked)
	req := createGoogleATestMessage()

	r, _, err := client.Exchange(req, addr.String())
	if err != nil {
		t.Fatalf("error in the first request: %s", err)
	}
	assertGoogleAResponse(t, r)

	// Send the second message (blocked)
	req = createGoogleATestMessage()

	_, _, err = client.Exchange(req, addr.String())
	if err == nil {
		t.Fatalf("second request was not blocked")
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func TestRatelimiting(t *testing.T) {
	// rate limit is 1 per sec
	p := Proxy{}
	p.Ratelimit = 1

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1232}

	limited := p.isRatelimited(addr)

	if limited {
		t.Fatal("First request must have been allowed")
	}

	limited = p.isRatelimited(addr)

	if !limited {
		t.Fatal("Second request must have been ratelimited")
	}
}

func TestWhitelist(t *testing.T) {
	// rate limit is 1 per sec with whitelist
	p := Proxy{}
	p.Ratelimit = 1
	p.RatelimitWhitelist = []string{"127.0.0.1", "127.0.0.2", "127.0.0.125"}

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1232}

	limited := p.isRatelimited(addr)

	if limited {
		t.Fatal("First request must have been allowed")
	}

	limited = p.isRatelimited(addr)

	if limited {
		t.Fatal("Second request must have been allowed due to whitelist")
	}
}
