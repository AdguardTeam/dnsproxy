package proxy

import (
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
)

func TestRatelimitingProxy(t *testing.T) {
	dnsProxy := mustNew(t, &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		Ratelimit:              1,
	})

	servicetest.RequireRun(t, dnsProxy, testTimeout)

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{
		Net:     string(ProtoUDP),
		Timeout: testTimeout,
	}

	// Send the first message (not blocked)
	req := newTestMessage()

	r, _, err := client.Exchange(req, addr.String())
	if err != nil {
		t.Fatalf("error in the first request: %s", err)
	}
	requireResponse(t, req, r)

	// Send the second message (blocked)
	req = newTestMessage()

	_, _, err = client.Exchange(req, addr.String())
	if err == nil {
		t.Fatalf("second request was not blocked")
	}
}

func TestRatelimiting(t *testing.T) {
	// rate limit is 1 per sec
	p := Proxy{}
	p.Ratelimit = 1

	addr := netip.MustParseAddr("127.0.0.1")

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
	p.RatelimitWhitelist = []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("127.0.0.2"),
		netip.MustParseAddr("127.0.0.125"),
	}

	addr := netip.MustParseAddr("127.0.0.1")

	limited := p.isRatelimited(addr)

	if limited {
		t.Fatal("First request must have been allowed")
	}

	limited = p.isRatelimited(addr)

	if limited {
		t.Fatal("Second request must have been allowed due to whitelist")
	}
}
