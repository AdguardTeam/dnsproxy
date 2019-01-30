package upstream

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTLSPoolReconnect(t *testing.T) {
	u, err := AddressToUpstream("tls://one.one.one.one", "8.8.8.8:53", 10*time.Second)
	if err != nil {
		t.Fatalf("cannot create upstream: %s", err)
	}

	// Send the first test message
	req := createTestMessage()
	reply, err := u.Exchange(req)
	if err != nil {
		t.Fatalf("first DNS message failed: %s", err)
	}
	assertResponse(t, reply)

	// Now let's close the pooled connection and return it back to the pool
	p := u.(*dnsOverTLS)
	conn, _ := p.pool.Get()
	conn.Close()
	p.pool.Put(conn)

	// Send the second test message
	req = createTestMessage()
	reply, err = u.Exchange(req)
	if err != nil {
		t.Fatalf("second DNS message failed: %s", err)
	}
	assertResponse(t, reply)

	// Now assert that the number of connections in the pool is not changed
	if len(p.pool.conns) != 1 {
		t.Fatal("wrong number of pooled connections")
	}
}

func TestDNSTruncated(t *testing.T) {
	// AdGuard DNS
	address := "176.103.130.130:53"
	u, err := AddressToUpstream(address, "", 10*time.Second)

	if err != nil {
		t.Fatalf("error while creating an upstream: %s", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)
	req.RecursionDesired = true

	res, err := u.Exchange(req)
	if err != nil {
		t.Fatalf("error while making a request: %s", err)
	}

	if res.Truncated {
		t.Fatalf("response must NOT be truncated")
	}
}

// See the details here: https://github.com/AdguardTeam/AdGuardHome/issues/524
func TestDNSCryptTruncated(t *testing.T) {
	// AdGuard DNS (DNSCrypt)
	address := "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	u, err := AddressToUpstream(address, "", 10*time.Second)

	if err != nil {
		t.Fatalf("error while creating an upstream: %s", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)
	req.RecursionDesired = true

	res, err := u.Exchange(req)
	if err != nil {
		t.Fatalf("error while making a request: %s", err)
	}

	if res.Truncated {
		t.Fatalf("response must NOT be truncated")
	}
}

func TestUpstreams(t *testing.T) {
	upstreams := []struct {
		address   string
		bootstrap string
	}{
		{
			address:   "8.8.8.8:53",
			bootstrap: "8.8.8.8:53",
		},
		{
			address:   "1.1.1.1",
			bootstrap: "",
		},
		{
			address:   "1.1.1.1",
			bootstrap: "1.0.0.1",
		},
		{
			address:   "tcp://1.1.1.1:53",
			bootstrap: "",
		},
		{
			address:   "176.103.130.130:5353",
			bootstrap: "",
		},
		{
			address:   "tls://1.1.1.1",
			bootstrap: "",
		},
		{
			address:   "tls://9.9.9.9:853",
			bootstrap: "",
		},
		{
			address:   "tls://dns.adguard.com",
			bootstrap: "8.8.8.8:53",
		},
		{
			address:   "tls://dns.adguard.com:853",
			bootstrap: "8.8.8.8:53",
		},
		{
			address:   "tls://dns.adguard.com:853",
			bootstrap: "8.8.8.8",
		},
		{
			address:   "tls://one.one.one.one",
			bootstrap: "",
		},
		{
			address:   "https://dns9.quad9.net:443/dns-query",
			bootstrap: "8.8.8.8",
		},
		{
			address:   "https://cloudflare-dns.com/dns-query",
			bootstrap: "8.8.8.8:53",
		},
		{
			address:   "https://dns.google.com/experimental",
			bootstrap: "",
		},
		{
			// AdGuard DNS (DNSCrypt)
			address:   "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
			bootstrap: "",
		},
		{
			// AdGuard Family (DNSCrypt)
			address:   "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
			bootstrap: "8.8.8.8",
		},
		{
			// Cisco OpenDNS (DNSCrypt)
			address:   "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
			bootstrap: "8.8.8.8:53",
		},
		{
			// Cloudflare DNS (DoH)
			address:   "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk",
			bootstrap: "8.8.8.8:53",
		},
		{
			// Google (DNS-over-HTTPS)
			address:   "sdns://AgUAAAAAAAAAACAe9iTP_15r07rd8_3b_epWVGfjdymdx-5mdRZvMAzBuQ5kbnMuZ29vZ2xlLmNvbQ0vZXhwZXJpbWVudGFs",
			bootstrap: "8.8.8.8:53",
		},
		{
			// Google (Plain)
			address:   "sdns://AAcAAAAAAAAABzguOC44Ljg",
			bootstrap: "",
		},
		{
			// AdGuard DNS (DNS-over-TLS)
			address:   "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t",
			bootstrap: "8.8.8.8:53",
		},
	}
	for _, test := range upstreams {

		t.Run(test.address, func(t *testing.T) {
			u, err := AddressToUpstream(test.address, test.bootstrap, 10*time.Second)
			if err != nil {
				t.Fatalf("Failed to generate upstream from address %s: %s", test.address, err)
			}

			checkUpstream(t, u, test.address)
		})
	}
}

func checkUpstream(t *testing.T, u Upstream, addr string) {
	t.Helper()

	req := createTestMessage()
	reply, err := u.Exchange(req)
	if err != nil {
		t.Fatalf("Couldn't talk to upstream %s: %s", addr, err)
	}
	assertResponse(t, reply)
}

func createTestMessage() *dns.Msg {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "google-public-dns-a.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	return &req
}

func assertResponse(t *testing.T, reply *dns.Msg) {
	if len(reply.Answer) != 1 {
		t.Fatalf("DNS upstream returned reply with wrong number of answers - %d", len(reply.Answer))
	}
	if a, ok := reply.Answer[0].(*dns.A); ok {
		if !net.IPv4(8, 8, 8, 8).Equal(a.A) {
			t.Fatalf("DNS upstream returned wrong answer instead of 8.8.8.8: %v", a.A)
		}
	} else {
		t.Fatalf("DNS upstream returned wrong answer type instead of A: %v", reply.Answer[0])
	}
}
