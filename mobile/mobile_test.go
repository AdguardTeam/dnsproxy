package mobile

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestMobileApi(t *testing.T) {
	config := createTestConfig()
	proxy := DNSProxy{Config: config}
	err := proxy.Start()
	if err != nil {
		t.Fatalf("cannot start the mobile proxy: %s", err)
	}

	//
	// Test that it resolves something
	//

	// Create a test DNS message
	req := createTestMessage("google-public-dns-a.google.com.", dns.TypeA)
	addr := proxy.Addr()
	reply, err := dns.Exchange(req, addr)
	if err != nil {
		t.Fatalf("Couldn't talk to upstream %s: %s", addr, err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("DNS upstream %s returned reply with wrong number of answers - %d", addr, len(reply.Answer))
	}
	if a, ok := reply.Answer[0].(*dns.A); ok {
		if !net.IPv4(8, 8, 8, 8).Equal(a.A) {
			t.Fatalf("DNS upstream %s returned wrong answer instead of 8.8.8.8: %v", addr, a.A)
		}
	} else {
		t.Fatalf("DNS upstream %s returned wrong answer type instead of A: %v", addr, reply.Answer[0])
	}

	err = proxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the mobile proxy: %s", err)
	}
}

func TestMobileApiDNS64(t *testing.T) {
	config := createTestConfig()
	config.DNS64Upstream = "2001:67c:27e4:15::64"
	proxy := DNSProxy{Config: config}
	err := proxy.Start()
	if err != nil {
		t.Fatalf("cannot start the mobile proxy: %s", err)
	}

	// Wait for NAT64 prefix calculation
	time.Sleep(6 * time.Second)

	//
	// Test that it resolves IPv4 only host with AAAA request type
	//

	// Create a test DNS message
	req := createTestMessage("and.ru.", dns.TypeAAAA)
	addr := proxy.Addr()
	reply, err := dns.Exchange(req, addr)
	if err != nil {
		t.Fatalf("Couldn't talk to upstream %s: %s", addr, err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("DNS upstream %s returned reply with wrong number of answers - %d", addr, len(reply.Answer))
	}

	if len(reply.Answer) == 0 {
		t.Fatalf("No answers")
	}

	if _, ok := reply.Answer[0].(*dns.AAAA); !ok {
		t.Fatalf("DNS upstream %s returned wrong answer type instead of AAAA: %v", addr, reply.Answer[0])
	}

	err = proxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the mobile proxy: %s", err)
	}
}

func TestDNS64AddressValidation(t *testing.T) {
	dns64 := "1.1.1.1\n1.1.1.1:53\nhttps://dns.adguard.com\n[2001:67c:27e4:15::64]:53\n2001:67c:27e4:15::64"
	addresses := validateIPv6Addresses(dns64)
	if len(addresses) != 2 {
		t.Fatalf("Wrong count of addresses: %d", len(addresses))
	}
	if addresses[0] != addresses[1] {
		t.Fatalf("Wrong addresses. Expected: [2001:67c:27e4:15::64]:53, actual: %s, %s", addresses[0], addresses[1])
	}

}

func TestExchangeWithClient(t *testing.T) {
	res := getNAT64PrefixWithClient("1.1.1.1:53")
	if res.err == nil {
		t.Fatalf("1.1.1.1:53 is not DNS64 server")
	}

	res = getNAT64PrefixWithClient("[2001:67c:27e4:15::64]:53")
	if res.err != nil {
		t.Fatalf("Error while ipv4only.arpa exchange: %s", res.err)
	}

	if len(res.prefix) != 12 {
		t.Fatalf("Wrong prefix format: %v", res.prefix)
	}
}

func TestParallelExchange(t *testing.T) {
	dns64 := []string{"1.1.1.1:53", "[2001:67c:27e4:15::64]:53", "8.8.8.8"}
	res := getNAT64PrefixParallel(dns64)
	if res.err != nil {
		t.Fatalf("Error while NAT64 prefix calculation: %s", res.err)
	}

	if len(res.prefix) != 12 {
		t.Fatalf("Invalid prefix: %v", res.prefix)
	}
}

func createTestMessage(name string, dnsType uint16) *dns.Msg {
	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: name, Qtype: dnsType, Qclass: dns.ClassINET},
	}
	return req
}

func createTestConfig() *Config {
	upstreams := []string{
		"tls://dns.adguard.com",
		"https://dns.adguard.com/dns-query",
		// AdGuard DNS (DNSCrypt)
		"sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}
	upstreamsStr := strings.Join(upstreams, "\n")
	return &Config{
		ListenAddr:   "127.0.0.1",
		ListenPort:   0, // Specify 0 to start listening on a random free port
		BootstrapDNS: "8.8.8.8:53\n1.1.1.1:53",
		Fallbacks:    "8.8.8.8:53\n1.1.1.1:53",
		Timeout:      5000,
		Upstreams:    upstreamsStr,
	}
}
