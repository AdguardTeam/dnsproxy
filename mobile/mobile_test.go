package mobile

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestMobileApi(t *testing.T) {
	upstreams := []string{
		"tls://dns.adguard.com",
		"https://dns.adguard.com/dns-query",
		// AdGuard DNS (DNSCrypt)
		"sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}
	upstreamsStr := strings.Join(upstreams, "\n")

	config := &Config{
		Verbose:      true,
		LogOutput:    "test_log.txt",
		ListenAddr:   "127.0.0.1",
		ListenPort:   0, // Specify 0 to start listening on a random free port
		BootstrapDNS: "8.8.8.8:53",
		Fallback:     "8.8.8.8:53",
		Timeout:      5000,
		Upstreams:    upstreamsStr,
	}

	proxy := DNSProxy{Config: config}
	err := proxy.Start()
	if err != nil {
		t.Fatalf("cannot start the mobile proxy: %s", err)
	}

	//
	// Test that it resolves something
	//

	// Create a test DNS message
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "google-public-dns-a.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	addr := proxy.Addr()
	reply, err := dns.Exchange(&req, addr)
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
		t.Fatalf("cannot start the mobile proxy: %s", err)
	}

	//
	// Test that the log file exists by deleting it
	//
	err = os.Remove(config.LogOutput)
	if err != nil {
		t.Fatalf("problem with the log file: %s", err)
	}
}
