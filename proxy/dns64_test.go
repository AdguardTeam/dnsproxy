package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

const dns64Upstream = "2001:67c:27e4:15::64"
const ipv4OnlyHost = "and.ru"

// TestNAT64Prefix calculates nat64 prefix
func TestNAT64Prefix(t *testing.T) {
	arpa := createIpv4ArpaMessage()
	u, err := upstream.AddressToUpstream(dns64Upstream, upstream.Options{Timeout: defaultTimeout})
	if err != nil {
		t.Fatalf("Failed to create upstream to %s", dns64Upstream)
	}

	resp, err := u.Exchange(arpa)
	if err != nil {
		t.Fatalf("Can not exchange ipv4Arpa message: %s", err)
	}

	prefix, err := getNAT64PrefixFromResponse(resp)
	if err != nil {
		t.Fatalf("Can not get NAT64 prefix from response")
	}

	if l := len(prefix); l != 12 {
		t.Fatalf("Wrong prefix length: %d", l)
	}
}

func TestProxyWithDNS64(t *testing.T) {
	d := createTestProxy(t, nil)
	d.DNS64Upstreams = []upstream.Upstream{}
	dns64 := []string{dns64Upstream, "8.8.8.8"}
	for _, up := range dns64 {
		u, err := upstream.AddressToUpstream(up, upstream.Options{Timeout: time.Second})
		if err != nil {
			t.Fatalf("Failed to create upstream to %s", up)
		}

		d.DNS64Upstreams = append(d.DNS64Upstreams, u)
	}

	err := d.Start()
	if err != nil {
		t.Fatalf("Failed to start dns proxy")
	}

	// Wait for DNS64 upstream timeout. NAT64 prefix should be already calculated
	time.Sleep(time.Second)
	if !d.isNAT64PrefixAvailable() {
		t.Fatalf("Failed to calculate NAT64 prefix")
	}

	// Let's create test A request to ipv4OnlyHost and exchange it with test proxy
	req := createHostTestMessage(ipv4OnlyHost)
	resp, _, err := d.exchange(req, d.DNS64Upstreams)
	if err != nil {
		t.Fatalf("Can not exchange test message for %s cause: %s", ipv4OnlyHost, err)
	}

	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Answer for %s is not A record!", ipv4OnlyHost)
	}

	// Let's manually add NAT64 prefix to IPv4 response
	mappedIP := make(net.IP, net.IPv6len)
	copy(mappedIP, d.nat64Prefix)
	for index, b := range a.A {
		mappedIP[12+index] = b
	}

	// Create test context with AAAA request to ipv4OnlyHost and resolve it
	testDNSContext := createTestDNSContext(ipv4OnlyHost)
	err = d.Resolve(testDNSContext)
	if err != nil {
		t.Fatalf("Error whilr DNSContext resolve: %s", err)
	}

	// Response should be AAAA answer
	res := testDNSContext.Res
	if res == nil {
		t.Fatalf("No response")
	}

	ans, ok := res.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("Mapped answer for %s is not AAAA record", ipv4OnlyHost)
	}

	// Compare manually mapped IP with IP that was resolved by dnsproxy with calculated NAT64 prefix
	if !ans.AAAA.Equal(mappedIP) {
		t.Fatalf("Manually mapped IP %s not equlas to repsonse %s", mappedIP.String(), ans.AAAA.String())
	}

	err = d.Stop()
	if err != nil {
		t.Fatalf("Failed to stop dns proxy")
	}
}

func createAAAATestMessage(host string) *dns.Msg {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	name := host + "."
	req.Question = []dns.Question{
		{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
	}
	return &req
}

func createTestDNSContext(host string) *DNSContext {
	d := DNSContext{}
	d.Req = createAAAATestMessage(host)
	return &d
}
