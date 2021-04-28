package proxy

import (
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

const ipv4OnlyHost = "ipv4only.arpa"

// Valid NAT-64 prefix for 2001:67c:27e4:15::64 server
var testNAT64Prefix = []byte{32, 1, 6, 124, 39, 228, 16, 100, 0, 0, 0, 0} //nolint

func TestProxyWithDNS64(t *testing.T) {
	// Create test proxy and manually set NAT64 prefix
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.SetNAT64Prefix(testNAT64Prefix)

	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("Failed to start dns proxy")
	}

	// Let's create test A request to ipv4OnlyHost and exchange it with test proxy
	req := createHostTestMessage(ipv4OnlyHost)
	resp, _, err := dnsProxy.exchange(req, dnsProxy.UpstreamConfig.Upstreams)
	if err != nil {
		t.Fatalf("Can not exchange test message for %s cause: %s", ipv4OnlyHost, err)
	}

	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Answer for %s is not an A record!", ipv4OnlyHost)
	}

	// Let's manually add NAT64 prefix to IPv4 response
	mappedIP := make(net.IP, net.IPv6len)
	copy(mappedIP, testNAT64Prefix)
	for index, b := range a.A {
		mappedIP[NAT64PrefixLength+index] = b
	}

	// Create test context with AAAA request to ipv4OnlyHost and resolve it
	testDNSContext := createTestDNSContext(ipv4OnlyHost)
	err = dnsProxy.Resolve(testDNSContext)
	if err != nil {
		t.Fatalf("Error while DNSContext resolve: %s", err)
	}

	// Response should be AAAA answer
	res := testDNSContext.Res
	if res == nil {
		t.Fatalf("No response")
	}

	ans, ok := res.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("Answer for %s is not AAAA record", ipv4OnlyHost)
	}

	// Compare manually mapped IP with IP that was resolved by dnsproxy with calculated NAT64 prefix
	if !ans.AAAA.Equal(mappedIP) {
		t.Fatalf("Manually mapped IP %s not equlas to response %s", mappedIP.String(), ans.AAAA.String())
	}

	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("Failed to stop dns proxy")
	}
}

func TestDNS64Race(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.SetNAT64Prefix(testNAT64Prefix)
	dnsProxy.UpstreamConfig.Upstreams = append(dnsProxy.UpstreamConfig.Upstreams, dnsProxy.UpstreamConfig.Upstreams[0])

	// Start listening
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("cannot connect to the proxy: %s", err)
	}

	sendTestAAAAMessagesAsync(t, conn)

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func sendTestAAAAMessagesAsync(t *testing.T, conn *dns.Conn) {
	g := &sync.WaitGroup{}
	g.Add(testMessagesCount)

	for i := 0; i < testMessagesCount; i++ {
		go sendTestAAAAMessageAsync(t, conn, g, ipv4OnlyHost)
	}

	g.Wait()
}

func sendTestAAAAMessageAsync(t *testing.T, conn *dns.Conn, g *sync.WaitGroup, host string) {
	defer func() {
		g.Done()
	}()

	req := createAAAATestMessage(host)
	err := conn.WriteMsg(req)
	if err != nil {
		t.Fatalf("cannot write message: %s", err)
	}

	res, err := conn.ReadMsg()
	if err != nil {
		t.Fatalf("cannot read response to message: %s", err)
	}

	if len(res.Answer) == 0 {
		t.Fatalf("No answers!")
	}

	_, ok := res.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("Answer for %s is not AAAA record!", host)
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
