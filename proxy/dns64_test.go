package proxy

import (
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const ipv4OnlyHost = "ipv4only.arpa"

// Valid NAT-64 prefix for 2001:67c:27e4:15::64 server.
var testNAT64Prefix = []byte{32, 1, 6, 124, 39, 228, 16, 100, 0, 0, 0, 0}

func TestProxyWithDNS64(t *testing.T) {
	// Create test proxy and manually set NAT64 prefix.
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.SetNAT64Prefix(testNAT64Prefix)

	err := dnsProxy.Start()
	require.NoError(t, err)

	// Let's create test A request to ipv4OnlyHost and exchange it with the
	// test proxy.
	req := createHostTestMessage(ipv4OnlyHost)
	resp, _, err := dnsProxy.exchange(req, dnsProxy.UpstreamConfig.Upstreams)
	require.NoError(t, err)
	require.Len(t, resp.Answer, 2)

	var mappedIPs []net.IP
	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		require.True(t, ok)

		// Let's manually add NAT64 prefix to IPv4 response.
		mappedIP := make(net.IP, net.IPv6len)
		copy(mappedIP, testNAT64Prefix)
		for index, b := range a.A {
			mappedIP[NAT64PrefixLength+index] = b
		}

		mappedIPs = append(mappedIPs, mappedIP)
	}

	// Create test context with AAAA request to ipv4OnlyHost and resolve it.
	testDNSContext := createTestDNSContext(ipv4OnlyHost)
	err = dnsProxy.Resolve(testDNSContext)
	require.NoError(t, err)

	// Response should be AAAA answer.
	res := testDNSContext.Res
	require.NotNil(t, res)

	for _, rr := range res.Answer {
		aaaa, ok := rr.(*dns.AAAA)
		require.True(t, ok)

		// Compare manually mapped IP with IP that was resolved by dnsproxy
		// with calculated NAT64 prefix.
		found := false
		for _, mappedIP := range mappedIPs {
			if aaaa.AAAA.Equal(mappedIP) {
				found = true
				break
			}
		}

		require.True(t, found)
	}

	err = dnsProxy.Stop()
	require.NoError(t, err)
}

func TestDNS64Race(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.SetNAT64Prefix(testNAT64Prefix)
	dnsProxy.UpstreamConfig.Upstreams = append(dnsProxy.UpstreamConfig.Upstreams, dnsProxy.UpstreamConfig.Upstreams[0])

	// Start listening.
	err := dnsProxy.Start()
	require.NoError(t, err)

	// Create a DNS-over-UDP client connection.
	addr := dnsProxy.Addr(ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)

	sendTestAAAAMessagesAsync(t, conn)

	// Stop the proxy.
	err = dnsProxy.Stop()
	require.NoError(t, err)
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
	require.NoError(t, err)

	res, err := conn.ReadMsg()
	require.NoError(t, err)
	require.True(t, len(res.Answer) > 0)

	_, ok := res.Answer[0].(*dns.AAAA)
	require.True(t, ok)
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
