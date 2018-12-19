package proxy

import (
	"fmt"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"net"
	"testing"
)

const (
	listenPort   = 43812
	listenIp     = "127.0.0.1"
	upstreamAddr = "8.8.8.8:53"
)

func TestTcpProxy(t *testing.T) {

	// Prepare the proxy server
	dnsProxy := createTestProxy(t)

	// Start listening
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// Create a DNS-over-TCP client connection
	addr := fmt.Sprintf("%s:%d", listenIp, listenPort)
	conn, err := dns.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("cannot connect to the proxy: %s", err)
	}

	for i := 0; i < 10; i++ {
		req := createTestMessage()
		err := conn.WriteMsg(req)
		if err != nil {
			t.Fatalf("cannot write message #%d: %s", i, err)
		}

		res, err := conn.ReadMsg()
		if err != nil {
			t.Fatalf("cannot read response to message #%d: %s", i, err)
		}
		assertResponse(t, res)
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func createTestProxy(t *testing.T) *Proxy {
	listenUdpAddr := &net.UDPAddr{Port: listenPort, IP: net.ParseIP(listenIp)}
	listenTcpAddr := &net.TCPAddr{Port: listenPort, IP: net.ParseIP(listenIp)}
	upstreams := make([]upstream.Upstream, 0)

	dnsUpstream, err := upstream.AddressToUpstream(upstreamAddr, "")
	if err != nil {
		t.Fatalf("cannot prepare the upstream: %s", err)
	}
	upstreams = append(upstreams, dnsUpstream)

	// Prepare the proxy server
	return &Proxy{UDPListenAddr: listenUdpAddr, TCPListenAddr: listenTcpAddr, Upstreams: upstreams}
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
