package proxy

import (
	"fmt"
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestFilteringHandler(t *testing.T) {
	// Initializing the test middleware
	h := &testFilteringHandler{}

	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.Handler = h

	// Start listening
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// Create a DNS-over-UDP client connection
	addr := fmt.Sprintf("%s:%d", listenIp, listenPort)
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	// Send the first message (not blocked)
	req := createTestMessage()

	r, _, err := client.Exchange(req, addr)
	if err != nil {
		t.Fatalf("error in the first request: %s", err)
	}
	assertResponse(t, r)

	// Now send the second and make sure it is blocked
	h.blockResponse = true

	r, _, err = client.Exchange(req, addr)
	if err != nil {
		t.Fatalf("error in the second request: %s", err)
	}
	if r.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("second request was not blocked")
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

type testFilteringHandler struct {
	blockResponse bool
}

func (h *testFilteringHandler) ServeDNS(d *DnsContext, next Handler) error {
	if h.blockResponse {
		resp := dns.Msg{}
		resp.SetRcode(d.Req, dns.RcodeNotImplemented)
		resp.RecursionAvailable = true

		// Set the response right away
		d.Res = &resp
		return nil
	}

	return next.ServeDNS(d, nil)
}
