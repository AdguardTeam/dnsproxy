package upstream

import (
	"testing"

	"github.com/miekg/dns"
)

func TestDNSTruncated(t *testing.T) {
	// AdGuard DNS
	address := "94.140.14.14:53"
	// Google DNS
	// address := "8.8.8.8:53"
	u, err := AddressToUpstream(address, Options{Timeout: timeout})

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
