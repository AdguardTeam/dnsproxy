package upstream

import (
	"context"
	"testing"
	"time"
)

func TestNewResolver(t *testing.T) {
	r := NewResolver("1.1.1.1:53", 3*time.Second)

	ipAddrs, err := r.LookupIPAddr(context.TODO(), "cloudflare-dns.com")
	if err != nil {
		t.Fatalf("r.LookupIPAddr: %s", err)
	}

	// check that both IPv4 and IPv6 addresses exist
	var nIP4, nIP6 uint
	for _, ip := range ipAddrs {
		if ip.IP.To4() != nil {
			nIP4++
		} else {
			nIP6++
		}
	}

	if nIP4 == 0 || nIP6 == 0 {
		t.Fatalf("nIP4 == 0 || nIP6 == 0")
	}
}
