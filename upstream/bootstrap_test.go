package upstream

import (
	"context"
	"testing"
	"time"
)

// See the details here: https://github.com/AdguardTeam/dnsproxy/issues/18
func TestDialContext(t *testing.T) {
	resolved := []struct {
		addresses []string
		host      string
	}{
		{
			addresses: []string{"216.239.32.59:443"},
			host:      "dns.google.com",
		},
		{
			addresses: []string{"94.140.14.14:855", "94.140.14.14:853"},
			host:      "dns.adguard.com",
		},
		{
			addresses: []string{"1.1.1.1:5555", "1.1.1.1:853", "8.8.8.8:85"},
			host:      "1dot1dot1dot1.cloudflare-dns.com",
		},
	}
	b := bootstrapper{options: Options{Timeout: 2 * time.Second}}
	for _, test := range resolved {
		dialContext := b.createDialContext(test.addresses)
		_, err := dialContext(context.TODO(), "tcp", "")
		if err != nil {
			t.Fatalf("Couldn't dial to %s: %s", test.host, err)
		}
	}
}
