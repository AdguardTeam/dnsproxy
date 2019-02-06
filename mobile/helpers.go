package mobile

import (
	"errors"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// DNSStamp is mobile-friendly DNS stamp structure
type DNSStamp struct {
	Proto        int    // Protocol (0x00 for plain, 0x01 for DNSCrypt, 0x02 for DOH, 0x03 for DOT
	ServerAddr   string // Server address
	ProviderName string // Provider name
	Path         string // Path (for DOH)
}

// ParseDNSStamp parses a DNS stamp string and returns a stamp instance or an error
func ParseDNSStamp(stampStr string) (*DNSStamp, error) {
	serverStamp, err := dnsstamps.NewServerStampFromString(stampStr)
	if err != nil {
		return nil, err
	}

	return &DNSStamp{
		Proto:        int(serverStamp.Proto),
		ServerAddr:   serverStamp.ServerAddrStr,
		ProviderName: serverStamp.ProviderName,
		Path:         serverStamp.Path,
	}, nil
}

// TestUpstream checks if upstream is valid and available
// If it is, no error is returned. Otherwise this method returns an error with an explanation.
// * address - see upstream.AddressToUpstream for examples
// * bootstrap - an optional bootstrap DNS. You can pass several addresses separated by `\n` on a line
// * timeout - timeout in milliseconds
func TestUpstream(address string, bootstrap string, timeout int) error {
	t := time.Duration(timeout) * time.Millisecond

	bootstraps := []string{}

	// Check bootstrap for empty strings
	lines := strings.Split(bootstrap, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		bootstraps = append(bootstraps, line)
	}

	u, err := upstream.AddressToUpstream(address, bootstraps, t)
	if err != nil {
		return err
	}

	// Create a test DNS message
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "ipv4only.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	reply, err := u.Exchange(&req)

	if err != nil {
		return err
	}
	if len(reply.Answer) == 0 {
		return errors.New("DNS upstream returned reply with wrong number of answers")
	}

	// Everything else is supposed to be success
	return nil
}
