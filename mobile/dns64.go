// Utility functions for NAT64 prefix calculation (see https://tools.ietf.org/html/rfc7050).
// We called calculateNAT64Prefix in the separate goroutine after proxy starts.
// - Checks if dns64 addresses are IPv6.
// - Starts ticker with resolverTimeout. It's necessary to make several calculation tryouts (5 tryouts with a break of resolverTimeout).
// - getNAT64PrefixParallel starts parallel prefix calculation with all available dns64 upstreams.
// - getNAT64PrefixWithClient returns result of ipv4only.arpa AAAA request exchange via dns.Client.
// - getNAT64PrefixFromDNSResponse parses AAAA response for NAT64 prefix. Valid answer is:
//   * First 12 bytes are NAT64 prefix
//   * Last 4 bytes are required "well-known IPv4" addresses: wellKnownIpv4First or wellKnownIpv4Second
// - NAT64 prefix is set to proxy after successful validation.
// - getImportantError called if all dns64 upstreams failed to calculate NAT64 prefix.
// - When the network changes, the following errors may occur:
//   * Timeout
//   * SyscallError with "connect" message
// - There is no real error in this case and we should retry to calculate NAT64 prefix one more time
// - The calculation ends after it's success or after 5 unsuccessful attempts.

package mobile

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

// Byte representation of IPv4 addresses we are looking for after NAT64 prefix while dns response parsing
// It's two "well-known IPv4" addresses defined for Pref64::/n
// https://tools.ietf.org/html/rfc7050#section-2.2
var wellKnownIPv4First = []byte{192, 0, 0, 171}  //nolint
var wellKnownIPv4Second = []byte{192, 0, 0, 170} //nolint

const resolverTimeout = 5 * time.Second

// getImportantError looks for errors that may occurs on network change: network is unreachable or client timeout
// if errs contains one of this errors we should try to exchange ipv4only.arpa again
func getImportantError(errs []error) error {
	for _, err := range errs {
		// Timeout
		if os.IsTimeout(err) {
			return nil
		}

		// Let's put out error syscall
		if e, ok := err.(*net.OpError); ok {
			if er, ok := e.Err.(*os.SyscallError); ok {
				// No connection, let,s try again
				if er.Syscall == "connect" {
					return nil
				}
			}
		}
	}

	// No important errors in errs slice
	return errorx.DecorateMany("Failed to get NAT64 prefix with all upstreams:", errs...)
}

// validateIPv6Addresses returns slice of valid ipv6 addresses. Param dns64 is a list of system dns upstreams (each on new line)
func validateIPv6Addresses(dns64 string) []string {
	addresses := []string{}
	lines := strings.Split(dns64, "\n")
	for _, address := range lines {
		if address == "" {
			continue
		}

		// DNS64 upstream is just a plain DNS host:port
		// First let's check port
		_, _, err := net.SplitHostPort(address)
		if err != nil {
			// Doesn't have a port, we should add default one
			address = net.JoinHostPort(address, "53")
		}

		// Separate ip from port. It should be IPv6 address
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}

		// ParseIP func may return IPv6 address with zero 12-bytes prefix
		ip := net.ParseIP(host)
		if len(ip) != net.IPv6len || ip.To4() != nil {
			continue
		}

		// Add address to slice after validation
		addresses = append(addresses, address)
	}

	return addresses
}

// calculateNAT64Prefix should be called inside the goroutine.
// This func validates dns64 addresses and starts ticker for prefix calculation
// Each tryout starts after resolverTimeout. If getNAT64PrefixParallel returns an error it breaks the loop
// It also breaks the loop and set prefix to proxy after successfully calculation
func calculateNAT64Prefix(p *proxy.Proxy, dns64 string) {
	addresses := validateIPv6Addresses(dns64)
	if len(addresses) == 0 {
		log.Tracef("no dns64 upstreams specified")
		return
	}

	count := 1
	var prefix []byte
	ticker := time.NewTicker(resolverTimeout)
	for range ticker.C {
		log.Tracef("%d tryout of NAT64 prefix calculation", count)
		res := getNAT64PrefixParallel(addresses)

		if res.err != nil {
			log.Tracef("Failed to lookup for ipv4only.arpa: %s", res.err)
			break
		}

		// Non-zero prefix. Break the loop
		if res.prefix != nil {
			prefix = res.prefix
			break
		}

		// Five tryouts
		if count == 5 {
			break
		}
		count++
	}

	if len(prefix) != 12 {
		log.Tracef("Failed to calculate NAT64 prefix")
	}

	p.SetNAT64Prefix(prefix)
}

// createIpv4ArpaMessage creates AAAA request for the "Well-Known IPv4-only Name"
// this request should be exchanged with DNS64 upstreams.
func createIpv4ArpaMessage() *dns.Msg {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "ipv4only.arpa.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
	}
	return &req
}

// getNAT64PrefixFromResponse parses a response for NAT64 prefix
// valid answer should contains the following AAAA record:
//
// - 16 bytes record
// - first 12 bytes is NAT64 prefix
// - last 4 bytes are required IPv4: wellKnownIpv4First or wellKnownIpv4Second
// we use simplified algorithm and consider the first matched record to be valid
func getNAT64PrefixFromDNSResponse(r *dns.Msg) ([]byte, error) {
	var prefix []byte
	for _, reply := range r.Answer {
		a, ok := reply.(*dns.AAAA)
		if !ok {
			log.Tracef("Answer is not AAAA record")
			continue
		}
		ip := a.AAAA

		// Let's separate IPv4 part from NAT64 prefix
		ipv4 := ip[12:]
		if len(ipv4) != net.IPv4len {
			continue
		}

		// Compare IPv4 part to wellKnownIPv4First and wellKnownIPv4Second
		if !ipv4.Equal(wellKnownIPv4First) && !ipv4.Equal(wellKnownIPv4Second) {
			continue
		}

		// Set NAT64 prefix and break the loop
		log.Tracef("NAT64 prefix was obtained from response. Answer is: %s", ip.String())
		prefix = ip[:12]
		break
	}

	if len(prefix) == 0 {
		return nil, fmt.Errorf("no NAT64 prefix in answers")
	}

	return prefix, nil
}

// nat64Result is a result of NAT64 prefix calculation
type nat64Result struct {
	prefix []byte
	err    error
}

// getNAT64PrefixParallel starts parallel NAT64 prefix calculation with all available dns64 upstreams
func getNAT64PrefixParallel(dns64 []string) nat64Result {
	ch := make(chan nat64Result, len(dns64))
	for _, d := range dns64 {
		go getNAT64PrefixAsync(d, ch)
	}

	errs := []error{}
	for {
		select {
		case rep := <-ch:
			if rep.err != nil {
				errs = append(errs, rep.err)
				if len(errs) == len(dns64) {
					return nat64Result{err: getImportantError(errs)}
				}
			} else {
				return rep
			}
		}
	}
}

// getNAT64PrefixWithClient sends ipv4only.arpa AAAA request to dns64 address via dns.Client
// In case of successfully exchange it returns result of getNAT64PrefixFromDNSResponse
func getNAT64PrefixWithClient(dns64 string) nat64Result {
	req := createIpv4ArpaMessage()
	tcpClient := dns.Client{Net: "tcp", Timeout: resolverTimeout}
	reply, _, tcpErr := tcpClient.Exchange(req, dns64)
	if tcpErr != nil {
		return nat64Result{err: tcpErr}
	}

	prefix, err := getNAT64PrefixFromDNSResponse(reply)
	return nat64Result{prefix, err}
}

// getNAT64PrefixAsync sends result of getNAT64PrefixWithClient into the channel
func getNAT64PrefixAsync(dns64 string, ch chan nat64Result) {
	ch <- getNAT64PrefixWithClient(dns64)
}
