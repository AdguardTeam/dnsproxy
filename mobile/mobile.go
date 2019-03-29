/*
Package mobile contains a simple mobile API for github.com/AdguardTeam/dnsproxy
*/
package mobile

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
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

// DNSProxy represents a proxy with it's configuration
type DNSProxy struct {
	Config *Config // Proxy configuration

	dnsProxy *proxy.Proxy
	sync.RWMutex
}

// Config is the DNS proxy configuration which uses only the subset of types that is supported by gomobile
// In Java API this structure becomes an object that needs to be configured and setted as field of DNSProxy
type Config struct {
	ListenAddr    string // IP address to listen to
	ListenPort    int    // Port to listen to
	BootstrapDNS  string // A list of bootstrap DNS (i.e. 8.8.8.8:53 each on a new line)
	Fallbacks     string // A list of fallback resolvers that will be used if the main one is not available (i.e. 1.1.1.1:53 each on a new line)
	Upstreams     string // A list of upstream resolvers (each on a new line)
	DNS64Upstream string // A list of DNS64 upstreams for ipv6-only network (each on new line)
	Timeout       int    // Default timeout for all resolvers (milliseconds)
	CacheSize     int    // Maximum number of elements in the cache. Default size: 1000
	AllServers    bool   // If true, parallel queries to all configured upstream servers are enabled
}

// Start starts the DNS proxy
func (d *DNSProxy) Start() error {
	d.Lock()

	if d.dnsProxy != nil {
		d.Unlock()
		return errors.New("DNS proxy is already started")
	}

	c, err := createConfig(d.Config)
	if err != nil {
		d.Unlock()
		return fmt.Errorf("cannot start the DNS proxy: %s", err)
	}
	d.dnsProxy = &proxy.Proxy{Config: *c}

	// defer called here 'cause otherwise d.dnsProxy may be null
	defer func() {
		log.Tracef("CALL DEFER!")
		d.Unlock()
		go calculateNAT64Prefix(d.dnsProxy, d.Config.DNS64Upstream)
	}()

	// Start the proxy
	return d.dnsProxy.Start()
}

// Stop stops the DNS proxy
func (d *DNSProxy) Stop() error {
	d.Lock()
	defer d.Unlock()

	var err error

	if d.dnsProxy != nil {
		err = d.dnsProxy.Stop()
		d.dnsProxy = nil
	}

	return err
}

// Addr gets the address proxy is currently listening to
func (d *DNSProxy) Addr() string {
	d.Lock()
	defer d.Unlock()

	if d.dnsProxy == nil {
		return ""
	}

	addr := d.dnsProxy.Addr(proxy.ProtoUDP)
	if addr == nil {
		return ""
	}

	return addr.String()
}

// createProxyConfig creates proxy.Config from mobile.Config values
func createConfig(config *Config) (*proxy.Config, error) {
	listenIP := net.ParseIP(config.ListenAddr)
	if listenIP == nil {
		return nil, fmt.Errorf("cannot parse %s", config.ListenAddr)
	}
	timeout := time.Duration(config.Timeout) * time.Millisecond

	// Init listen addresses and upstreams
	listenUDPAddr := &net.UDPAddr{Port: config.ListenPort, IP: listenIP}
	listenTCPAddr := &net.TCPAddr{Port: config.ListenPort, IP: listenIP}
	upstreams := make([]upstream.Upstream, 0)

	// Check bootstraps list for empty strings
	bootstrapLines := strings.Split(config.BootstrapDNS, "\n")
	var bootstraps []string
	for _, line := range bootstrapLines {
		if line == "" {
			continue
		}

		bootstraps = append(bootstraps, line)
	}

	lines := strings.Split(config.Upstreams, "\n")

	for i, line := range lines {
		if line == "" {
			continue
		}

		dnsUpstream, err := upstream.AddressToUpstream(line, upstream.Options{Bootstrap: bootstraps, Timeout: timeout})
		if err != nil {
			return nil, fmt.Errorf("cannot prepare the upstream %s (%s): %s", line, config.BootstrapDNS, err)
		}
		log.Printf("Upstream %d: %s", i, dnsUpstream.Address())
		upstreams = append(upstreams, dnsUpstream)
	}

	// Create the config
	proxyConfig := proxy.Config{
		UDPListenAddr: listenUDPAddr,
		TCPListenAddr: listenTCPAddr,
		Upstreams:     upstreams,
		AllServers:    config.AllServers,
		CacheSize:     config.CacheSize,
	}

	if config.Fallbacks != "" {
		fallbacks := []upstream.Upstream{}
		lines = strings.Split(config.Fallbacks, "\n")
		for i, line := range lines {
			if line == "" {
				continue
			}

			fallback, err := upstream.AddressToUpstream(line, upstream.Options{Timeout: timeout})
			if err != nil {
				return nil, fmt.Errorf("cannot parse the fallback %s (%s): %s", line, config.BootstrapDNS, err)
			}

			log.Printf("Fallback %d: %s", i, fallback.Address())
			fallbacks = append(fallbacks, fallback)
		}
		proxyConfig.Fallbacks = fallbacks
	}

	return &proxyConfig, nil
}

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

// validateIPv6Addresses returns only valid ipv6 addresses
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
			// Doesn't have port, add default one
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
