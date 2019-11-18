package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

// RootCAs is the CertPool that must be used by all upstreams
// Redefining RootCAs makes sense on iOS to overcome the 15MB memory limit of the NEPacketTunnelProvider
// nolint
var RootCAs *x509.CertPool

type bootstrapper struct {
	address        string        // in form of "tls://one.one.one.one:853"
	resolvers      []*Resolver   // list of Resolvers to use to resolve hostname, if necessary
	timeout        time.Duration // resolution duration (shared with the upstream) (0 == infinite timeout)
	dialContext    dialHandler   // specifies the dial function for creating unencrypted TCP connections.
	resolvedConfig *tls.Config
	sync.RWMutex
}

// Resolver is wrapper for resolver and it's address
type Resolver struct {
	resolver        *net.Resolver // net.Resolver
	resolverAddress string        // Resolver's address
	upstream        Upstream
}

// toBootResolved creates a new bootstrapper that already contains resolved config.
// This can be done only in the case when we already know the resolver IP address.
// timeout is also used for establishing TCP connections
func toBootResolved(address string, serverIP net.IP, timeout time.Duration) (*bootstrapper, error) {
	// get a host without port
	host, port, err := getAddressHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("bootstrapper requires port in address %s", address)
	}

	// Upgrade lock to protect n.resolved
	resolverAddress := net.JoinHostPort(serverIP.String(), port)

	return &bootstrapper{
		address:        address,
		dialContext:    createDialContext([]string{resolverAddress}, timeout),
		resolvedConfig: createTLSConfig(host),
		timeout:        timeout,
	}, nil
}

// toBoot initializes a new bootstrapper instance
// address -- original resolver address string (i.e. tls://one.one.one.one:853)
// bootstrapAddr -- a list of bootstrap DNS resolvers' addresses
// timeout -- DNS query timeout
func toBoot(address string, bootstrapAddr []string, timeout time.Duration) *bootstrapper {
	resolvers := []*Resolver{}
	if bootstrapAddr != nil && len(bootstrapAddr) != 0 {
		// Create a list of resolvers for parallel lookup
		for _, boot := range bootstrapAddr {
			r := NewResolver(boot, timeout)
			resolvers = append(resolvers, r)
		}
	} else {
		// nil resolver if the default one
		resolvers = append(resolvers, NewResolver("", timeout))
	}

	return &bootstrapper{
		address:   address,
		resolvers: resolvers,
		timeout:   timeout,
	}
}

// NewResolver creates an instance of Resolver structure with defined net.Resolver and it's address
// resolverAddress is address of net.Resolver
// The host in the address parameter of Dial func will always be a literal IP address (from documentation)
func NewResolver(resolverAddress string, timeout time.Duration) *Resolver {
	r := &Resolver{}

	// set default net.Resolver as a resolver if resolverAddress is empty
	if resolverAddress == "" {
		r.resolver = &net.Resolver{}
		return r
	}

	r.resolverAddress = resolverAddress
	opts := Options{
		Timeout: timeout,
	}
	var err error
	r.upstream, err = AddressToUpstream(resolverAddress, opts)
	if err != nil {
		log.Error("AddressToUpstream: %s", err)
		return r
	}

	// Validate the bootstrap resolver. It must be either a plain DNS resolver.
	// Or a DOT/DOH resolver with an IP address (not a hostname).
	if !isResolverValidBootstrap(r.upstream) {
		r.upstream = nil
		log.Error("Resolver %s is not eligible to be a bootstrap DNS server", resolverAddress)
	}

	return r
}

// isResolverValidBootstrap checks if the upstream is eligible to be a bootstrap DNS server
// DNSCrypt and plain DNS resolvers are okay
// DOH and DOT are okay only in the case if an IP address is used in the IP address
func isResolverValidBootstrap(upstream Upstream) bool {
	if u, ok := upstream.(*dnsOverTLS); ok {
		host, _, err := net.SplitHostPort(u.Address())
		if err != nil {
			return false
		}

		if ip := net.ParseIP(host); ip != nil {
			return true
		}
		return false
	}

	if u, ok := upstream.(*dnsOverHTTPS); ok {
		urlAddr, err := url.Parse(u.Address())
		if err != nil {
			return false
		}
		host, _, err := net.SplitHostPort(urlAddr.Host)
		if err != nil {
			host = urlAddr.Host
		}

		if ip := net.ParseIP(host); ip != nil {
			return true
		}
		return false
	}

	return true
}

type resultError struct {
	resp *dns.Msg
	err  error
}

func (r *Resolver) resolve(host string, qtype uint16, ch chan *resultError) {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{
			Name:   host,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		},
	}
	resp, err := r.upstream.Exchange(&req)
	ch <- &resultError{resp, err}
}

func setIPAddresses(ipAddrs *[]net.IPAddr, answers []dns.RR) {
	for _, ans := range answers {
		if a, ok := ans.(*dns.A); ok {
			ip := net.IPAddr{IP: a.A}
			*ipAddrs = append(*ipAddrs, ip)
		} else if a, ok := ans.(*dns.AAAA); ok {
			ip := net.IPAddr{IP: a.AAAA}
			*ipAddrs = append(*ipAddrs, ip)
		}
	}
}

// LookupIPAddr returns result of LookupIPAddr method of Resolver's net.Resolver
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if r.resolver != nil {
		// use system resolver
		return r.resolver.LookupIPAddr(ctx, host)
	}

	if r.upstream == nil || len(host) == 0 {
		return []net.IPAddr{}, nil
	}

	if host[:1] != "." {
		host += "."
	}

	ch := make(chan *resultError)
	go r.resolve(host, dns.TypeA, ch)
	go r.resolve(host, dns.TypeAAAA, ch)

	var ipAddrs []net.IPAddr
	var errs []error
	n := 0
wait:
	for {
		var re *resultError
		select {
		case re = <-ch:
			if re.err != nil {
				errs = append(errs, re.err)
			} else {
				setIPAddresses(&ipAddrs, re.resp.Answer)
			}
			n++
			if n == 2 {
				break wait
			}
		}
	}

	if len(ipAddrs) == 0 && len(errs) != 0 {
		return []net.IPAddr{}, errs[0]
	}

	return ipAddrs, nil
}

// dialHandler specifies the dial function for creating unencrypted TCP connections.
type dialHandler func(ctx context.Context, network, addr string) (net.Conn, error)

// will get usable IP address from Address field, and caches the result
func (n *bootstrapper) get() (*tls.Config, dialHandler, error) {
	n.RLock()
	if n.dialContext != nil && n.resolvedConfig != nil { // fast path
		tlsConfig, dialContext := n.resolvedConfig, n.dialContext
		n.RUnlock()
		return tlsConfig, dialContext, nil
	}

	//
	// Slow path: resolve the IP address of the n.address's host
	//

	// get a host without port
	host, port, err := getAddressHostPort(n.address)
	if err != nil {
		addr := n.address
		n.RUnlock()
		return nil, nil, fmt.Errorf("bootstrapper requires port in address %s", addr)
	}

	// if n.address's host is an IP, just use it right away
	ip := net.ParseIP(host)
	if ip != nil {
		n.RUnlock()

		// Upgrade lock to protect n.resolved
		resolverAddress := net.JoinHostPort(host, port)
		n.Lock()
		defer n.Unlock()

		dialContext := createDialContext([]string{resolverAddress}, n.timeout)
		n.dialContext = dialContext
		config := createTLSConfig(host)
		n.resolvedConfig = config
		return config, n.dialContext, nil
	}

	// Don't lock anymore (we can launch multiple lookup requests at a time)
	// Otherwise, it might mess with the timeout specified for the Upstream
	// See here: https://github.com/AdguardTeam/dnsproxy/issues/15
	n.RUnlock()

	//
	// if it's a hostname
	//

	var ctx context.Context
	if n.timeout > 0 {
		ctxWithTimeout, cancel := context.WithTimeout(context.TODO(), n.timeout)
		defer cancel() // important to avoid a resource leak
		ctx = ctxWithTimeout
	} else {
		ctx = context.Background()
	}

	addrs, err := LookupParallel(ctx, n.resolvers, host)
	if err != nil {
		return nil, nil, errorx.Decorate(err, "failed to lookup %s", host)
	}

	resolved := []string{}
	for _, addr := range addrs {
		if addr.IP.To4() == nil && addr.IP.To16() == nil {
			continue
		}

		resolved = append(resolved, net.JoinHostPort(addr.String(), port))
	}

	if len(resolved) == 0 {
		// couldn't find any suitable IP address
		return nil, nil, fmt.Errorf("couldn't find any suitable IP address for host %s", host)
	}

	n.Lock()
	defer n.Unlock()

	dialContext := createDialContext(resolved, n.timeout)
	n.dialContext = dialContext
	n.resolvedConfig = createTLSConfig(host)
	return n.resolvedConfig, n.dialContext, nil
}

// createDialContext returns dialContext function that tries to establish connection with all given addresses one by one
func createDialContext(addresses []string, timeout time.Duration) (dialContext dialHandler) {
	dialer := &net.Dialer{
		Timeout:   timeout,
		DualStack: true,
	}

	dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		errs := []error{}

		// Return first connection without error
		// Note that we're using bootstrapped resolverAddress instead of what's passed to the function
		for _, resolverAddress := range addresses {
			log.Tracef("Dialing to %s", resolverAddress)
			start := time.Now()
			con, err := dialer.DialContext(ctx, network, resolverAddress)
			elapsed := time.Since(start) / time.Millisecond

			if err == nil {
				log.Tracef("dialer has successfully initialized connection to %s in %d milliseconds", resolverAddress, elapsed)
				return con, err
			}
			errs = append(errs, err)
			log.Tracef("dialer failed to initialize connection to %s, in %d milliseconds, cause: %s", resolverAddress, elapsed, err)
		}
		return nil, errorx.DecorateMany("all dialers failed to initialize connection: ", errs...)
	}
	return
}

// createTLSConfig creates a client TLS config
func createTLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName: host,
		RootCAs:    RootCAs,
		MinVersion: tls.VersionTLS12,
	}
}

// getAddressHostPort splits resolver address into host and port
// returns host, port
func getAddressHostPort(address string) (string, string, error) {
	justHostPort := address
	if strings.Contains(address, "://") {
		parsedURL, err := url.Parse(address)
		if err != nil {
			return "", "", errorx.Decorate(err, "failed to parse %s", address)
		}

		justHostPort = parsedURL.Host
	}

	// convert host to IP if necessary, we know that it's scheme://hostname:port/

	// get a host without port
	return net.SplitHostPort(justHostPort)
}
