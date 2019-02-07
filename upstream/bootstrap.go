package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hmage/golibs/log"
	"github.com/joomcode/errorx"
)

type bootstrapper struct {
	address        string        // in form of "tls://one.one.one.one:853"
	resolvers      []*Resolver   // list of Resolvers to use to resolve hostname, if necessary
	timeout        time.Duration // resolution duration (shared with the upstream) (0 == infinite timeout)
	resolvedConfig *tls.Config
	dialContext    func(ctx context.Context, network, addr string) (net.Conn, error)
	sync.RWMutex
}

// Resolver is wrapper for resolver and it's address
type Resolver struct {
	resolver        *net.Resolver // net.Resolver
	resolverAddress string        // Resolver's address
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
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, resolverAddress)
		},
	}
	return r
}

// LookupIPAddr returns result of LookupIPAddr method of Resolver's net.Resolver
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return r.resolver.LookupIPAddr(ctx, host)
}

func toBoot(address string, bootstrapAddr []string, timeout time.Duration) bootstrapper {
	resolvers := []*Resolver{}
	if bootstrapAddr != nil && len(bootstrapAddr) != 0 {
		for idx, adr := range bootstrapAddr {
			_, _, err := net.SplitHostPort(adr)
			if err != nil {
				// Add the default port for bootstrap DNS address if no port is defined
				adr = net.JoinHostPort(adr, "53")
				bootstrapAddr[idx] = adr
			}
		}

		// Create list of resolvers for parallel lookup
		for _, boot := range bootstrapAddr {
			r := NewResolver(boot, timeout)
			resolvers = append(resolvers, r)
		}
	} else {
		// nil resolver if the default one
		resolvers = append(resolvers, NewResolver("", timeout))
	}

	return bootstrapper{
		address:   address,
		resolvers: resolvers,
		timeout:   timeout,
	}
}

// will get usable IP address from Address field, and caches the result
func (n *bootstrapper) get() (*tls.Config, func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	n.RLock()
	if n.dialContext != nil && n.resolvedConfig != nil { // fast path
		tlsconfig, dialContext := n.resolvedConfig, n.dialContext
		n.RUnlock()
		return tlsconfig, dialContext, nil
	}

	//
	// Slow path: resolve the IP address of the n.address's host
	//

	// get a host without port
	host, port, err := n.getAddressHostPort()
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

		dialContext := createDialContext([]string{resolverAddress}, n.timeout)

		n.dialContext = dialContext
		config := &tls.Config{ServerName: host}
		n.resolvedConfig = config
		n.Unlock()
		return config, n.dialContext, nil
	}

	// Don't lock anymore (we can launch multiple lookup requests at a time)
	// Otherwise, it might mess with the timeout specified for the Upstream
	// See here: https://github.com/AdguardTeam/dnsproxy/issues/15
	n.RUnlock()

	//
	// if it's a hostname
	//

	ctx, cancel := context.WithTimeout(context.TODO(), n.timeout)
	defer cancel() // important to avoid a resource leak

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
		return nil, nil, fmt.Errorf("couldn't find any suitable IP slice address for host %s", host)
	}

	n.Lock()
	defer n.Unlock()

	dialContext := createDialContext(resolved, n.timeout)
	n.dialContext = dialContext
	n.resolvedConfig = &tls.Config{ServerName: host}
	return n.resolvedConfig, n.dialContext, nil
}

// createDialContext returns dialContext function that tries to establish connection with all given addresses one by one
func createDialContext(addresses []string, timeout time.Duration) (dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) {
	// decrease timeout for each dialer. Sum of timeouts equals bootstrap's timeout
	count := time.Duration(len(addresses))
	dialer := &net.Dialer{
		Timeout:   timeout / count,
		DualStack: true,
	}

	dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		errs := []error{}

		// Return first connection without error
		// Note that we're using bootstrapped resolverAddress instead of what's passed to the function
		for _, resolverAddress := range addresses {
			log.Printf("Dialing to %s", resolverAddress)
			start := time.Now()
			con, err := dialer.DialContext(ctx, network, resolverAddress)
			elapsed := time.Since(start) / time.Millisecond

			if err == nil {
				log.Printf("dialer successfully initialize connection to %s in %d milliseconds", resolverAddress, elapsed)
				return con, err
			}
			errs = append(errs, err)
			log.Printf("dialer failed to initialize connection to %s, in %d milliseconds, cause: %s", resolverAddress, elapsed, err)
		}
		return nil, errorx.DecorateMany("all dialers failed to initialize connection: ", errs...)
	}
	return
}

func (n *bootstrapper) getAddressHostPort() (string, string, error) {
	justHostPort := n.address
	if strings.Contains(n.address, "://") {
		parsedURL, err := url.Parse(n.address)
		if err != nil {
			return "", "", errorx.Decorate(err, "failed to parse %s", n.address)
		}

		justHostPort = parsedURL.Host
	}

	// convert host to IP if necessary, we know that it's scheme://hostname:port/

	// get a host without port
	return net.SplitHostPort(justHostPort)
}
