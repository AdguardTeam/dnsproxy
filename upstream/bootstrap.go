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

	"golang.org/x/net/http2"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
)

// NextProtoDQ - During connection establishment, DNS/QUIC support is indicated
// by selecting the ALPN token "dq" in the crypto handshake.
const NextProtoDQ = "dq"

// RootCAs is the CertPool that must be used by all upstreams
// Redefining RootCAs makes sense on iOS to overcome the 15MB memory limit of the NEPacketTunnelProvider
// nolint
var RootCAs *x509.CertPool

// CipherSuites - custom list of TLSv1.2 ciphers
// nolint
var CipherSuites []uint16

type bootstrapper struct {
	address            string        // in form of "tls://one.one.one.one:853"
	resolvers          []*Resolver   // list of Resolvers to use to resolve hostname, if necessary
	timeout            time.Duration // resolution duration (shared with the upstream) (0 == infinite timeout)
	insecureSkipVerify bool          // if true - tls.Config will have InsecureSkipVerify set to true

	dialContext    dialHandler // specifies the dial function for creating unencrypted TCP connections.
	resolvedConfig *tls.Config
	sync.RWMutex
}

// newBootstrapperResolved creates a new bootstrapper that already contains resolved config.
// This can be done only in the case when we already know the resolver IP address.
// timeout is also used for establishing TCP connections
// insecureSkipVerify -- if true, disable TLS certs verification
func newBootstrapperResolved(address string, serverIPAddrs []net.IP, timeout time.Duration, insecureSkipVerify bool) (*bootstrapper, error) {
	// get a host without port
	host, port, err := getAddressHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("bootstrapper requires port in address %s", address)
	}

	var resolverAddresses []string
	for _, ip := range serverIPAddrs {
		addr := net.JoinHostPort(ip.String(), port)
		resolverAddresses = append(resolverAddresses, addr)
	}

	b := &bootstrapper{
		address:            address,
		timeout:            timeout,
		insecureSkipVerify: insecureSkipVerify,
	}
	b.dialContext = b.createDialContext(resolverAddresses, timeout)
	b.resolvedConfig = b.createTLSConfig(host)

	return b, nil
}

// newBootstrapper initializes a new bootstrapper instance
// address -- original resolver address string (i.e. tls://one.one.one.one:853)
// bootstrapAddr -- a list of bootstrap DNS resolvers' addresses
// timeout -- DNS query timeout
// insecureSkipVerify -- if true, disable TLS certs verification
func newBootstrapper(address string, bootstrapAddr []string, timeout time.Duration, insecureSkipVerify bool) (*bootstrapper, error) {
	resolvers := []*Resolver{}
	if bootstrapAddr != nil && len(bootstrapAddr) != 0 {
		// Create a list of resolvers for parallel lookup
		for _, boot := range bootstrapAddr {
			r, err := NewResolver(boot, timeout)
			if err != nil {
				return nil, err
			}
			resolvers = append(resolvers, r)
		}
	} else {
		r, _ := NewResolver("", timeout) // NewResolver("") always succeeds
		// nil resolver if the default one
		resolvers = append(resolvers, r)
	}

	return &bootstrapper{
		address:            address,
		resolvers:          resolvers,
		timeout:            timeout,
		insecureSkipVerify: insecureSkipVerify,
	}, nil
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

		n.dialContext = n.createDialContext([]string{resolverAddress}, n.timeout)
		n.resolvedConfig = n.createTLSConfig(host)
		return n.resolvedConfig, n.dialContext, nil
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

	n.dialContext = n.createDialContext(resolved, n.timeout)
	n.resolvedConfig = n.createTLSConfig(host)
	return n.resolvedConfig, n.dialContext, nil
}

// createTLSConfig creates a client TLS config
func (n *bootstrapper) createTLSConfig(host string) *tls.Config {
	tlsConfig := &tls.Config{
		ServerName:         host,
		RootCAs:            RootCAs,
		CipherSuites:       CipherSuites,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: n.insecureSkipVerify,
	}

	tlsConfig.NextProtos = []string{
		"http/1.1", http2.NextProtoTLS, NextProtoDQ,
	}

	return tlsConfig
}

// createDialContext returns dialContext function that tries to establish connection with all given addresses one by one
func (n *bootstrapper) createDialContext(addresses []string, timeout time.Duration) (dialContext dialHandler) {
	dialer := &net.Dialer{
		Timeout: timeout,
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

		if len(errs) == 0 {
			return nil, fmt.Errorf("all dialers failed to initialize connection")
		}
		return nil, errorx.DecorateMany("all dialers failed to initialize connection: ", errs...)
	}
	return
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
