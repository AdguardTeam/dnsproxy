package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// NextProtoDQ is the ALPN token for DoQ. During the connection establishment,
// DNS/QUIC support is indicated by selecting the ALPN token "doq" in the
// crypto handshake.
// The current draft version is https://datatracker.ietf.org/doc/rfc9250/.
const NextProtoDQ = "doq"

// compatProtoDQ is a list of ALPN tokens used by a QUIC connection.
// NextProtoDQ is the latest draft version supported by dnsproxy, but it also
// includes previous drafts.
var compatProtoDQ = []string{NextProtoDQ, "doq-i00", "dq", "doq-i02"}

// RootCAs is the CertPool that must be used by all upstreams. Redefining
// RootCAs makes sense on iOS to overcome the 15MB memory limit of the
// NEPacketTunnelProvider.
var RootCAs *x509.CertPool

// CipherSuites is a custom list of TLSv1.2 ciphers.
var CipherSuites []uint16

// TODO(ameshkov): refactor bootstrapper, it's overcomplicated and hard to
// understand what it does.
type bootstrapper struct {
	// URL is the upstream server address.
	URL *url.URL

	// resolvers is a list of *net.Resolver to use to resolve the upstream
	// hostname, if necessary.
	resolvers []*Resolver

	// dialContext is the dial function for creating unencrypted TCP
	// connections.
	dialContext dialHandler

	// resolvedConfig is a *tls.Config that is used for encrypted DNS protocols.
	resolvedConfig *tls.Config

	// sessionsCache is necessary to achieve TLS session resumption.  We create
	// once when the bootstrapper is created and re-use every time when we need
	// to create a new tls.Config.
	sessionsCache tls.ClientSessionCache

	// guard protects dialContext and resolvedConfig.
	guard sync.RWMutex

	// options is the Options that were passed to the AddressToUpstream
	// function.  It configures different upstream properties: callbacks for
	// checking certificates, timeout, etc.
	options *Options
}

// newBootstrapperResolved creates a new bootstrapper that already contains
// resolved config. This can be done only in the case when we already know the
// resolver IP address passed via options.
func newBootstrapperResolved(upsURL *url.URL, options *Options) (*bootstrapper, error) {
	// get a host without port
	host, port, err := net.SplitHostPort(upsURL.Host)
	if err != nil {
		return nil, fmt.Errorf("bootstrapper requires port in address %s", upsURL)
	}

	var resolverAddresses []string
	for _, ip := range options.ServerIPAddrs {
		addr := net.JoinHostPort(ip.String(), port)
		resolverAddresses = append(resolverAddresses, addr)
	}

	b := &bootstrapper{
		URL:     upsURL,
		options: options,
		// Use the default capacity for the LRU cache.  It may be useful to
		// store several caches since the user may be routed to different
		// servers in case there's load balancing on the server-side.
		sessionsCache: tls.NewLRUClientSessionCache(0),
	}
	b.dialContext = b.createDialContext(resolverAddresses)
	b.resolvedConfig = b.createTLSConfig(host)

	return b, nil
}

// newBootstrapper initializes a new bootstrapper instance. u is the original
// resolver address string (i.e. tls://one.one.one.one:853), options is the
// upstream configuration options.
func newBootstrapper(u *url.URL, options *Options) (b *bootstrapper, err error) {
	resolvers := []*Resolver{}
	if len(options.Bootstrap) != 0 {
		// Create a list of resolvers for parallel lookup
		for _, boot := range options.Bootstrap {
			var r *Resolver
			r, err = NewResolver(boot, options)
			if err != nil {
				return nil, err
			}

			resolvers = append(resolvers, r)
		}
	} else {
		r, _ := NewResolver("", options) // NewResolver("") always succeeds
		// nil resolver if the default one
		resolvers = append(resolvers, r)
	}

	return &bootstrapper{
		URL:       u,
		resolvers: resolvers,
		options:   options,
		// Use the default capacity for the LRU cache.  It may be useful to
		// store several caches since the user may be routed to different
		// servers in case there's load balancing on the server-side.
		sessionsCache: tls.NewLRUClientSessionCache(0),
	}, nil
}

// dialHandler describes the dial function for creating unencrypted network
// connections to the upstream server.  Internally, this function will use the
// supplied bootstrap DNS servers to resolve the upstream's IP address and only
// then it will actually establish a connection.
type dialHandler func(ctx context.Context, network, addr string) (net.Conn, error)

// get is the main function of bootstrapper that does two crucial things.
// First, it creates an instance of a dialHandler function that should be used
// by the Upstream to establish a connection to the upstream DNS server.  This
// dialHandler in a lazy manner resolves the DNS server IP address using the
// bootstrap DNS servers supplied to this bootstrapper instance.  It will also
// create an instance of *tls.Config that should be used for establishing an
// encrypted connection for DoH/DoT/DoQ.
func (n *bootstrapper) get() (*tls.Config, dialHandler, error) {
	n.guard.RLock()
	if n.dialContext != nil && n.resolvedConfig != nil { // fast path
		tlsConfig, dialContext := n.resolvedConfig, n.dialContext
		n.guard.RUnlock()
		return tlsConfig.Clone(), dialContext, nil
	}

	//
	// Slow path: resolve the IP address of the n.address's host
	//

	// get a host without port
	u := n.URL
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		n.guard.RUnlock()
		return nil, nil, fmt.Errorf("bootstrapper requires port in address %s", u)
	}

	// if n.address's host is an IP, just use it right away.
	ip := net.ParseIP(host)
	if ip != nil {
		n.guard.RUnlock()

		resolverAddress := net.JoinHostPort(host, port)

		// Upgrade lock to protect n.resolvedConfig.
		// TODO(ameshkov): rework, that's not how it should be done.
		n.guard.Lock()
		defer n.guard.Unlock()

		n.dialContext = n.createDialContext([]string{resolverAddress})
		n.resolvedConfig = n.createTLSConfig(host)
		return n.resolvedConfig, n.dialContext, nil
	}

	// Don't lock anymore (we can launch multiple lookup requests at a time)
	// Otherwise, it might mess with the timeout specified for the Upstream
	// See here: https://github.com/AdguardTeam/dnsproxy/issues/15
	n.guard.RUnlock()

	//
	// if it's a hostname
	//

	var ctx context.Context
	if n.options.Timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(context.Background(), n.options.Timeout)
		defer cancel()
	} else {
		ctx = context.Background()
	}

	addrs, err := LookupParallel(ctx, n.resolvers, host)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup %s: %w", host, err)
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

	n.guard.Lock()
	defer n.guard.Unlock()

	n.dialContext = n.createDialContext(resolved)
	n.resolvedConfig = n.createTLSConfig(host)
	return n.resolvedConfig, n.dialContext, nil
}

// createTLSConfig creates a client TLS config that will be used to establish
// an encrypted connection for DoH/DoT/DoQ.
func (n *bootstrapper) createTLSConfig(host string) *tls.Config {
	tlsConfig := &tls.Config{
		ServerName:            host,
		RootCAs:               RootCAs,
		CipherSuites:          CipherSuites,
		ClientSessionCache:    n.sessionsCache,
		MinVersion:            tls.VersionTLS12,
		InsecureSkipVerify:    n.options.InsecureSkipVerify,
		VerifyPeerCertificate: n.options.VerifyServerCertificate,
		VerifyConnection:      n.options.VerifyConnection,
	}

	// Depending on the URL scheme, we choose what ALPN will be advertised by
	// the client.
	switch n.URL.Scheme {
	case "tls":
		// Don't use the ALPN since some servers currently do not accept it.
		//
		// See https://github.com/ameshkov/dnslookup/issues/19.
	case "https":
		httpVersions := n.options.HTTPVersions
		if httpVersions == nil {
			httpVersions = DefaultHTTPVersions
		}

		var nextProtos []string
		for _, v := range httpVersions {
			nextProtos = append(nextProtos, string(v))
		}

		tlsConfig.NextProtos = nextProtos
	case "quic":
		tlsConfig.NextProtos = compatProtoDQ
	}

	return tlsConfig
}

// createDialContext returns a dialHandler function that tries to establish the
// connection to each of the provided addresses one by one.
func (n *bootstrapper) createDialContext(addresses []string) (dialContext dialHandler) {
	dialer := &net.Dialer{
		Timeout: n.options.Timeout,
	}

	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		if len(addresses) == 0 {
			return nil, errors.Error("no addresses")
		}

		var errs []error

		// Return first connection without error
		// Note that we're using bootstrapped resolverAddress instead of what's passed to the function
		for _, resolverAddress := range addresses {
			log.Tracef("Dialing to %s", resolverAddress)
			start := time.Now()
			conn, err := dialer.DialContext(ctx, network, resolverAddress)
			elapsed := time.Since(start)
			if err == nil {
				log.Tracef(
					"dialer has successfully initialized connection to %s in %s",
					resolverAddress,
					elapsed,
				)

				return conn, nil
			}

			errs = append(errs, err)

			log.Tracef(
				"dialer failed to initialize connection to %s, in %s, cause: %s",
				resolverAddress,
				elapsed,
				err,
			)
		}

		return nil, errors.List("all dialers failed", errs...)
	}
}
