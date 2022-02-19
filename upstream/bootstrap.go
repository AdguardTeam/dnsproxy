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
	"golang.org/x/net/http2"
)

// NextProtoDQ is the ALPN token for DoQ. During connection establishment,
// DNS/QUIC support is indicated by selecting the ALPN token "dq" in the
// crypto handshake.
// Current draft version:
// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02
const NextProtoDQ = "doq-i02"

// compatProtoDQ is a list of ALPN tokens used by a QUIC connection.
// NextProtoDQ is the latest draft version supported by dnsproxy, but it also
// includes previous drafts.
var compatProtoDQ = []string{NextProtoDQ, "doq-i00", "dq", "doq"}

// RootCAs is the CertPool that must be used by all upstreams
// Redefining RootCAs makes sense on iOS to overcome the 15MB memory limit of the NEPacketTunnelProvider
// nolint
var RootCAs *x509.CertPool

// CipherSuites - custom list of TLSv1.2 ciphers
// nolint
var CipherSuites []uint16

// TODO: refactor bootstrapper, it's overcomplicated and hard to understand what it does
type bootstrapper struct {
	URL            *url.URL
	resolvers      []*Resolver // list of Resolvers to use to resolve hostname, if necessary
	dialContext    dialHandler // specifies the dial function for creating unencrypted TCP connections.
	resolvedConfig *tls.Config
	sync.RWMutex

	// stores options for AddressToUpstream func:
	// callbacks for checking certificates, timeout,
	// the need to verify the server certificate,
	// the addresses of upstream servers, etc
	options *Options
}

// newBootstrapperResolved creates a new bootstrapper that already contains resolved config.
// This can be done only in the case when we already know the resolver IP address.
// options -- Upstream customization options
func newBootstrapperResolved(upsURL *url.URL, options *Options) (*bootstrapper, error) {
	// get a host without port
	host, port, err := net.SplitHostPort(upsURL.Host)
	if err != nil {
		return nil, fmt.Errorf("bootstrapper requires port in address %s", upsURL.String())
	}

	var resolverAddresses []string
	for _, ip := range options.ServerIPAddrs {
		addr := net.JoinHostPort(ip.String(), port)
		resolverAddresses = append(resolverAddresses, addr)
	}

	b := &bootstrapper{
		URL:     upsURL,
		options: options,
	}
	b.dialContext = b.createDialContext(resolverAddresses)
	b.resolvedConfig = b.createTLSConfig(host)
	return b, nil
}

// newBootstrapper initializes a new bootstrapper instance
// address -- original resolver address string (i.e. tls://one.one.one.one:853)
// options -- Upstream customization options
func newBootstrapper(address *url.URL, options *Options) (*bootstrapper, error) {
	resolvers := []*Resolver{}
	if len(options.Bootstrap) != 0 {
		// Create a list of resolvers for parallel lookup
		for _, boot := range options.Bootstrap {
			r, err := NewResolver(boot, options)
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
		URL:       address,
		resolvers: resolvers,
		options:   options,
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
		return tlsConfig.Clone(), dialContext, nil
	}

	//
	// Slow path: resolve the IP address of the n.address's host
	//

	// get a host without port
	addr := n.URL
	host, port, err := net.SplitHostPort(addr.Host)
	if err != nil {
		n.RUnlock()
		return nil, nil, fmt.Errorf("bootstrapper requires port in address %s", addr.String())
	}

	// if n.address's host is an IP, just use it right away
	ip := net.ParseIP(host)
	if ip != nil {
		n.RUnlock()

		// Upgrade lock to protect n.resolved
		resolverAddress := net.JoinHostPort(host, port)
		n.Lock()
		defer n.Unlock()

		n.dialContext = n.createDialContext([]string{resolverAddress})
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
	n.Lock()
	defer n.Unlock()

	n.dialContext = n.createDialContext(resolved)
	n.resolvedConfig = n.createTLSConfig(host)

	return n.resolvedConfig, n.dialContext, nil
}

// createTLSConfig creates a client TLS config
func (n *bootstrapper) createTLSConfig(host string) *tls.Config {
	tlsConfig := &tls.Config{
		ServerName:            host,
		RootCAs:               RootCAs,
		CipherSuites:          CipherSuites,
		MinVersion:            tls.VersionTLS12,
		InsecureSkipVerify:    n.options.InsecureSkipVerify,
		VerifyPeerCertificate: n.options.VerifyServerCertificate,
	}

	// Depending on the URL scheme, we choose what ALPN will be advertised by
	// the client.
	switch n.URL.Scheme {
	case "tls":
		// Don't use the ALPN since some servers currently do not accept it.
		//
		// See https://github.com/ameshkov/dnslookup/issues/19.
	case "https":
		tlsConfig.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}
	case "quic":
		tlsConfig.NextProtos = compatProtoDQ
	}

	if n.options.TLSClientCertificates != nil {
		log.Printf("Passing TLS configuration with client authentication")
		tlsConfig.Certificates = []tls.Certificate{*n.options.TLSClientCertificates}
	}

	// The supported application level protocols should be specified only
	// for DNS-over-HTTPS and DNS-over-QUIC connections.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/2681.
	if n.URL.Scheme != "tls" {
		tlsConfig.NextProtos = append([]string{
			"http/1.1", http2.NextProtoTLS, NextProtoDQ,
		}, compatProtoDQ...)
	}

	return tlsConfig
}

// createDialContext returns dialContext function that tries to establish connection with all given addresses one by one
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
				log.Tracef("dialer has successfully initialized connection to %s in %s", resolverAddress, elapsed)

				return conn, nil
			}

			errs = append(errs, err)

			log.Tracef("dialer failed to initialize connection to %s, in %s, cause: %s", resolverAddress, elapsed, err)
		}

		return nil, errors.List("all dialers failed", errs...)
	}
}
