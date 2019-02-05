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

	"github.com/joomcode/errorx"
)

type bootstrapper struct {
	address        string        // in form of "tls://one.one.one.one:853"
	resolvers      []*Resolver   // list of Resolvers to use to resolve hostname, if necessary
	resolved       string        // in form "IP:port"
	timeout        time.Duration // resolution duration (shared with the upstream) (0 == infinite timeout)
	resolvedConfig *tls.Config
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
func (n *bootstrapper) get() (string, *tls.Config, error) {
	n.RLock()
	if n.resolved != "" { // fast path
		retval, tlsconfig := n.resolved, n.resolvedConfig
		n.RUnlock()
		return retval, tlsconfig, nil
	}

	//
	// Slow path: resolve the IP address of the n.address's host
	//

	// get a host without port
	host, port, err := n.getAddressHostPort()
	if err != nil {
		addr := n.address
		n.RUnlock()
		return "", nil, fmt.Errorf("bootstrapper requires port in address %s", addr)
	}

	// if n.address's host is an IP, just use it right away
	ip := net.ParseIP(host)
	if ip != nil {
		n.RUnlock()

		// Upgrade lock to protect n.resolved
		addr := net.JoinHostPort(host, port)
		n.Lock()
		n.resolved = addr
		n.Unlock()
		return addr, nil, nil
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
		return "", nil, errorx.Decorate(err, "failed to lookup %s", host)
	}

	for _, addr := range addrs {
		// TODO: support ipv6, support multiple ipv4
		if addr.IP.To4() == nil {
			continue
		}
		ip = addr.IP
		break
	}

	if ip == nil {
		// couldn't find any suitable IP address
		return "", nil, fmt.Errorf("couldn't find any suitable IP address for host %s", host)
	}

	n.Lock()
	defer n.Unlock()
	n.resolved = net.JoinHostPort(ip.String(), port)
	n.resolvedConfig = &tls.Config{ServerName: host}
	return n.resolved, n.resolvedConfig, nil
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
