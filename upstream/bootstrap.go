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
	resolvers      []*net.Resolver // resolver to use to resolve hostname, if necessary
	resolved       string        // in form "IP:port"
	timeout        time.Duration // resolution duration (shared with the upstream) (0 == infinite timeout)
	resolvedConfig *tls.Config
	sync.RWMutex
}

func toBoot(address string, bootstrapAddr []string, timeout time.Duration) bootstrapper {
	resolvers := []*net.Resolver{}
	if bootstrapAddr != nil && len(bootstrapAddr) != 0 {
		for idx, adr := range bootstrapAddr {
			_, _, err := net.SplitHostPort(adr)
			if err != nil {
				// Add the default port for bootstrap DNS address if no port is defined
				adr = net.JoinHostPort(adr, "53")
				bootstrapAddr[idx] = adr
			}
		}

		for _, boot := range bootstrapAddr {
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: timeout}
					return d.DialContext(ctx, network, boot)
				},
			}
			resolvers = append(resolvers, resolver)
		}
	} else {
		var resolver *net.Resolver
		resolvers = append(resolvers, resolver)
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

	resolver := n.resolvers // no need to check for nil resolver -- documented that nil is default resolver
	ctx, cancel := context.WithTimeout(context.TODO(), n.timeout)
	defer cancel() // important to avoid a resource leak

	addrs, err := parallelLookup(ctx, resolver, host)
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

func parallelLookup(ctx context.Context, resolvers []*net.Resolver, host string) ([]net.IPAddr, error) {
	size := len(resolvers)

	resp := make(chan []net.IPAddr, size)
	quit := make(chan error, size)

	resolver := resolvers // no need to check for nil resolver -- documented that nil is default resolver
	for _, res := range resolver {
		go lookupIp(ctx, res, host, resp, quit)
	}

	var count int
	for {
		select {
		case addrs := <- resp:
			return addrs, nil
		case err := <- quit:
			log.Printf("failed to lookup for %s: %g", host, err)
			count++
			if count == size {
				return nil, err
			}
		}
	}
}

// TODO change it like ExchangeParallel and use new structure
func lookupIp(ctx context.Context, resolver *net.Resolver, host string, ip chan []net.IPAddr, quit chan error) {
	address, err := resolver.LookupIPAddr(ctx, host)
	if address != nil {
		ip <- address
	} else {
		quit <- err
	}
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
