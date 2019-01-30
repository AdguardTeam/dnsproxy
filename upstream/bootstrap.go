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
	resolver       *net.Resolver // resolver to use to resolve hostname, if necessary
	resolved       string        // in form "IP:port"
	timeout        time.Duration // resolution duration (shared with the upstream) (0 == infinite timeout)
	resolvedConfig *tls.Config
	sync.RWMutex
}

func toBoot(address, bootstrapAddr string, timeout time.Duration) bootstrapper {
	var resolver *net.Resolver
	if bootstrapAddr != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, network, bootstrapAddr)
			},
		}
	}

	return bootstrapper{
		address:  address,
		resolver: resolver,
		timeout:  timeout,
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
		n.RUnlock()
		return "", nil, fmt.Errorf("bootstrapper requires port in address %s", n.address)
	}

	// if n.address's host is an IP, just use it right away
	ip := net.ParseIP(host)
	if ip != nil {
		n.RUnlock()
		n.resolved = net.JoinHostPort(host, port)
		return n.resolved, nil, nil
	}

	// Don't lock anymore (we can launch multiple lookup requests at a time)
	// Otherwise, it might mess with the timeout specified for the Upstream
	// See here: https://github.com/AdguardTeam/dnsproxy/issues/15
	n.RUnlock()

	//
	// if it's a hostname
	//

	resolver := n.resolver // no need to check for nil resolver -- documented that nil is default resolver
	ctx, cancel := context.WithTimeout(context.TODO(), n.timeout)
	defer cancel() // important to avoid a resource leak

	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", nil, errorx.Decorate(err, "failed to lookup %s", host)
	}

	n.Lock()
	defer n.Unlock()
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
