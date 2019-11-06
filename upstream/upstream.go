// Package upstream implements DNS clients for all known DNS encryption protocols
package upstream

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ameshkov/dnsstamps"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

// Upstream is an interface for a DNS resolver
type Upstream interface {
	Exchange(m *dns.Msg) (*dns.Msg, error)
	Address() string
}

// Options for AddressToUpstream func
type Options struct {
	// Bootstrap is a list of plain DNS servers to be used to resolve DOH/DOT hostnames (if any)
	Bootstrap []string

	// Timeout is the default upstream timeout. Also, it is used as a timeout for bootstrap DNS requests.
	// timeout=0 means infinite timeout.
	Timeout time.Duration

	// ServerIP allows specifying the resolver's IP address. In the case if it's specified,
	// bootstrap DNS servers won't be used at all.
	ServerIP net.IP
}

// AddressToUpstream converts the specified address to an Upstream instance
// * 8.8.8.8:53 -- plain DNS
// * tcp://8.8.8.8:53 -- plain DNS over TCP
// * tls://1.1.1.1 -- DNS-over-TLS
// * https://dns.adguard.com/dns-query -- DNS-over-HTTPS
// * sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
func AddressToUpstream(address string, opts Options) (Upstream, error) {
	if strings.Contains(address, "://") {
		upstreamURL, err := url.Parse(address)
		if err != nil {
			return nil, errorx.Decorate(err, "failed to parse %s", address)
		}
		return urlToUpstream(upstreamURL, opts)
	}

	// we don't have scheme in the url, so it's just a plain DNS host:port
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		// doesn't have port, default to 53
		address = net.JoinHostPort(address, "53")
	}
	return &plainDNS{address: address, timeout: opts.Timeout}, nil
}

// urlToBoot creates an instance of the bootstrapper with the specified options
func urlToBoot(resolverURL string, opts Options) (*bootstrapper, error) {
	if opts.ServerIP == nil {
		return toBoot(resolverURL, opts.Bootstrap, opts.Timeout), nil
	}

	return toBootResolved(resolverURL, opts.ServerIP, opts.Timeout)
}

// urlToUpstream converts a URL to an Upstream
func urlToUpstream(upstreamURL *url.URL, opts Options) (Upstream, error) {
	switch upstreamURL.Scheme {
	case "sdns":
		return stampToUpstream(upstreamURL.String(), opts)
	case "dns":
		return &plainDNS{address: getHostWithPort(upstreamURL, "53"), timeout: opts.Timeout}, nil
	case "tcp":
		return &plainDNS{address: getHostWithPort(upstreamURL, "53"), timeout: opts.Timeout, preferTCP: true}, nil
	case "tls":
		resolverURL := getHostWithPort(upstreamURL, "853")
		b, err := urlToBoot(resolverURL, opts)
		if err != nil {
			return nil, errorx.Decorate(err, "couldn't create tls bootstrapper")
		}

		return &dnsOverTLS{boot: b}, nil
	case "https":
		if upstreamURL.Port() == "" {
			upstreamURL.Host += ":443"
		}

		resolverURL := upstreamURL.String()
		b, err := urlToBoot(resolverURL, opts)
		if err != nil {
			return nil, errorx.Decorate(err, "couldn't create tls bootstrapper")
		}

		return &dnsOverHTTPS{boot: b}, nil
	default:
		// assume it's plain DNS
		return &plainDNS{address: getHostWithPort(upstreamURL, "53"), timeout: opts.Timeout}, nil
	}
}

// stampToUpstream converts a DNS stamp to an Upstream
func stampToUpstream(address string, opts Options) (Upstream, error) {
	stamp, err := dnsstamps.NewServerStampFromString(address)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to parse %s", address)
	}

	if stamp.ServerAddrStr != "" {
		host, _, err := net.SplitHostPort(stamp.ServerAddrStr)
		if err != nil {
			host = stamp.ServerAddrStr
		}

		// Parse and add to options
		opts.ServerIP = net.ParseIP(host)
		if opts.ServerIP == nil {
			return nil, fmt.Errorf("invalid server address in the stamp: %s", stamp.ServerAddrStr)
		}
	}

	switch stamp.Proto {
	case dnsstamps.StampProtoTypePlain:
		return &plainDNS{address: stamp.ServerAddrStr, timeout: opts.Timeout}, nil
	case dnsstamps.StampProtoTypeDNSCrypt:
		return &dnsCrypt{boot: toBoot(address, opts.Bootstrap, opts.Timeout)}, nil
	case dnsstamps.StampProtoTypeDoH:
		return AddressToUpstream(fmt.Sprintf("https://%s%s", stamp.ProviderName, stamp.Path), opts)
	case dnsstamps.StampProtoTypeTLS:
		return AddressToUpstream(fmt.Sprintf("tls://%s", stamp.ProviderName), opts)
	}

	return nil, fmt.Errorf("unsupported protocol %v in %s", stamp.Proto, address)
}

// getHostWithPort is a helper function that appends port if needed
func getHostWithPort(upstreamURL *url.URL, defaultPort string) string {
	if upstreamURL.Port() == "" {
		return upstreamURL.Host + ":" + defaultPort
	}
	return upstreamURL.Host
}
