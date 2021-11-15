// Package upstream implements DNS clients for all known DNS encryption protocols
package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
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
	// Bootstrap is a list of DNS servers to be used to resolve DOH/DOT hostnames (if any)
	// You can use plain DNS, DNSCrypt, or DOT/DOH with IP addresses (not hostnames)
	Bootstrap []string

	// Timeout is the default upstream timeout. Also, it is used as a timeout for bootstrap DNS requests.
	// timeout=0 means infinite timeout.
	Timeout time.Duration

	// List of IP addresses of upstream DNS server
	// Bootstrap DNS servers won't be used at all
	ServerIPAddrs []net.IP

	// InsecureSkipVerify - if true, do not verify the server certificate
	InsecureSkipVerify bool

	// VerifyServerCertificate will be set to crypto/tls Config.VerifyPeerCertificate for DoH, DoQ, DoT
	VerifyServerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyDNSCryptCertificate is callback to which the DNSCrypt server certificate will be passed.
	// is called in dnsCrypt.exchangeDNSCrypt; if error != nil then Upstream.Exchange() will return it
	VerifyDNSCryptCertificate func(cert *dnscrypt.Cert) error

	TLSClientCertificates *tls.Certificate // TLS certificates when DoH/DoT/DoQ Client Authentication is used
}

// Parse "host:port" string and validate port number
func parseHostAndPort(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	} else {
		// validate port
		portN, err := strconv.Atoi(port)
		if err != nil || portN <= 0 || portN > 0xffff {
			return "", "", fmt.Errorf("invalid address: %s", addr)
		}
		port = strconv.Itoa(portN)
	}
	return host, port, nil
}

// AddressToUpstream converts the specified address to an Upstream instance
// * 8.8.8.8:53 -- plain DNS
// * tcp://8.8.8.8:53 -- plain DNS over TCP
// * tls://1.1.1.1 -- DNS-over-TLS
// * https://dns.adguard.com/dns-query -- DNS-over-HTTPS
// * sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
// options -- Upstream customization options, nil means default options.
func AddressToUpstream(address string, options *Options) (Upstream, error) {
	if options == nil {
		options = &Options{}
	}

	if strings.Contains(address, "://") {

		upstreamURL, err := url.Parse(address)
		if err != nil {
			return nil, errorx.Decorate(err, "failed to parse %s", address)
		}
		return urlToUpstream(upstreamURL, options)
	}

	// we don't have scheme in the url, so it's just a plain DNS host:port
	host, port, err := parseHostAndPort(address)
	if err != nil {
		return nil, err
	}
	if port == "" {
		port = "53"
	}

	return &plainDNS{address: net.JoinHostPort(host, port), timeout: options.Timeout}, nil
}

// urlToBoot creates an instance of the bootstrapper with the specified options
// options -- Upstream customization options
func urlToBoot(resolverURL *url.URL, opts *Options) (*bootstrapper, error) {
	if len(opts.ServerIPAddrs) == 0 {
		return newBootstrapper(resolverURL, opts)
	}

	return newBootstrapperResolved(resolverURL, opts)
}

// urlToUpstream converts a URL to an Upstream
// options -- Upstream customization options
func urlToUpstream(upstreamURL *url.URL, opts *Options) (Upstream, error) {
	switch upstreamURL.Scheme {
	case "sdns":
		return stampToUpstream(upstreamURL, opts)

	case "dns":
		return &plainDNS{address: getHostWithPort(upstreamURL, "53"), timeout: opts.Timeout}, nil

	case "tcp":
		return &plainDNS{address: getHostWithPort(upstreamURL, "53"), timeout: opts.Timeout, preferTCP: true}, nil

	case "quic":
		if upstreamURL.Port() == "" {
			// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-10.2.1
			// Early experiments MAY use port 8853. This port is marked in the IANA registry as unassigned.
			// (Note that prior to version -02 of this draft, experiments were directed to use port 784.)
			upstreamURL.Host += ":8853"
		}

		b, err := urlToBoot(upstreamURL, opts)
		if err != nil {
			return nil, errorx.Decorate(err, "couldn't create quic bootstrapper")
		}

		return &dnsOverQUIC{boot: b}, nil

	case "tls":
		if upstreamURL.Port() == "" {
			upstreamURL.Host += ":853"
		}

		b, err := urlToBoot(upstreamURL, opts)
		if err != nil {
			return nil, errorx.Decorate(err, "couldn't create tls bootstrapper")
		}

		return &dnsOverTLS{boot: b}, nil

	case "https":
		if upstreamURL.Port() == "" {
			upstreamURL.Host += ":443"
		}

		b, err := urlToBoot(upstreamURL, opts)
		if err != nil {
			return nil, errorx.Decorate(err, "couldn't create tls bootstrapper")
		}

		return &dnsOverHTTPS{boot: b}, nil

	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s", upstreamURL.Scheme)
	}
}

// stampToUpstream converts a DNS stamp to an Upstream
// options -- Upstream customization options
func stampToUpstream(upsURL *url.URL, opts *Options) (Upstream, error) {
	stamp, err := dnsstamps.NewServerStampFromString(upsURL.String())
	if err != nil {
		return nil, errorx.Decorate(err, "failed to parse %s", upsURL)
	}

	if stamp.ServerAddrStr != "" {
		host, _, err := net.SplitHostPort(stamp.ServerAddrStr)
		if err != nil {
			host = stamp.ServerAddrStr
		}

		// Parse and add to options
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("invalid server address in the stamp: %s", stamp.ServerAddrStr)
		}
		opts.ServerIPAddrs = []net.IP{ip}
	}

	switch stamp.Proto {
	case dnsstamps.StampProtoTypePlain:
		return &plainDNS{address: stamp.ServerAddrStr, timeout: opts.Timeout}, nil
	case dnsstamps.StampProtoTypeDNSCrypt:
		b, err := newBootstrapper(upsURL, opts)
		if err != nil {
			return nil, fmt.Errorf("bootstrap server parse: %s", err)
		}
		return &dnsCrypt{boot: b}, nil
	case dnsstamps.StampProtoTypeDoH:
		return AddressToUpstream(fmt.Sprintf("https://%s%s", stamp.ProviderName, stamp.Path), opts)
	case dnsstamps.StampProtoTypeDoQ:
		return AddressToUpstream(fmt.Sprintf("quic://%s%s", stamp.ProviderName, stamp.Path), opts)
	case dnsstamps.StampProtoTypeTLS:
		return AddressToUpstream(fmt.Sprintf("tls://%s", stamp.ProviderName), opts)
	}

	return nil, fmt.Errorf("unsupported protocol %v in %s", stamp.Proto, upsURL)
}

// getHostWithPort is a helper function that appends port if needed
func getHostWithPort(upstreamURL *url.URL, defaultPort string) string {
	if upstreamURL.Port() == "" {
		return upstreamURL.Host + ":" + defaultPort
	}
	return upstreamURL.Host
}

// Write to log DNS request information that we are going to send
func logBegin(upstreamAddress string, req *dns.Msg) {
	qtype := ""
	target := ""
	if len(req.Question) != 0 {
		qtype = dns.TypeToString[req.Question[0].Qtype]
		target = req.Question[0].Name
	}
	log.Debug("%s: sending request %s %s",
		upstreamAddress, qtype, target)
}

// Write to log about the result of DNS request
func logFinish(upstreamAddress string, err error) {
	status := "ok"
	if err != nil {
		status = err.Error()
	}
	log.Debug("%s: response: %s",
		upstreamAddress, status)
}
