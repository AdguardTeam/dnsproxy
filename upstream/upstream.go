// Package upstream implements DNS clients for all known DNS encryption protocols
package upstream

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// Upstream is an interface for a DNS resolver
type Upstream interface {
	Exchange(m *dns.Msg) (*dns.Msg, error)
	Address() string
}

// Options for AddressToUpstream func
type Options struct {
	// Bootstrap is a list of DNS servers to be used to resolve
	// DNS-over-HTTPS/DNS-over-TLS hostnames.  Plain DNS, DNSCrypt, or
	// DNS-over-HTTPS/DNS-over-TLS with IP addresses (not hostnames) could be
	// used.
	Bootstrap []string

	// Timeout is the default upstream timeout.  It's also used as a timeout for
	// bootstrap DNS requests.  Zero value disables the timeout.
	Timeout time.Duration

	// List of IP addresses of the upstream DNS server.  If not empty, bootstrap
	// DNS servers won't be used at all.
	ServerIPAddrs []net.IP

	// InsecureSkipVerify disables verifying the server's certificate.
	InsecureSkipVerify bool

	// VerifyServerCertificate used to be set to crypto/tls
	// Config.VerifyPeerCertificate for DNS-over-HTTPS, DNS-over-QUIC,
	// DNS-over-TLS.
	VerifyServerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyDNSCryptCertificate is the callback the DNSCrypt server certificate
	// will be passed to.  It's called in dnsCrypt.exchangeDNSCrypt.
	// Upstream.Exchange method returns any error caused by it.
	VerifyDNSCryptCertificate func(cert *dnscrypt.Cert) error
}

const (
	// defaultPortPlain is the default port for plain DNS.
	defaultPortPlain = 53

	// defaultPortDoH is the default port for DNS-over-HTTPS.
	defaultPortDoH = 443

	// defaultPortDoT is the default port for DNS-over-TLS.
	defaultPortDoT = 853

	// defaultPortDoQ is the default port for DNS-over-QUIC.  Prior to version
	// -10 of the draft experiments were directed to use ports 8853, 784.
	//
	// See https://www.rfc-editor.org/rfc/rfc9250.html#name-port-selection.
	defaultPortDoQ = 853
)

// AddressToUpstream converts addr to an Upstream instance:
//
//	8.8.8.8:53 or udp://dns.adguard.com for plain DNS;
//	tcp://8.8.8.8:53 for plain DNS-over-TCP;
//	tls://1.1.1.1 for DNS-over-TLS;
//	https://dns.adguard.com/dns-query for DNS-over-HTTPS;
//	sdns://... for DNS stamp, see https://dnscrypt.info/stamps-specifications.
//
// opts are applied to the u.  nil is a valid value for opts.
func AddressToUpstream(addr string, opts *Options) (u Upstream, err error) {
	if opts == nil {
		opts = &Options{}
	}

	if strings.Contains(addr, "://") {
		var uu *url.URL
		uu, err = url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", addr, err)
		}

		return urlToUpstream(uu, opts)
	}

	var host, port string
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return &plainDNS{address: net.JoinHostPort(addr, "53"), timeout: opts.Timeout}, nil
	}

	// Validate port.
	portN, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", addr)
	}

	return &plainDNS{address: netutil.JoinHostPort(host, int(portN)), timeout: opts.Timeout}, nil
}

// urlToBoot creates a bootstrapper with the specified options.
func urlToBoot(u *url.URL, opts *Options) (b *bootstrapper, err error) {
	if len(opts.ServerIPAddrs) == 0 {
		return newBootstrapper(u, opts)
	}

	return newBootstrapperResolved(u, opts)
}

// urlToUpstream converts uu to an Upstream using opts.
func urlToUpstream(uu *url.URL, opts *Options) (u Upstream, err error) {
	switch sch := uu.Scheme; sch {
	case "sdns":
		return stampToUpstream(uu, opts)
	case "udp", "tcp":
		return newPlain(uu, opts.Timeout, sch == "tcp"), nil
	case "quic":
		return newDoQ(uu, opts)
	case "tls":
		return newDoT(uu, opts)
	case "https":
		return newDoH(uu, opts)
	default:
		return nil, fmt.Errorf("unsupported url scheme: %s", sch)
	}
}

// stampToUpstream converts a DNS stamp to an Upstream
// options -- Upstream customization options
func stampToUpstream(upsURL *url.URL, opts *Options) (Upstream, error) {
	stamp, err := dnsstamps.NewServerStampFromString(upsURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", upsURL, err)
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

// addPort appends port to u if it's absent.
func addPort(u *url.URL, port int) {
	if u != nil && u.Port() == "" {
		u.Host = netutil.JoinHostPort(strings.Trim(u.Host, "[]"), port)
	}
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
