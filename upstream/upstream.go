// Package upstream implements DNS clients for all known DNS encryption
// protocols.
package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

// Upstream is an interface for a DNS resolver.
type Upstream interface {
	// Exchange sends the DNS query req to this upstream and returns the
	// response that has been received or an error if something went wrong.
	Exchange(req *dns.Msg) (resp *dns.Msg, err error)

	// Address returns the address of the upstream DNS resolver.
	Address() (addr string)

	// Closer used to close the upstreams properly.  Exchange shouldn't be
	// called after calling Close.
	io.Closer
}

// QUICTraceFunc is a function that returns a [logging.ConnectionTracer]
// specific for a given role and connection ID.
type QUICTraceFunc func(
	ctx context.Context,
	role logging.Perspective,
	connID quic.ConnectionID,
) (tracer *logging.ConnectionTracer)

// Options for AddressToUpstream func.  With these options we can configure the
// upstream properties.
type Options struct {
	// VerifyServerCertificate is used to set the VerifyPeerCertificate property
	// of the *tls.Config for DNS-over-HTTPS, DNS-over-QUIC, and DNS-over-TLS.
	VerifyServerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection is used to set the VerifyConnection property
	// of the *tls.Config for DNS-over-HTTPS, DNS-over-QUIC, and DNS-over-TLS.
	VerifyConnection func(state tls.ConnectionState) error

	// VerifyDNSCryptCertificate is the callback the DNSCrypt server certificate
	// will be passed to.  It's called in dnsCrypt.exchangeDNSCrypt.
	// Upstream.Exchange method returns any error caused by it.
	VerifyDNSCryptCertificate func(cert *dnscrypt.Cert) error

	// QUICTracer is an optional callback that allows tracing every QUIC
	// connection and logging every packet that goes through.
	QUICTracer QUICTraceFunc

	// RootCAs is the CertPool that must be used by all upstreams.  Redefining
	// RootCAs makes sense on iOS to overcome the 15MB memory limit of the
	// NEPacketTunnelProvider.
	RootCAs *x509.CertPool

	// CipherSuites is a custom list of TLSv1.2 ciphers.
	CipherSuites []uint16

	// Bootstrap is used to resolve upstreams' hostnames.  If nil, the
	// [net.DefaultResolver] will be used.
	Bootstrap Resolver

	// HTTPVersions is a list of HTTP versions that should be supported by the
	// DNS-over-HTTPS client.  If not set, HTTP/1.1 and HTTP/2 will be used.
	HTTPVersions []HTTPVersion

	// Timeout is the default upstream timeout.  It's also used as a timeout for
	// bootstrap DNS requests.  Zero value disables the timeout.
	Timeout time.Duration

	// InsecureSkipVerify disables verifying the server's certificate.
	InsecureSkipVerify bool

	// PreferIPv6 tells the bootstrapper to prefer IPv6 addresses for an
	// upstream.
	PreferIPv6 bool
}

// Clone copies o to a new struct.  Note, that this is not a deep clone.
func (o *Options) Clone() (clone *Options) {
	return &Options{
		Bootstrap:                 o.Bootstrap,
		Timeout:                   o.Timeout,
		HTTPVersions:              o.HTTPVersions,
		VerifyServerCertificate:   o.VerifyServerCertificate,
		VerifyConnection:          o.VerifyConnection,
		VerifyDNSCryptCertificate: o.VerifyDNSCryptCertificate,
		InsecureSkipVerify:        o.InsecureSkipVerify,
		PreferIPv6:                o.PreferIPv6,
		QUICTracer:                o.QUICTracer,
		RootCAs:                   o.RootCAs,
		CipherSuites:              o.CipherSuites,
	}
}

// HTTPVersion is an enumeration of the HTTP versions that we support.  Values
// that we use in this enumeration are also used as ALPN values.
type HTTPVersion string

const (
	// HTTPVersion11 is HTTP/1.1.
	HTTPVersion11 HTTPVersion = "http/1.1"
	// HTTPVersion2 is HTTP/2.
	HTTPVersion2 HTTPVersion = "h2"
	// HTTPVersion3 is HTTP/3.
	HTTPVersion3 HTTPVersion = "h3"
)

// DefaultHTTPVersions is the list of HTTPVersion that we use by default in
// the DNS-over-HTTPS client.
var DefaultHTTPVersions = []HTTPVersion{HTTPVersion11, HTTPVersion2}

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

// AddressToUpstream converts addr to an Upstream using the specified options.
// addr can be either a URL, or a plain address, either a domain name or an IP.
//
//   - udp://5.3.5.3:53 or 5.3.5.3:53 for plain DNS using IP address;
//   - udp://name.server:53 or name.server:53 for plain DNS using domain name;
//   - tcp://5.3.5.3:53 for plain DNS-over-TCP using IP address;
//   - tcp://name.server:53 for plain DNS-over-TCP using domain name;
//   - tls://5.3.5.3:853 for DNS-over-TLS using IP address;
//   - tls://name.server:853 for DNS-over-TLS using domain name;
//   - https://5.3.5.3:443/dns-query for DNS-over-HTTPS using IP address;
//   - https://name.server:443/dns-query for DNS-over-HTTPS using domain name;
//   - quic://5.3.5.3:853 for DNS-over-QUIC using IP address;
//   - quic://name.server:853 for DNS-over-QUIC using domain name;
//   - h3://dns.google for DNS-over-HTTPS that only works with HTTP/3;
//   - sdns://... for DNS stamp, see https://dnscrypt.info/stamps-specifications.
//
// If addr doesn't have port specified, the default port of the appropriate
// protocol will be used.
//
// opts are applied to the u and shouldn't be modified afterwards, nil value is
// valid.
//
// TODO(e.burkov):  Clone opts?
func AddressToUpstream(addr string, opts *Options) (u Upstream, err error) {
	if opts == nil {
		opts = &Options{}
	}

	var uu *url.URL
	if strings.Contains(addr, "://") {
		// Parse as URL.
		uu, err = url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", addr, err)
		}
	} else {
		// Probably, plain UDP upstream defined by address or address:port.
		_, port, splitErr := net.SplitHostPort(addr)
		if splitErr == nil {
			// Validate port.
			_, err = strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid address %s: %w", addr, err)
			}
		}

		uu = &url.URL{
			Scheme: "udp",
			Host:   addr,
		}
	}

	return urlToUpstream(uu, opts)
}

// urlToUpstream converts uu to an Upstream using opts.
func urlToUpstream(uu *url.URL, opts *Options) (u Upstream, err error) {
	switch sch := uu.Scheme; sch {
	case "sdns":
		return parseStamp(uu, opts)
	case "udp", "tcp":
		return newPlain(uu, opts)
	case "quic":
		return newDoQ(uu, opts)
	case "tls":
		return newDoT(uu, opts)
	case "h3", "https":
		return newDoH(uu, opts)
	default:
		return nil, fmt.Errorf("unsupported url scheme: %s", sch)
	}
}

// parseStamp converts a DNS stamp to an Upstream.
func parseStamp(upsURL *url.URL, opts *Options) (u Upstream, err error) {
	stamp, err := dnsstamps.NewServerStampFromString(upsURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", upsURL, err)
	}

	// TODO(e.burkov):  Port?
	if stamp.ServerAddrStr != "" {
		host, _, sErr := netutil.SplitHostPort(stamp.ServerAddrStr)
		if sErr != nil {
			host = stamp.ServerAddrStr
		}

		var ip netip.Addr
		ip, err = netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("invalid server stamp address %s", stamp.ServerAddrStr)
		}

		opts.Bootstrap = StaticResolver{ip}
	}

	switch stamp.Proto {
	case dnsstamps.StampProtoTypePlain:
		return newPlain(&url.URL{Scheme: "udp", Host: stamp.ServerAddrStr}, opts)
	case dnsstamps.StampProtoTypeDNSCrypt:
		return newDNSCrypt(upsURL, opts), nil
	case dnsstamps.StampProtoTypeDoH:
		return newDoH(&url.URL{Scheme: "https", Host: stamp.ProviderName, Path: stamp.Path}, opts)
	case dnsstamps.StampProtoTypeDoQ:
		return newDoQ(&url.URL{Scheme: "quic", Host: stamp.ProviderName, Path: stamp.Path}, opts)
	case dnsstamps.StampProtoTypeTLS:
		return newDoT(&url.URL{Scheme: "tls", Host: stamp.ProviderName}, opts)
	default:
		return nil, fmt.Errorf("unsupported stamp protocol %s", &stamp.Proto)
	}
}

// addPort appends port to u if it's absent.
func addPort(u *url.URL, port uint16) {
	if u != nil {
		_, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			u.Host = netutil.JoinHostPort(u.Host, port)

			return
		}
	}
}

// logBegin logs the start of DNS request resolution.  It should be called right
// before dialing the connection to the upstream.  n is the [network] that will
// be used to send the request.
func logBegin(upsAddr string, n network, req *dns.Msg) {
	qtype := ""
	target := ""
	if len(req.Question) != 0 {
		qtype = dns.Type(req.Question[0].Qtype).String()
		target = req.Question[0].Name
	}

	log.Debug("dnsproxy: %s: sending request over %s: %s %s", upsAddr, n, qtype, target)
}

// Write to log about the result of DNS request
func logFinish(upsAddr string, n network, err error) {
	status := "ok"
	if err != nil {
		status = err.Error()
	}

	log.Debug("dnsproxy: %s: response received over %s: %q", upsAddr, n, status)
}

// DialerInitializer returns the handler that it creates.  All the subsequent
// calls to it, except the first one, will return the same handler so that
// resolving will be performed only once.
type DialerInitializer func() (handler bootstrap.DialHandler, err error)

// newDialerInitializer creates an initializer of the dialer that will dial the
// addresses resolved from u using opts.
func newDialerInitializer(u *url.URL, opts *Options) (di DialerInitializer) {
	if _, err := netip.ParseAddrPort(u.Host); err == nil {
		// Don't resolve the address of the server since it's already an IP.
		handler := bootstrap.NewDialContext(opts.Timeout, u.Host)

		return func() (bootstrap.DialHandler, error) { return handler, nil }
	}

	boot := opts.Bootstrap
	if boot == nil {
		// Use the default resolver for bootstrapping.
		boot = net.DefaultResolver
	}

	var dialHandler atomic.Pointer[bootstrap.DialHandler]

	return func() (h bootstrap.DialHandler, err error) {
		// Check if the dial handler has already been created.
		if hPtr := dialHandler.Load(); hPtr != nil {
			return *hPtr, nil
		}

		// TODO(e.burkov):  It may appear that several exchanges will try to
		// resolve the upstream hostname at the same time.  Currently, the last
		// successful value will be stored in dialHandler, but ideally we should
		// resolve only once.
		h, err = bootstrap.ResolveDialContext(u, opts.Timeout, boot, opts.PreferIPv6)
		if err != nil {
			return nil, fmt.Errorf("creating dial handler: %w", err)
		}

		if !dialHandler.CompareAndSwap(nil, &h) {
			return *dialHandler.Load(), nil
		}

		return h, nil
	}
}
