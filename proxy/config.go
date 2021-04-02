package proxy

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
)

// UpstreamModeType - upstream mode
type UpstreamModeType int

const (
	// UModeLoadBalance - LoadBalance
	UModeLoadBalance UpstreamModeType = iota
	// UModeParallel - parallel queries to all configured upstream servers are enabled
	UModeParallel
	// UModeFastestAddr - use Fastest Address algorithm
	UModeFastestAddr
)

// BeforeRequestHandler is an optional custom handler called before DNS requests
// If it returns false, the request won't be processed at all
type BeforeRequestHandler func(p *Proxy, d *DNSContext) (bool, error)

// RequestHandler is an optional custom handler for DNS requests
// It is called instead of the default method (Proxy.Resolve())
// See handler_test.go for examples
type RequestHandler func(p *Proxy, d *DNSContext) error

// ResponseHandler is a callback method that is called when DNS query has been processed
// d -- current DNS query context (contains response if it was successful)
// err -- error (if any)
type ResponseHandler func(d *DNSContext, err error)

// Config contains all the fields necessary for proxy configuration
type Config struct {
	// Listeners
	// --

	UDPListenAddr         []*net.UDPAddr // if nil, then it does not listen for UDP
	TCPListenAddr         []*net.TCPAddr // if nil, then it does not listen for TCP
	HTTPSListenAddr       []*net.TCPAddr // if nil, then it does not listen for HTTPS (DoH)
	TLSListenAddr         []*net.TCPAddr // if nil, then it does not listen for TLS (DoT)
	QUICListenAddr        []*net.UDPAddr // if nil, then it does not listen for QUIC (DoQ)
	DNSCryptUDPListenAddr []*net.UDPAddr // if nil, then it does not listen for DNSCrypt
	DNSCryptTCPListenAddr []*net.TCPAddr // if nil, then it does not listen for DNSCrypt

	// Encryption configuration
	// --

	TLSConfig            *tls.Config    // necessary for TLS, HTTPS, QUIC
	DNSCryptProviderName string         // DNSCrypt provider name
	DNSCryptResolverCert *dnscrypt.Cert // DNSCrypt resolver certificate

	// Rate-limiting and anti-DNS amplification measures
	// --

	Ratelimit          int      // max number of requests per second from a given IP (0 to disable)
	RatelimitWhitelist []string // a list of whitelisted client IP addresses
	RefuseAny          bool     // if true, refuse ANY requests

	// Upstream DNS servers and their settings
	// --

	UpstreamConfig *UpstreamConfig     // Upstream DNS servers configuration
	Fallbacks      []upstream.Upstream // list of fallback resolvers (which will be used if regular upstream failed to answer)
	UpstreamMode   UpstreamModeType    // How to request the upstream servers

	// BogusNXDomain - transforms responses that contain at least one of the given IP addresses into NXDOMAIN
	// Similar to dnsmasq's "bogus-nxdomain"
	BogusNXDomain []net.IP

	// Enable EDNS Client Subnet option
	// DNS requests to the upstream server will contain an OPT record with Client Subnet option.
	//  If the original request already has this option set, we pass it through as is.
	//  Otherwise, we set it ourselves using the client IP with subnet /24 (for IPv4) and /112 (for IPv6).
	//
	// If the upstream server supports ECS, it sets subnet number in the response.
	// This subnet number along with the client IP and other data is used as a cache key.
	// Next time, if a client from the same subnet requests this host name,
	//  we get the response from cache.
	// If another client from a different subnet requests this host name,
	//  we pass his request to the upstream server.
	//
	// If the upstream server doesn't support ECS (there's no subnet number in response),
	//  this response will be cached for all clients.
	//
	// If client IP is private (i.e. not public), we don't add EDNS record into a request.
	// And so there will be no EDNS record in response either.
	// We store these responses in general cache (without subnet)
	//  so they will never be used for clients with public IP addresses.
	EnableEDNSClientSubnet bool
	EDNSAddr               net.IP // ECS IP used in request

	// Cache settings
	// --

	CacheEnabled    bool   // cache status
	CacheOptimistic bool   // Optimistic cache status
	CacheSizeBytes  int    // Cache size (in bytes). Default: 64k
	CacheMinTTL     uint32 // Minimum TTL for DNS entries (in seconds).
	CacheMaxTTL     uint32 // Maximum TTL for DNS entries (in seconds).

	// Handlers (for the case when dnsproxy is used as a library)
	// --

	BeforeRequestHandler BeforeRequestHandler // callback that is called before each request
	RequestHandler       RequestHandler       // callback that can handle incoming DNS requests
	ResponseHandler      ResponseHandler      // response callback

	// Other settings
	// --

	// MaxGoroutines is the maximum number of goroutines processing DNS
	// requests.  Important for mobile users.
	//
	// TODO(a.garipov): Renamme this to something like
	// “MaxDNSRequestGoroutines” in a later major version, as it doesn't
	// actually limit all goroutines.
	MaxGoroutines int

	// The size of the read buffer on the underlying socket. Larger read buffers can handle
	// larger bursts of requests before packets get dropped.
	UDPBufferSize int
}

// validateConfig verifies that the supplied configuration is valid and returns an error if it's not
func (p *Proxy) validateConfig() error {
	if p.started {
		return errors.New("server has been already started")
	}

	err := p.validateListenAddrs()
	if err != nil {
		return err
	}

	if p.UpstreamConfig == nil {
		return errors.New("no default upstreams specified")
	}

	if len(p.UpstreamConfig.Upstreams) == 0 {
		if len(p.UpstreamConfig.DomainReservedUpstreams) == 0 {
			return errors.New("no upstreams specified")
		}
		return errors.New("no default upstreams specified")
	}

	if p.CacheMinTTL > 0 || p.CacheMaxTTL > 0 {
		log.Info("Cache TTL override is enabled. Min=%d, Max=%d", p.CacheMinTTL, p.CacheMaxTTL)
	}

	if p.Ratelimit > 0 {
		log.Info("Ratelimit is enabled and set to %d rps", p.Ratelimit)
	}

	if p.RefuseAny {
		log.Info("The server is configured to refuse ANY requests")
	}

	if len(p.BogusNXDomain) > 0 {
		log.Info("%d bogus-nxdomain IP specified", len(p.BogusNXDomain))
	}

	return nil
}

// validateListenAddrs -- checks if listen addrs are properly configured
func (p *Proxy) validateListenAddrs() error {
	if !p.hasListenAddrs() {
		return errors.New("no listen address specified")
	}

	if p.TLSListenAddr != nil && p.TLSConfig == nil {
		return errors.New("cannot create a TLS listener without TLS config")
	}

	if p.HTTPSListenAddr != nil && p.TLSConfig == nil {
		return errors.New("cannot create an HTTPS listener without TLS config")
	}

	if p.QUICListenAddr != nil && p.TLSConfig == nil {
		return errors.New("cannot create a QUIC listener without TLS config")
	}

	if (p.DNSCryptTCPListenAddr != nil || p.DNSCryptUDPListenAddr != nil) &&
		(p.DNSCryptResolverCert == nil || p.DNSCryptProviderName == "") {
		return errors.New("cannot create a DNSCrypt listener without DNSCrypt config")
	}

	return nil
}

// hasListenAddrs - is there any addresses to listen to?
func (p *Proxy) hasListenAddrs() bool {
	if p.UDPListenAddr == nil &&
		p.TCPListenAddr == nil &&
		p.TLSListenAddr == nil &&
		p.HTTPSListenAddr == nil &&
		p.QUICListenAddr == nil &&
		p.DNSCryptUDPListenAddr == nil &&
		p.DNSCryptTCPListenAddr == nil {
		return false
	}

	return true
}
