package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
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
//
// TODO(a.garipov): Consider extracting conf blocks for better fieldalignment.
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
	HTTP3                bool           // if true, HTTPS server will also support HTTP/3
	DNSCryptProviderName string         // DNSCrypt provider name
	DNSCryptResolverCert *dnscrypt.Cert // DNSCrypt resolver certificate

	// Rate-limiting and anti-DNS amplification measures
	// --
	//
	// TODO(s.chzhen):  Extract ratelimit settings to a separate structure.

	// RatelimitSubnetLenIPv4 is a subnet length for IPv4 addresses used for
	// rate limiting requests.
	RatelimitSubnetLenIPv4 int

	// RatelimitSubnetLenIPv6 is a subnet length for IPv6 addresses used for
	// rate limiting requests.
	RatelimitSubnetLenIPv6 int

	// Ratelimit is a maximum number of requests per second from a given IP (0
	// to disable).
	Ratelimit int

	// RatelimitWhitelist is a list of IP addresses excluded from rate limiting.
	RatelimitWhitelist []netip.Addr

	// RefuseAny makes proxy refuse the requests of type ANY.
	RefuseAny bool

	// TrustedProxies is the list of IP addresses and CIDR networks to
	// detect proxy servers addresses the DoH requests from which should be
	// handled.  The value of nil or an empty slice for this field makes
	// Proxy not trust any address.
	TrustedProxies []string

	// Upstream DNS servers and their settings
	// --

	// UpstreamConfig is a general set of DNS servers to forward requests to.
	UpstreamConfig *UpstreamConfig

	// PrivateRDNSUpstreamConfig is the set of upstream DNS servers for
	// resolving private IP addresses.  All the requests considered private will
	// be resolved via these upstream servers.  Such queries will finish with
	// [upstream.ErrNoUpstream] if it's empty.
	PrivateRDNSUpstreamConfig *UpstreamConfig

	// Fallbacks is a list of fallback resolvers.  Those will be used if the
	// general set fails responding.
	Fallbacks *UpstreamConfig

	// UpstreamMode determines the logic through which upstreams will be used.
	UpstreamMode UpstreamModeType

	// FastestPingTimeout is the timeout for waiting the first successful
	// dialing when the UpstreamMode is set to UModeFastestAddr.  Non-positive
	// value will be replaced with the default one.
	FastestPingTimeout time.Duration

	// BogusNXDomain is the set of networks used to transform responses into
	// NXDOMAIN ones if they contain at least a single IP address within these
	// networks.  It's similar to dnsmasq's "bogus-nxdomain".
	BogusNXDomain []netip.Prefix

	// Enable EDNS Client Subnet option DNS requests to the upstream server will
	// contain an OPT record with Client Subnet option.  If the original request
	// already has this option set, we pass it through as is.  Otherwise, we set
	// it ourselves using the client IP with subnet /24 (for IPv4) and /56 (for
	// IPv6).
	//
	// If the upstream server supports ECS, it sets subnet number in the
	// response.  This subnet number along with the client IP and other data is
	// used as a cache key.  Next time, if a client from the same subnet
	// requests this host name, we get the response from cache.  If another
	// client from a different subnet requests this host name, we pass his
	// request to the upstream server.
	//
	// If the upstream server doesn't support ECS (there's no subnet number in
	// response), this response will be cached for all clients.
	//
	// If client IP is private (i.e. not public), we don't add EDNS record into
	// a request.  And so there will be no EDNS record in response either.  We
	// store these responses in general cache (without subnet) so they will
	// never be used for clients with public IP addresses.
	EnableEDNSClientSubnet bool

	// EDNSAddr is the ECS IP used in request.
	EDNSAddr net.IP

	// Cache settings
	// --

	CacheEnabled   bool   // cache status
	CacheSizeBytes int    // Cache size (in bytes). Default: 64k
	CacheMinTTL    uint32 // Minimum TTL for DNS entries (in seconds).
	CacheMaxTTL    uint32 // Maximum TTL for DNS entries (in seconds).
	// CacheOptimistic defines if the optimistic cache mechanism should be
	// used.
	CacheOptimistic bool

	// Handlers (for the case when dnsproxy is used as a library)
	// --

	BeforeRequestHandler BeforeRequestHandler // callback that is called before each request
	RequestHandler       RequestHandler       // callback that can handle incoming DNS requests
	ResponseHandler      ResponseHandler      // response callback

	// Other settings
	// --

	// HTTPSServerName sets the Server header of the HTTPS server responses, if
	// not empty.
	HTTPSServerName string

	// Userinfo is the sole permitted userinfo for the DoH basic authentication.
	// If Userinfo is set, all DoH queries are required to have this basic
	// authentication information.
	Userinfo *url.Userinfo

	// MaxGoroutines is the maximum number of goroutines processing DNS
	// requests.  Important for mobile users.
	//
	// TODO(a.garipov): Rename this to something like
	// “MaxDNSRequestGoroutines” in a later major version, as it doesn't
	// actually limit all goroutines.
	MaxGoroutines int

	// The size of the read buffer on the underlying socket. Larger read buffers can handle
	// larger bursts of requests before packets get dropped.
	UDPBufferSize int

	// UseDNS64 enables DNS64 handling.  If true, proxy will translate IPv4
	// answers into IPv6 answers using first of DNS64Prefs.  Note also that PTR
	// requests for addresses within the specified networks are considered
	// private and will be forwarded as PrivateRDNSUpstreamConfig specifies.
	UseDNS64 bool

	// DNS64Prefs is the set of NAT64 prefixes used for DNS64 handling.  nil
	// value disables the feature.  An empty value will be interpreted as the
	// default Well-Known Prefix.
	DNS64Prefs []netip.Prefix

	// PreferIPv6 tells the proxy to prefer IPv6 addresses when bootstrapping
	// upstreams that use hostnames.
	PreferIPv6 bool
}

// validateConfig verifies that the supplied configuration is valid and returns
// an error if it's not.
func (p *Proxy) validateConfig() error {
	err := p.validateListenAddrs()
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	err = p.UpstreamConfig.validate()
	if err != nil {
		return fmt.Errorf("validating general upstreams: %w", err)
	}

	// Allow both [Proxy.PrivateRDNSUpstreamConfig] and [Proxy.Fallbacks] to be
	// nil, but not empty.  nil means using the default values for those.

	err = p.PrivateRDNSUpstreamConfig.validate()
	if err != nil && !errors.Is(err, errNoDefaultUpstreams) {
		return fmt.Errorf("validating private RDNS upstreams: %w", err)
	}

	err = p.Fallbacks.validate()
	if err != nil && !errors.Is(err, errNoDefaultUpstreams) {
		return fmt.Errorf("validating fallbacks: %w", err)
	}

	err = p.validateRatelimit()
	if err != nil {
		return fmt.Errorf("validating ratelimit: %w", err)
	}

	p.logConfigInfo()

	return nil
}

// validateRatelimit validates ratelimit configuration and returns an error if
// it's invalid.
func (p *Proxy) validateRatelimit() (err error) {
	if p.Ratelimit == 0 {
		return nil
	}

	err = checkInclusion(p.RatelimitSubnetLenIPv4, 0, netutil.IPv4BitLen)
	if err != nil {
		return fmt.Errorf("ratelimit subnet len ipv4 is invalid: %w", err)
	}

	err = checkInclusion(p.RatelimitSubnetLenIPv6, 0, netutil.IPv6BitLen)
	if err != nil {
		return fmt.Errorf("ratelimit subnet len ipv6 is invalid: %w", err)
	}

	return nil
}

// checkInclusion returns an error if a n is not in the inclusive range between
// minN and maxN.
func checkInclusion(n, minN, maxN int) (err error) {
	switch {
	case n < minN:
		return fmt.Errorf("value %d less than min %d", n, minN)
	case n > maxN:
		return fmt.Errorf("value %d greater than max %d", n, maxN)
	}

	return nil
}

// logConfigInfo logs proxy configuration information.
func (p *Proxy) logConfigInfo() {
	if p.CacheMinTTL > 0 || p.CacheMaxTTL > 0 {
		log.Info("Cache TTL override is enabled. Min=%d, Max=%d", p.CacheMinTTL, p.CacheMaxTTL)
	}

	if p.Ratelimit > 0 {
		log.Info(
			"Ratelimit is enabled and set to %d rps, IPv4 subnet mask len %d, IPv6 subnet mask len %d",
			p.Ratelimit,
			p.RatelimitSubnetLenIPv4,
			p.RatelimitSubnetLenIPv6,
		)
	}

	if p.RefuseAny {
		log.Info("The server is configured to refuse ANY requests")
	}

	if len(p.BogusNXDomain) > 0 {
		log.Info("%d bogus-nxdomain IP specified", len(p.BogusNXDomain))
	}
}

// validateListenAddrs returns an error if the addresses are not configured
// properly.
func (p *Proxy) validateListenAddrs() error {
	if !p.hasListenAddrs() {
		return errors.Error("no listen address specified")
	}

	if p.TLSConfig == nil {
		if p.TLSListenAddr != nil {
			return errors.Error("cannot create tls listener without tls config")
		}

		if p.HTTPSListenAddr != nil {
			return errors.Error("cannot create https listener without tls config")
		}

		if p.QUICListenAddr != nil {
			return errors.Error("cannot create quic listener without tls config")
		}
	}

	if (p.DNSCryptTCPListenAddr != nil || p.DNSCryptUDPListenAddr != nil) &&
		(p.DNSCryptResolverCert == nil || p.DNSCryptProviderName == "") {
		return errors.Error("cannot create dnscrypt listener without dnscrypt config")
	}

	return nil
}

// hasListenAddrs - is there any addresses to listen to?
func (p *Proxy) hasListenAddrs() bool {
	return p.UDPListenAddr != nil ||
		p.TCPListenAddr != nil ||
		p.TLSListenAddr != nil ||
		p.HTTPSListenAddr != nil ||
		p.QUICListenAddr != nil ||
		p.DNSCryptUDPListenAddr != nil ||
		p.DNSCryptTCPListenAddr != nil
}
