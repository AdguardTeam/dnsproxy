package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
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

// RequestHandler is an optional custom handler for DNS requests.  It's used
// instead of [Proxy.Resolve] if set.  The resulting error doesn't affect the
// request processing.  The custom handler is responsible for calling
// [ResponseHandler], if it doesn't call [Proxy.Resolve].
//
// TODO(e.burkov):  Use the same interface-based approach as
// [BeforeRequestHandler].
type RequestHandler func(p *Proxy, dctx *DNSContext) (err error)

// ResponseHandler is an optional custom handler called when DNS query has been
// processed.  When called from [Proxy.Resolve], dctx will contain the response
// message if the upstream or cache succeeded.  err is only not nil if the
// upstream failed to respond.
//
// TODO(e.burkov):  Use the same interface-based approach as
// [BeforeRequestHandler].
type ResponseHandler func(dctx *DNSContext, err error)

// Config contains all the fields necessary for proxy configuration
//
// TODO(a.garipov): Consider extracting conf blocks for better fieldalignment.
type Config struct {
	// TrustedProxies is the trusted list of CIDR networks to detect proxy
	// servers addresses from where the DoH requests should be handled.  The
	// value of nil makes Proxy not trust any address.
	TrustedProxies netutil.SubnetSet

	// PrivateSubnets is the set of private networks.  Client having an address
	// within this set is able to resolve PTR requests for addresses within this
	// set.
	PrivateSubnets netutil.SubnetSet

	// MessageConstructor used to build DNS messages.  If nil, the default
	// constructor will be used.
	MessageConstructor MessageConstructor

	// BeforeRequestHandler is an optional custom handler called before each DNS
	// request is started processing, see [BeforeRequestHandler].  The default
	// no-op implementation is used, if it's nil.
	BeforeRequestHandler BeforeRequestHandler

	// RequestHandler is an optional custom handler for DNS requests.  It's used
	// instead of [Proxy.Resolve] if set.  See [RequestHandler].
	RequestHandler RequestHandler

	// ResponseHandler is an optional custom handler called when DNS query has
	// been processed.  See [ResponseHandler].
	ResponseHandler ResponseHandler

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

	// Userinfo is the sole permitted userinfo for the DoH basic authentication.
	// If Userinfo is set, all DoH queries are required to have this basic
	// authentication information.
	Userinfo *url.Userinfo

	// TLSConfig is the TLS configuration.  Required for DNS-over-TLS,
	// DNS-over-HTTP, and DNS-over-QUIC servers.
	TLSConfig *tls.Config

	// DNSCryptResolverCert is the DNSCrypt resolver certificate.  Required for
	// DNSCrypt server.
	DNSCryptResolverCert *dnscrypt.Cert

	// DNSCryptProviderName is the DNSCrypt provider name.  Required for
	// DNSCrypt server.
	DNSCryptProviderName string

	// HTTPSServerName sets the Server header of the HTTPS server responses, if
	// not empty.
	HTTPSServerName string

	// UDPListenAddr is the set of UDP addresses to listen for plain
	// DNS-over-UDP requests.
	UDPListenAddr []*net.UDPAddr

	// TCPListenAddr is the set of TCP addresses to listen for plain
	// DNS-over-TCP requests.
	TCPListenAddr []*net.TCPAddr

	// HTTPSListenAddr is the set of TCP addresses to listen for DNS-over-HTTPS
	// requests.
	HTTPSListenAddr []*net.TCPAddr

	// TLSListenAddr is the set of TCP addresses to listen for DNS-over-TLS
	// requests.
	TLSListenAddr []*net.TCPAddr

	// QUICListenAddr is the set of UDP addresses to listen for DNS-over-QUIC
	// requests.
	QUICListenAddr []*net.UDPAddr

	// DNSCryptUDPListenAddr is the set of UDP addresses to listen for DNSCrypt
	// requests.
	DNSCryptUDPListenAddr []*net.UDPAddr

	// DNSCryptTCPListenAddr is the set of TCP addresses to listen for DNSCrypt
	// requests.
	DNSCryptTCPListenAddr []*net.TCPAddr

	// BogusNXDomain is the set of networks used to transform responses into
	// NXDOMAIN ones if they contain at least a single IP address within these
	// networks.  It's similar to dnsmasq's "bogus-nxdomain".
	BogusNXDomain []netip.Prefix

	// DNS64Prefs is the set of NAT64 prefixes used for DNS64 handling.  nil
	// value disables the feature.  An empty value will be interpreted as the
	// default Well-Known Prefix.
	DNS64Prefs []netip.Prefix

	// RatelimitWhitelist is a list of IP addresses excluded from rate limiting.
	RatelimitWhitelist []netip.Addr

	// EDNSAddr is the ECS IP used in request.
	EDNSAddr net.IP

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

	// CacheSizeBytes is the maximum cache size in bytes.
	CacheSizeBytes int

	// CacheMinTTL is the minimum TTL for cached DNS responses in seconds.
	CacheMinTTL uint32

	// CacheMaxTTL is the maximum TTL for cached DNS responses in seconds.
	CacheMaxTTL uint32

	// MaxGoroutines is the maximum number of goroutines processing DNS
	// requests.  Important for mobile users.
	//
	// TODO(a.garipov): Rename this to something like “MaxDNSRequestGoroutines”
	// in a later major version, as it doesn't actually limit all goroutines.
	MaxGoroutines uint

	// The size of the read buffer on the underlying socket.  Larger read
	// buffers can handle larger bursts of requests before packets get dropped.
	UDPBufferSize int

	// UpstreamMode determines the logic through which upstreams will be used.
	UpstreamMode UpstreamModeType

	// FastestPingTimeout is the timeout for waiting the first successful
	// dialing when the UpstreamMode is set to UModeFastestAddr.  Non-positive
	// value will be replaced with the default one.
	FastestPingTimeout time.Duration

	// RefuseAny makes proxy refuse the requests of type ANY.
	RefuseAny bool

	// HTTP3 enables HTTP/3 support for HTTPS server.
	HTTP3 bool

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

	// CacheEnabled defines if the response cache should be used.
	CacheEnabled bool

	// CacheOptimistic defines if the optimistic cache mechanism should be used.
	CacheOptimistic bool

	// UseDNS64 enables DNS64 handling.  If true, proxy will translate IPv4
	// answers into IPv6 answers using first of DNS64Prefs.  Note also that PTR
	// requests for addresses within the specified networks are considered
	// private and will be forwarded as PrivateRDNSUpstreamConfig specifies.
	// Those will be responded with NXDOMAIN if UsePrivateRDNS is false.
	UseDNS64 bool

	// UsePrivateRDNS defines if the PTR requests for private IP addresses
	// should be resolved via PrivateRDNSUpstreamConfig.  Note that it requires
	// a valid PrivateRDNSUpstreamConfig with at least a single general upstream
	// server.
	UsePrivateRDNS bool

	// PreferIPv6 tells the proxy to prefer IPv6 addresses when bootstrapping
	// upstreams that use hostnames.
	PreferIPv6 bool
}

// validateConfig verifies that the supplied configuration is valid and returns
// an error if it's not.
func (p *Proxy) validateConfig() (err error) {
	err = p.UpstreamConfig.validate()
	if err != nil {
		return fmt.Errorf("validating general upstreams: %w", err)
	}

	err = ValidatePrivateConfig(p.PrivateRDNSUpstreamConfig, p.privateNets)
	if err != nil {
		if p.UsePrivateRDNS || errors.Is(err, upstream.ErrNoUpstreams) {
			return fmt.Errorf("validating private RDNS upstreams: %w", err)
		}
	}

	// Allow [Proxy.Fallbacks] to be nil, but not empty.  nil means not to use
	// fallbacks at all.
	err = p.Fallbacks.validate()
	if errors.Is(err, upstream.ErrNoUpstreams) {
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
		log.Info("dnsproxy: server will refuse requests of type ANY")
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
