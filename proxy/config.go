package proxy

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/ameshkov/dnscrypt/v2"
)

// LogPrefix is a prefix for logging.
const LogPrefix = "dnsproxy"

const (
	// DefaultOptimisticMaxAge is default value for
	// [Config.CacheOptimisticMaxAge].
	DefaultOptimisticMaxAge = 12 * time.Hour

	// DefaultOptimisticAnswerTTL is default value for
	// [Config.CacheOptimisticAnswerTTL].
	DefaultOptimisticAnswerTTL = 30 * time.Second
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

// Config contains all the fields necessary for proxy configuration.
//
// TODO(a.garipov): Consider extracting conf blocks for better fieldalignment.
type Config struct {
	// Logger is used as the base logger for the proxy service.  If nil,
	// [slog.Default] with [LogPrefix] is used.
	Logger *slog.Logger

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

	// PendingRequests is used to mitigate the cache poisoning attacks by
	// tracking identical requests and returning the same response for them,
	// performing a single lookup.  If nil, it will be enabled by default.
	PendingRequests *PendingRequestsConfig

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
	// general set fails responding.  It isn't allowed to be empty, but can be
	// nil, which means not to use fallbacks.
	//
	// TODO(e.burkov):  Add explicit boolean for disabling fallbacks.
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

	// BindRetryConfig configures the listeners binding retrying.  If nil,
	// retries are disabled.
	BindRetryConfig *BindRetryConfig

	// DNSCryptProviderName is the DNSCrypt provider name.  Required for
	// DNSCrypt server.
	DNSCryptProviderName string

	// HTTPSServerName sets the Server header of the HTTPS server responses, if
	// not empty.
	HTTPSServerName string

	// UpstreamMode determines the logic through which upstreams will be used.
	// If not specified the [proxy.UpstreamModeLoadBalance] is used.
	UpstreamMode UpstreamMode

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

	// CacheOptimisticAnswerTTL is the default TTL for expired cached responses.
	// Default value is [DefaultOptimisticAnswerTTL].
	CacheOptimisticAnswerTTL time.Duration

	// CacheOptimisticMaxAge is the maximum time entries remain in the cache
	// when cache is optimistic.  Default value is [DefaultOptimisticMaxAge].
	CacheOptimisticMaxAge time.Duration

	// MaxGoroutines is the maximum number of goroutines processing DNS
	// requests.  Important for mobile users.
	//
	// TODO(a.garipov): Rename this to something like “MaxDNSRequestGoroutines”
	// in a later major version, as it doesn't actually limit all goroutines.
	MaxGoroutines uint

	// The size of the read buffer on the underlying socket.  Larger read
	// buffers can handle larger bursts of requests before packets get dropped.
	UDPBufferSize int

	// FastestPingTimeout is the timeout for waiting the first successful
	// dialing when the UpstreamMode is set to [UpstreamModeFastestAddr].
	// Non-positive value will be replaced with the default one.
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

// PendingRequestsConfig is the configuration for tracking identical requests.
type PendingRequestsConfig struct {
	// Enabled defines if the duplicate requests should be tracked.
	Enabled bool
}

// validateConfig verifies that the supplied configuration is valid and returns
// an error if it's not.
//
// TODO(s.chzhen):  Use [validate.Interface] from golibs.
func (p *Proxy) validateConfig() (err error) {
	err = p.UpstreamConfig.validate()
	if err != nil {
		return fmt.Errorf("general upstreams: %w", err)
	}

	err = ValidatePrivateConfig(p.PrivateRDNSUpstreamConfig, p.privateNets)
	if err != nil {
		if p.UsePrivateRDNS || errors.Is(err, upstream.ErrNoUpstreams) {
			return fmt.Errorf("private rdns upstreams: %w", err)
		}
	}

	err = p.Fallbacks.validate()
	// Allow [Proxy.Fallbacks] to be nil, but not empty.  nil means not to use
	// fallbacks at all.
	if errors.Is(err, upstream.ErrNoUpstreams) {
		return fmt.Errorf("fallbacks: %w", err)
	}

	err = p.validateRatelimit()
	if err != nil {
		return fmt.Errorf("ratelimit: %w", err)
	}

	switch p.UpstreamMode {
	case
		"",
		UpstreamModeFastestAddr,
		UpstreamModeLoadBalance,
		UpstreamModeParallel:
		// Go on.
	default:
		return fmt.Errorf("upstream mode: %w: %q", errors.ErrBadEnumValue, p.UpstreamMode)
	}

	err = p.validateBasicAuth()
	if err != nil {
		return fmt.Errorf("basic auth: %w", err)
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
		p.logger.Info("cache ttl override is enabled", "min", p.CacheMinTTL, "max", p.CacheMaxTTL)
	}

	if p.Ratelimit > 0 {
		p.logger.Info(
			"ratelimit is enabled",
			"rps",
			p.Ratelimit,
			"ipv4_subnet_mask_len",
			p.RatelimitSubnetLenIPv4,
			"ipv6_subnet_mask_len",
			p.RatelimitSubnetLenIPv6,
		)
	}

	if p.RefuseAny {
		p.logger.Info("server will refuse requests of type any")
	}

	if len(p.BogusNXDomain) > 0 {
		p.logger.Info("bogus-nxdomain ip specified", "prefix_len", len(p.BogusNXDomain))
	}

	if p.UpstreamMode != "" {
		p.logger.Info("upstream mode is set", "mode", p.UpstreamMode)
	}
}

// validateListenAddrs returns an error if the addresses are not configured
// properly.
//
// TODO(e.burkov):  Move to configuration validation.
func (p *Proxy) validateListenAddrs() (err error) {
	if !p.hasListenAddrs() {
		return fmt.Errorf("listen addresses: %w", errors.ErrNoValue)
	}

	err = p.validateTLSConfig()
	if err != nil {
		return fmt.Errorf("invalid tls configuration: %w", err)
	}

	if p.DNSCryptResolverCert == nil || p.DNSCryptProviderName == "" {
		if p.DNSCryptTCPListenAddr != nil {
			return errors.Error("cannot create dnscrypt tcp listener without dnscrypt config")
		}

		if p.DNSCryptUDPListenAddr != nil {
			return errors.Error("cannot create dnscrypt udp listener without dnscrypt config")
		}
	}

	return nil
}

// validateTLSConfig returns an error if proxy TLS configuration parameters are
// needed but aren't provided.
func (p *Proxy) validateTLSConfig() (err error) {
	if p.TLSConfig != nil {
		return nil
	}

	if p.TLSListenAddr != nil {
		return errors.Error("tls listener configuration not found")
	}

	if p.HTTPSListenAddr != nil {
		return errors.Error("https listener configuration not found")
	}

	if p.QUICListenAddr != nil {
		return errors.Error("quic listener configuration not found")
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
