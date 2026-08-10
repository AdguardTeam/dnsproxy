// Package proxy implements a DNS proxy that supports all known DNS encryption
// protocols.
package proxy

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/dnsproxy/fastip"
	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/contextutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	defaultTimeout   = 10 * time.Second
	minDNSPacketSize = 12 + 5
)

// Proto is the DNS protocol.
type Proto string

// Proto values.
const (
	// ProtoUDP is the plain DNS-over-UDP protocol.
	ProtoUDP Proto = "udp"
	// ProtoTCP is the plain DNS-over-TCP protocol.
	ProtoTCP Proto = "tcp"
	// ProtoTLS is the DNS-over-TLS (DoT) protocol.
	ProtoTLS Proto = "tls"
	// ProtoHTTPS is the DNS-over-HTTPS (DoH) protocol.
	ProtoHTTPS Proto = "https"
	// ProtoQUIC is the DNS-over-QUIC (DoQ) protocol.
	ProtoQUIC Proto = "quic"
	// ProtoDNSCrypt is the DNSCrypt protocol.
	ProtoDNSCrypt Proto = "dnscrypt"
)

// logKeyProto is the key for the DNS protocol in logs.
const logKeyProto = "proto"

// Proxy combines the proxy server state and configuration.
//
// TODO(a.garipov): Consider extracting conf blocks for better fieldalignment.
type Proxy struct {
	// reqCtx is a constructor for the request contexts.  It is never nil.
	reqCtx contextutil.Constructor

	// privateNets determines if the requested address and the client address
	// are private.
	privateNets netutil.SubnetSet

	// time provides the current time.
	//
	// TODO(e.burkov):  Consider configuring it.
	time timeutil.Clock

	// randSrc provides the source of randomness.
	//
	// TODO(e.burkov):  Consider configuring it.
	randSrc rand.Source

	// messages constructs DNS messages.
	messages MessageConstructor

	// requestHandler handles the DNS request.  It is never nil.
	requestHandler Handler

	// requestsSema limits the number of simultaneous requests.
	//
	// TODO(a.garipov): Currently we have to pass this exact semaphore to the
	// workers, to prevent races on restart.  In the future we will need a
	// better restarting mechanism that completely prevents such invalid states.
	//
	// See also: https://github.com/AdguardTeam/AdGuardHome/issues/2242.
	requestsSema syncutil.Semaphore

	// pendingRequests is a storage for duplicated requests.  It is used to
	// prevent sending the same request to upstreams multiple times.
	pendingRequests pendingRequests

	// trustedProxies is the trusted list of CIDR networks to detect proxy
	// servers addresses from where the DoH requests should be handled.  The
	// value of nil makes Proxy not trust any address.
	trustedProxies netutil.SubnetSet

	// logger is used for logging in the proxy service.  It is never nil.
	logger *slog.Logger

	// bindRetryConfig configures the listeners binding retrying.  If nil,
	// retries are disabled.
	bindRetryConfig *BindRetryConfig

	// recDetector detects recursive requests that may appear when resolving
	// requests for private addresses.
	recDetector *recursionDetector

	// cache is used to cache requests.  It is disabled if nil.
	//
	// TODO(d.kolyshev): Move this cache to [Proxy.UpstreamConfig] field.
	cache *cache

	// fastestAddr finds the fastest IP address for the resolved domain.
	fastestAddr *fastip.FastestAddr

	// upstreamConfig is a general set of DNS servers to forward requests to.
	upstreamConfig *UpstreamConfig

	// bytesPool is a pool of byte slices used to read DNS packets.
	bytesPool *syncutil.Pool[[]byte]

	// shortFlighter is used to resolve the expired cached requests without
	// repetitions.
	shortFlighter *optimisticResolver

	// udpListen are the listened UDP connections.
	udpListen []*net.UDPConn

	// tcpListen are the listened TCP connections.
	tcpListen []net.Listener

	// tlsListen are the listened TCP connections with TLS.
	tlsListen []net.Listener

	// quicListen are the listened QUIC connections.
	quicListen []*quic.EarlyListener

	// quicConns are UDP connections for all listened QUIC connections.  These
	// should be closed on shutdown, since *quic.EarlyListener doesn't close
	// them.
	quicConns []*net.UDPConn

	// httpsListen are the listened HTTPS connections.
	httpsListen []net.Listener

	// quicTransports are transports for all listened QUIC connections.  These
	// should be closed on shutdown, since *quic.EarlyListener doesn't close
	// them.
	quicTransports []*quic.Transport

	// h3Listen are the listened HTTP/3 connections.
	h3Listen []*quic.EarlyListener

	// httpsServer serves queries received over HTTPS.
	httpsServer *http.Server

	// h3Server serves queries received over HTTP/3.
	h3Server *http3.Server

	// ednsAddr is the ECS IP used in request.
	ednsAddr net.IP

	// dns64Prefs is a set of NAT64 prefixes that are used to detect and
	// construct DNS64 responses.  The DNS64 function is disabled if it is
	// empty.
	dns64Prefs netutil.SliceSubnetSet

	// privateRDNSUpstreamConfig is the set of upstream DNS servers for
	// resolving private IP addresses.  All the requests considered private will
	// be resolved via these upstream servers.  Such queries will finish with
	// [upstream.ErrNoUpstream] if it's empty.
	privateRDNSUpstreamConfig *UpstreamConfig

	// rttLock protects upstreamRTTStats.
	rttLock *sync.Mutex

	// upstreamRTTStats maps the upstream address to its round-trip time
	// statistics.  It's holds the statistics for all upstreams to perform a
	// weighted random selection when using the load balancing mode.
	upstreamRTTStats map[string]upstreamRTTStats

	// mu protects the whole Proxy struct.
	mu *sync.RWMutex

	// fallbacks is a list of fallback resolvers.  Those will be used if the
	// general set fails responding.  It isn't allowed to be empty, but can be
	// nil, which means not to use fallbacks.
	//
	// TODO(e.burkov):  Add explicit boolean for disabling fallbacks.
	fallbacks *UpstreamConfig

	// tlsConfig is the TLS configuration.  Required for DNS-over-TLS,
	// DNS-over-HTTP, and DNS-over-QUIC servers.
	tlsConfig *tls.Config

	// dnsCryptResolverCert is the DNSCrypt resolver certificate.  Required for
	// DNSCrypt server.
	dnsCryptResolverCert *dnscrypt.Certificate

	// httpConfig is the configuration for HTTP requests proxying.  Required for
	// DoH server.  If nil, the DoH server is disabled.
	httpConfig *HTTPConfig

	// dnsCryptServers serve DNSCrypt queries.
	dnsCryptServers []*dnscrypt.Server

	// upstreamMode determines the logic through which upstreams will be used.
	// If not specified the [proxy.UpstreamModeLoadBalance] is used.
	upstreamMode UpstreamMode

	// dnsCryptProviderName is the DNSCrypt provider name.  Required for
	// DNSCrypt server.
	dnsCryptProviderName string

	// udpListenAddr is the set of UDP addresses to listen for plain
	// DNS-over-UDP requests.
	udpListenAddr []*net.UDPAddr

	// tcpListenAddr is the set of TCP addresses to listen for plain
	// DNS-over-TCP requests.
	tcpListenAddr []*net.TCPAddr

	// tlsListenAddr is the set of TCP addresses to listen for DNS-over-TLS
	// requests.
	tlsListenAddr []*net.TCPAddr

	// quicListenAddr is the set of UDP addresses to listen for DNS-over-QUIC
	// requests.
	quicListenAddr []*net.UDPAddr

	// dnsCryptUDPListenAddr is the set of UDP addresses to listen for DNSCrypt
	// requests.
	dnsCryptUDPListenAddr []*net.UDPAddr

	// dnsCryptTCPListenAddr is the set of TCP addresses to listen for DNSCrypt
	// requests.
	dnsCryptTCPListenAddr []*net.TCPAddr

	// bogusNXDomain is the set of networks used to transform responses into
	// NXDOMAIN ones if they contain at least a single IP address within these
	// networks.  It's similar to dnsmasq's "bogus-nxdomain".
	bogusNXDomain []netip.Prefix

	// bindRetryIvl is the interval between attempts to bind to an address for
	// listening.
	bindRetryIvl time.Duration

	// counter counts message contexts created with [Proxy.newDNSContext].
	counter atomic.Uint64

	// cacheOptimisticAnswerTTL is the default TTL for expired cached responses.
	// Default value is [DefaultOptimisticAnswerTTL].
	cacheOptimisticAnswerTTL time.Duration

	// cacheOptimisticMaxAge is the maximum time entries remain in the cache
	// when cache is optimistic.  Default value is [DefaultOptimisticMaxAge].
	cacheOptimisticMaxAge time.Duration

	// fastestPingTimeout is the timeout for waiting the first successful
	// dialing when the UpstreamMode is set to [UpstreamModeFastestAddr].
	// Non-positive value will be replaced with the default one.
	fastestPingTimeout time.Duration

	// The size of the read buffer on the underlying socket.  Larger read
	// buffers can handle larger bursts of requests before packets get dropped.
	udpBufferSize int

	// udpOOBSize is the size of the out-of-band data for UDP connections.
	udpOOBSize int

	// cacheSizeBytes is the maximum cache size in bytes.
	cacheSizeBytes int

	// maxGoroutines is the maximum number of goroutines processing DNS
	// requests.  Important for mobile users.
	//
	// TODO(a.garipov): Rename this to something like “MaxDNSRequestGoroutines”
	// in a later major version, as it doesn't actually limit all goroutines.
	maxGoroutines uint

	// bindRetryCount is the number of retries for binding to an address for
	// listening.  Zero means one attempt and no retries.
	bindRetryCount uint

	// cacheMinTTL is the minimum TTL for cached DNS responses in seconds.
	cacheMinTTL uint32

	// cacheMaxTTL is the maximum TTL for cached DNS responses in seconds.
	cacheMaxTTL uint32

	// started indicates if the proxy has been started.
	started bool

	// refuseAny makes proxy refuse the requests of type ANY.
	refuseAny bool

	// dnsSecEnabled specifies if the proxy should set the DO bits in the
	// upstream requests.
	dnsSecEnabled bool

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
	enableEDNSClientSubnet bool

	// cacheEnabled defines if the response cache should be used.
	cacheEnabled bool

	// cacheOptimistic defines if the optimistic cache mechanism should be used.
	cacheOptimistic bool

	// useDNS64 enables DNS64 handling.  If true, proxy will translate IPv4
	// answers into IPv6 answers using first of DNS64Prefs.  Note also that PTR
	// requests for addresses within the specified networks are considered
	// private and will be forwarded as PrivateRDNSUpstreamConfig specifies.
	// Those will be responded with NXDOMAIN if UsePrivateRDNS is false.
	useDNS64 bool

	// usePrivateRDNS defines if the PTR requests for private IP addresses
	// should be resolved via PrivateRDNSUpstreamConfig.  Note that it requires
	// a valid PrivateRDNSUpstreamConfig with at least a single general upstream
	// server.
	usePrivateRDNS bool

	// preferIPv6 tells the proxy to prefer IPv6 addresses when bootstrapping
	// upstreams that use hostnames.
	preferIPv6 bool
}

// New creates a new Proxy with the specified configuration.  c must not be nil.
//
// TODO(e.burkov):  Cover with tests.
//
// TODO(e.burkov):  Add context.
func New(c *Config) (p *Proxy, err error) {
	p = &Proxy{
		preferIPv6:                c.PreferIPv6,
		usePrivateRDNS:            c.UsePrivateRDNS,
		useDNS64:                  c.UseDNS64,
		cacheOptimistic:           c.CacheOptimistic,
		cacheEnabled:              c.CacheEnabled,
		enableEDNSClientSubnet:    c.EnableEDNSClientSubnet,
		dnsSecEnabled:             c.DNSSECEnabled,
		refuseAny:                 c.RefuseAny,
		fastestPingTimeout:        c.FastestPingTimeout,
		udpBufferSize:             c.UDPBufferSize,
		maxGoroutines:             c.MaxGoroutines,
		cacheOptimisticMaxAge:     c.CacheOptimisticMaxAge,
		cacheOptimisticAnswerTTL:  c.CacheOptimisticAnswerTTL,
		cacheMaxTTL:               c.CacheMaxTTL,
		cacheMinTTL:               c.CacheMinTTL,
		cacheSizeBytes:            c.CacheSizeBytes,
		ednsAddr:                  c.EDNSAddr,
		bogusNXDomain:             c.BogusNXDomain,
		dnsCryptTCPListenAddr:     c.DNSCryptTCPListenAddr,
		dnsCryptUDPListenAddr:     c.DNSCryptUDPListenAddr,
		quicListenAddr:            c.QUICListenAddr,
		tlsListenAddr:             c.TLSListenAddr,
		tcpListenAddr:             c.TCPListenAddr,
		udpListenAddr:             c.UDPListenAddr,
		upstreamMode:              c.UpstreamMode,
		dnsCryptProviderName:      c.DNSCryptProviderName,
		dnsCryptResolverCert:      c.DNSCryptResolverCert,
		tlsConfig:                 c.TLSConfig,
		bindRetryConfig:           c.BindRetryConfig,
		httpConfig:                c.HTTPConfig,
		upstreamConfig:            c.UpstreamConfig,
		privateRDNSUpstreamConfig: c.PrivateRDNSUpstreamConfig,
		fallbacks:                 c.Fallbacks,
		trustedProxies:            c.TrustedProxies,
		privateNets: cmp.Or[netutil.SubnetSet](
			c.PrivateSubnets,
			netutil.SubnetSetFunc(netutil.IsLocallyServed),
		),
		reqCtx: cmp.Or[contextutil.Constructor](
			c.RequestContext,
			contextutil.EmptyConstructor{},
		),
		requestHandler:   cmp.Or[Handler](c.RequestHandler, DefaultHandler{}),
		upstreamRTTStats: map[string]upstreamRTTStats{},
		rttLock:          &sync.Mutex{},
		mu:               &sync.RWMutex{},
		// 2 bytes may be used to store packet length (see TCP/TLS).
		bytesPool:  syncutil.NewSlicePool[byte](2 + dns.MaxMsgSize),
		udpOOBSize: proxynetutil.UDPGetOOBSize(),
		time:       timeutil.SystemClock{},
		messages: cmp.Or[MessageConstructor](
			c.MessageConstructor,
			dnsmsg.DefaultMessageConstructor{},
		),
		recDetector:     newRecursionDetector(recursionTTL, cachedRecurrentReqNum),
		pendingRequests: pendingRequestsOrDefault(c.PendingRequests),
		logger:          loggerOrDefault(c.Logger),
	}

	// TODO(e.burkov):  Validate config separately and add the contract to the
	// New function.
	err = p.validateConfig()
	if err != nil {
		return nil, err
	}

	p.cacheOptimisticAnswerTTL = cmp.Or(p.cacheOptimisticAnswerTTL, DefaultOptimisticAnswerTTL)
	p.cacheOptimisticMaxAge = cmp.Or(p.cacheOptimisticMaxAge, DefaultOptimisticMaxAge)

	p.initCache()

	if p.maxGoroutines > 0 {
		p.logger.Info("max goroutines is set", "count", p.maxGoroutines)

		p.requestsSema = syncutil.NewChanSemaphore(p.maxGoroutines)
	} else {
		p.requestsSema = syncutil.EmptySemaphore{}
	}

	p.upstreamMode = cmp.Or(p.upstreamMode, UpstreamModeLoadBalance)
	if p.upstreamMode == UpstreamModeFastestAddr {
		p.fastestAddr = fastip.New(&fastip.Config{
			Logger:          p.logger,
			PingWaitTimeout: p.fastestPingTimeout,
		})
	}

	if bindRetries := c.BindRetryConfig; bindRetries != nil && bindRetries.Enabled {
		p.bindRetryCount = bindRetries.Count
		p.bindRetryIvl = bindRetries.Interval
	}

	err = p.setupDNS64(c.DNS64Prefs)
	if err != nil {
		return nil, fmt.Errorf("setting up dns64: %w", err)
	}

	return p, nil
}

// pendingRequestsOrDefault returns the pending requests if it's not nil,
// otherwise it returns the default pending requests.
func pendingRequestsOrDefault(conf *PendingRequestsConfig) (pr pendingRequests) {
	if conf != nil && conf.Enabled {
		return newDefaultPendingRequests()
	}

	return emptyPendingRequests{}
}

// loggerOrDefault returns the logger if it's not nil, otherwise it returns the
// default logger.
func loggerOrDefault(l *slog.Logger) (logger *slog.Logger) {
	if l != nil {
		return l
	}

	return slog.Default().With(slogutil.KeyPrefix, LogPrefix)
}

// validateBasicAuth validates the HTTP settings if HTTPConfig.Userinfo is set.
func (p *Proxy) validateBasicAuth() (err error) {
	conf := p.httpConfig
	if conf == nil || conf.Userinfo == nil {
		return nil
	}

	return validate.NotEmptySlice("HTTPConfig.ListenAddresses", conf.ListenAddresses)
}

// Returns true if proxy is started.  It is safe for concurrent use.
func (p *Proxy) isStarted() (ok bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.started
}

// type check
var _ service.Interface = (*Proxy)(nil)

// Start implements the [service.Interface] for *Proxy.
func (p *Proxy) Start(ctx context.Context) (err error) {
	p.logger.InfoContext(ctx, "starting dns proxy server")

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.started {
		return errors.Error("server has been already started")
	}

	err = p.validateListenAddrs()
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	err = p.startListeners(ctx)
	if err != nil {
		closeErr := errors.Join(p.closeListeners(nil)...)

		return fmt.Errorf("configuring listeners: %w", errors.WithDeferred(err, closeErr))
	}

	err = p.initDNSCryptServers(ctx)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	// Use context without cancel to prevent listeners' context from being
	// canceled.
	p.serveListeners(context.WithoutCancel(ctx))

	err = p.startDNSCryptServers(context.WithoutCancel(ctx))
	if err != nil {
		p.dnsCryptServers = nil

		// Don't wrap the error since it's informative enough as is.
		return err
	}

	p.started = true

	return nil
}

// logClose closes the closer and logs the error at the specified level if it
// occurs.
func (p *Proxy) logClose(ctx context.Context, l slog.Level, c io.Closer, msg string, args ...any) {
	if err := c.Close(); err != nil {
		p.logger.Log(ctx, l, msg, append(args, slogutil.KeyError, err)...)
	}
}

// closeAll closes all closers and appends the occurred errors to errs.
func closeAll[C io.Closer](errs []error, closers ...C) (appended []error) {
	for _, c := range closers {
		err := c.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

// Shutdown implements the [service.Interface] for *Proxy.  It also closes the
// configured upstream configurations.
func (p *Proxy) Shutdown(ctx context.Context) (err error) {
	p.logger.InfoContext(ctx, "stopping server")

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.started {
		// TODO(a.garipov): Consider returning err.
		p.logger.WarnContext(ctx, "dns proxy server is not started")

		return nil
	}

	errs := p.closeListeners(nil)

	for _, u := range []*UpstreamConfig{
		p.upstreamConfig,
		p.privateRDNSUpstreamConfig,
		p.fallbacks,
	} {
		if u != nil {
			errs = closeAll(errs, u)
		}
	}

	err = shutdownDNSCryptServers(ctx, p.dnsCryptServers)
	errs = append(errs, err)
	p.dnsCryptServers = nil

	p.started = false

	p.logger.InfoContext(ctx, "stopped dns proxy server")

	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("stopping dns proxy server: %w", err)
	}

	return nil
}

// closeListeners closes all active listeners and returns the occurred errors.
//
// TODO(e.burkov):  Remove the argument if it remains unused.
func (p *Proxy) closeListeners(errs []error) (res []error) {
	res = errs

	res = closeAll(res, p.tcpListen...)
	p.tcpListen = nil

	res = closeAll(res, p.udpListen...)
	p.udpListen = nil

	res = closeAll(res, p.tlsListen...)
	p.tlsListen = nil

	if p.httpsServer != nil {
		res = closeAll(res, p.httpsServer)
		p.httpsServer = nil

		// No need to close these since they're closed by httpsServer.Close().
		p.httpsListen = nil
	}

	if p.h3Server != nil {
		res = closeAll(res, p.h3Server)
		p.h3Server = nil
	}

	res = closeAll(res, p.h3Listen...)
	p.h3Listen = nil

	res = closeAll(res, p.quicListen...)
	p.quicListen = nil

	res = closeAll(res, p.quicTransports...)
	p.quicTransports = nil

	res = closeAll(res, p.quicConns...)
	p.quicConns = nil

	return res
}

// addrFunc provides the address from the given A.
type addrFunc[A any] func(l A) (addr net.Addr)

// collectAddrs returns the slice of network addresses of the given addressers
// using the given addrFunc.
func collectAddrs[A any](addressers []A, af addrFunc[A]) (addrs []net.Addr) {
	for _, l := range addressers {
		addrs = append(addrs, af(l))
	}

	return addrs
}

// Addrs returns all listen addresses for the specified proto or nil if the
// proxy does not listen to it.  proto must be one of [Proto]: [ProtoTCP],
// [ProtoUDP], [ProtoTLS], [ProtoHTTPS], [ProtoQUIC], or [ProtoDNSCrypt].
func (p *Proxy) Addrs(proto Proto) (addrs []net.Addr) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch proto {
	case ProtoTCP:
		return collectAddrs(p.tcpListen, net.Listener.Addr)
	case ProtoTLS:
		return collectAddrs(p.tlsListen, net.Listener.Addr)
	case ProtoHTTPS:
		return collectAddrs(p.httpsListen, net.Listener.Addr)
	case ProtoUDP:
		return collectAddrs(p.udpListen, (*net.UDPConn).LocalAddr)
	case ProtoQUIC:
		return collectAddrs(p.quicListen, (*quic.EarlyListener).Addr)
	case ProtoDNSCrypt:
		return collectAddrs(p.dnsCryptServers, (*dnscrypt.Server).LocalAddr)
	default:
		// TODO(e.burkov):  Use [errors.ErrBadEnumValue].
		panic("proto must be 'tcp', 'tls', 'https', 'quic', 'dnscrypt' or 'udp'")
	}
}

// firstAddr returns the network address of the first entry in the given
// addressers or nil using the given addrFunc.
func firstAddr[A any](addressers []A, af addrFunc[A]) (addr net.Addr) {
	if len(addressers) == 0 {
		return nil
	}

	return af(addressers[0])
}

// Addr returns the first listen address for the specified proto or nil if the
// proxy does not listen to it.  proto must be one of [Proto]: [ProtoTCP],
// [ProtoUDP], [ProtoTLS], [ProtoHTTPS], [ProtoQUIC], or [ProtoDNSCrypt].
func (p *Proxy) Addr(proto Proto) (addr net.Addr) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch proto {
	case ProtoTCP:
		return firstAddr(p.tcpListen, net.Listener.Addr)
	case ProtoTLS:
		return firstAddr(p.tlsListen, net.Listener.Addr)
	case ProtoHTTPS:
		return firstAddr(p.httpsListen, net.Listener.Addr)
	case ProtoUDP:
		return firstAddr(p.udpListen, (*net.UDPConn).LocalAddr)
	case ProtoQUIC:
		return firstAddr(p.quicListen, (*quic.EarlyListener).Addr)
	case ProtoDNSCrypt:
		return firstAddr(p.dnsCryptServers, (*dnscrypt.Server).LocalAddr)
	default:
		panic("proto must be 'tcp', 'tls', 'https', 'quic', 'dnscrypt' or 'udp'")
	}
}

// selectUpstreams returns the upstreams to use for the specified host.  It
// firstly considers custom upstreams if those aren't empty and then the
// configured ones.  The returned slice may be empty or nil.
func (p *Proxy) selectUpstreams(d *DNSContext) (upstreams []upstream.Upstream, isPrivate bool) {
	q := d.Req.Question[0]
	host := q.Name

	if d.RequestedPrivateRDNS != (netip.Prefix{}) || p.shouldStripDNS64(d.Req) {
		// Use private upstreams.
		private := p.privateRDNSUpstreamConfig
		if p.usePrivateRDNS && d.IsPrivateClient && private != nil {
			// This may only be a PTR, SOA, and NS request.
			upstreams = private.getUpstreamsForDomain(host)
		}

		return upstreams, true
	}

	getUpstreams := (*UpstreamConfig).getUpstreamsForDomain
	if q.Qtype == dns.TypeDS {
		getUpstreams = (*UpstreamConfig).getUpstreamsForDS
	}

	if custom := d.CustomUpstreamConfig; custom != nil {
		// Try to use custom.
		upstreams = getUpstreams(custom.upstream, host)
		if len(upstreams) > 0 {
			return upstreams, false
		}
	}

	// Use configured.
	return getUpstreams(p.upstreamConfig, host), false
}

// replyFromUpstream tries to resolve the request via configured upstream
// servers.  It returns true if the response actually came from an upstream.
func (p *Proxy) replyFromUpstream(d *DNSContext) (ok bool, err error) {
	req := d.Req

	upstreams, isPrivate := p.selectUpstreams(d)
	if len(upstreams) == 0 {
		d.Res = p.messages.NewMsgNXDOMAIN(req)

		return false, fmt.Errorf("selecting upstream: %w", upstream.ErrNoUpstreams)
	}

	if isPrivate {
		p.recDetector.add(d.Req)
	}

	src := "upstream"
	wrapped := upstreamsWithStats(upstreams)

	// Perform the DNS request.
	resp, u, err := p.exchangeUpstreams(req, wrapped)
	if dns64Ups := p.performDNS64(req, resp, wrapped); dns64Ups != nil {
		u = dns64Ups
	} else if p.isBogusNXDomain(resp) {
		p.logger.Debug("response contains bogus-nxdomain ip")
		resp = p.messages.NewMsgNXDOMAIN(req)
	}

	var wrappedFallbacks []upstream.Upstream
	if err != nil && !isPrivate && p.fallbacks != nil {
		p.logger.Debug("using fallback", slogutil.KeyError, err)

		src = "fallback"

		// upstreams mustn't appear empty since they have been validated when
		// creating proxy.
		upstreams = p.fallbacks.getUpstreamsForDomain(req.Question[0].Name)

		wrappedFallbacks = upstreamsWithStats(upstreams)
		resp, u, err = upstream.ExchangeParallel(wrappedFallbacks, req)
	}

	if err != nil {
		p.logger.Debug("resolving err", "src", src, slogutil.KeyError, err)
	}

	if resp != nil {
		p.logger.Debug("resolved", "upstream", u.Address(), "src", src)
	}

	unwrapped, stats := collectQueryStats(p.upstreamMode, u, wrapped, wrappedFallbacks)
	d.queryStatistics = stats

	ctx := context.TODO()
	p.handleExchangeResult(ctx, d, req, resp, unwrapped)

	return resp != nil, err
}

// handleExchangeResult handles the result after the upstream exchange.  It sets
// resp and the upstream that has resolved the request in d.  Also, it clears
// the AA bit in the upstream response.  If resp is nil, it generates a server
// failure response.  req must not be nil.
func (p *Proxy) handleExchangeResult(
	ctx context.Context,
	d *DNSContext,
	req *dns.Msg,
	resp *dns.Msg,
	u upstream.Upstream,
) {
	if resp == nil || len(resp.Question) != 1 {
		d.Res = p.messages.NewMsgSERVFAIL(req)
		d.hasEDNS0 = false

		return
	}

	d.Upstream = u
	d.Res = resp
	d.Res.Authoritative = false

	p.setMinMaxTTL(ctx, resp)
}

// addDO adds EDNS0 RR if needed and sets DO bit of msg to true.  msg must not
// be nil.
func (p *Proxy) addDO(msg *dns.Msg) {
	if !p.dnsSecEnabled {
		// Do nothing if DNSSEC is disabled in the proxy.
		return
	}

	if o := msg.IsEdns0(); o != nil {
		if !o.Do() {
			o.SetDo()
		}

		return
	}

	msg.SetEdns0(defaultUDPBufSize, true)
}

// defaultUDPBufSize defines the default size of UDP buffer for EDNS0 RRs.
const defaultUDPBufSize = 2048

// Resolve is the default resolving method used by the DNS proxy to query
// upstream servers.  It expects dctx is filled with the client's request.
func (p *Proxy) Resolve(ctx context.Context, dctx *DNSContext) (err error) {
	if p.enableEDNSClientSubnet {
		dctx.processECS(p.ednsAddr, p.logger)
	}

	dctx.calcFlagsAndSize()

	cacheWorks := p.cacheWorks(dctx)
	if cacheWorks {
		// Request for DNSSEC from the upstream to cache the
		// DNSSEC resource records as well.  In case of disabled DNSSEC,
		// requesting and therefore caching of DNSSEC resource records depends
		// on the DO bit of the initiating query.
		//
		// See https://datatracker.ietf.org/doc/html/rfc4035#section-4.5 and
		// https://datatracker.ietf.org/doc/html/rfc3225#section-3.
		p.addDO(dctx.Req)

		// Only add pending requests if the cache is enabled, since this is a
		// mitigation against cache poisoning.
		//
		// TODO(e.burkov):  Consider tracking all requests.
		var loaded bool
		loaded, err = p.pendingRequests.queue(ctx, dctx)
		if loaded {
			return err
		}
		defer func() { p.pendingRequests.done(ctx, dctx, err) }()

		if p.replyFromCache(dctx) {
			// Complete the response from cache.
			filterMsg(dctx.Res, dctx.Res, dctx.adBit, dctx.doBit, 0)
			dctx.scrub()

			return nil
		}
	}

	var ok bool
	ok, err = p.replyFromUpstream(dctx)

	// Don't cache the responses having CD flag, just like Dnsmasq does.  It
	// prevents the cache from being poisoned with unvalidated answers which may
	// differ from validated ones.
	//
	// See https://github.com/imp/dnsmasq/blob/770bce967cfc9967273d0acfb3ea018fb7b17522/src/forward.c#L1169-L1172.
	if cacheWorks && ok && !dctx.Res.CheckingDisabled {
		// Cache the response with DNSSEC RRs.
		p.cacheResp(dctx)
	}

	// It is possible that the response is nil if the upstream hasn't been
	// chosen.
	if dctx.Res != nil {
		filterMsg(dctx.Res, dctx.Res, dctx.adBit, dctx.doBit, 0)
	}

	// Complete the response.
	dctx.scrub()

	return err
}

// validateRequest returns a response for invalid request or nil if the request
// is ok.
func (p *Proxy) validateRequest(d *DNSContext) (resp *dns.Msg) {
	switch {
	case len(d.Req.Question) != 1:
		p.logger.Debug("invalid number of questions", "req_questions_len", len(d.Req.Question))

		return p.messages.NewMsgFORMERR(d.Req)
	case p.refuseAny && d.Req.Question[0].Qtype == dns.TypeANY:
		// Refuse requests of type ANY (anti-DDOS measure).
		p.logger.Debug("refusing dns type any request")

		return p.messages.NewMsgNOTIMPLEMENTED(d.Req)
	case p.recDetector.check(d.Req):
		p.logger.Debug("recursion detected", "req_question", d.Req.Question[0].Name)

		return p.messages.NewMsgNXDOMAIN(d.Req)
	case d.isForbiddenARPA(p.privateNets, p.logger):
		p.logger.Debug(
			"private arpa domain is requested",
			"addr", d.Addr,
			"arpa", d.Req.Question[0].Name,
		)

		return p.messages.NewMsgNXDOMAIN(d.Req)
	default:
		return nil
	}
}

// cacheWorks returns true if the cache works for the given context.  If not, it
// returns false and logs the reason why.
func (p *Proxy) cacheWorks(dctx *DNSContext) (ok bool) {
	var reason string
	switch {
	case dctx.CustomUpstreamConfig != nil && dctx.CustomUpstreamConfig.cache == nil:
		// If custom upstreams are used but the custom upstream cache is
		// disabled, return false to prevent storing results in the global
		// cache.
		//
		// See https://github.com/AdguardTeam/dnsproxy/issues/169.
		reason = "custom upstreams cache is not configured"
	case p.cache == nil &&
		(dctx.CustomUpstreamConfig == nil || dctx.CustomUpstreamConfig.cache == nil):
		reason = "caching disabled: neither global cache nor custom upstreams cache is configured"
	case dctx.RequestedPrivateRDNS != netip.Prefix{}:
		// Don't cache the requests intended for local upstream servers, those
		// should be fast enough as is.
		reason = "requested address is private"
	case dctx.Req.CheckingDisabled:
		// Also don't lookup the cache for responses with DNSSEC checking
		// disabled since only validated responses are cached and those may be
		// not the desired result for user specifying CD flag.
		reason = "dnssec check disabled"
	default:
		return true
	}

	p.logger.Debug("not caching", "reason", reason)

	return false
}

// processECS adds EDNS Client Subnet data into the request from d.
func (dctx *DNSContext) processECS(cliIP net.IP, l *slog.Logger) {
	if ecs, _ := ecsFromMsg(dctx.Req); ecs != nil {
		if ones, _ := ecs.Mask.Size(); ones != 0 {
			dctx.ReqECS = ecs

			l.Debug("passing through ecs", "subnet", dctx.ReqECS)

			return
		}
	}

	var cliAddr netip.Addr
	if cliIP == nil {
		cliAddr = dctx.Addr.Addr()
		cliIP = cliAddr.AsSlice()
	} else {
		cliAddr, _ = netip.AddrFromSlice(cliIP)
	}

	if !netutil.IsSpecialPurpose(cliAddr) {
		// A Stub Resolver MUST set SCOPE PREFIX-LENGTH to 0.  See RFC 7871
		// Section 6.
		dctx.ReqECS = setECS(dctx.Req, cliIP, 0)

		l.Debug("setting ecs", "subnet", dctx.ReqECS)
	}
}
