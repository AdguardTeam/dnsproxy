// Package proxy implements a DNS proxy that supports all known DNS encryption
// protocols.
package proxy

import (
	"cmp"
	"context"
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

	"github.com/AdguardTeam/dnsproxy/fastip"
	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/ameshkov/dnscrypt/v2"
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

// Proxy combines the proxy server state and configuration.
//
// TODO(a.garipov): Consider extracting conf blocks for better fieldalignment.
type Proxy struct {
	// requestsSema limits the number of simultaneous requests.
	//
	// TODO(a.garipov): Currently we have to pass this exact semaphore to the
	// workers, to prevent races on restart.  In the future we will need a
	// better restarting mechanism that completely prevents such invalid states.
	//
	// See also: https://github.com/AdguardTeam/AdGuardHome/issues/2242.
	requestsSema syncutil.Semaphore

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

	// beforeRequestHandler handles the request's context before it is resolved.
	beforeRequestHandler BeforeRequestHandler

	// requestHandler handles the DNS request after it's been processed by the
	// beforeRequestHandler.  It is never nil.
	requestHandler Handler

	// dnsCryptServer serves DNSCrypt queries.
	dnsCryptServer *dnscrypt.Server

	// logger is used for logging in the proxy service.  It is never nil.
	logger *slog.Logger

	// fastestAddr finds the fastest IP address for the resolved domain.
	fastestAddr *fastip.FastestAddr

	// cache is used to cache requests.  It is disabled if nil.
	//
	// TODO(d.kolyshev): Move this cache to [Proxy.UpstreamConfig] field.
	cache *cache

	// shortFlighter is used to resolve the expired cached requests without
	// repetitions.
	shortFlighter *optimisticResolver

	// recDetector detects recursive requests that may appear when resolving
	// requests for private addresses.
	recDetector *recursionDetector

	// pendingRequests is a storage for duplicated requests.  It is used to
	// prevent sending the same request to upstreams multiple times.
	pendingRequests pendingRequests

	// bytesPool is a pool of byte slices used to read DNS packets.
	bytesPool *syncutil.Pool[[]byte]

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

	// quicTransports are transports for all listened QUIC connections.  These
	// should be closed on shutdown, since *quic.EarlyListener doesn't close
	// them.
	quicTransports []*quic.Transport

	// httpsListen are the listened HTTPS connections.
	httpsListen []net.Listener

	// h3Listen are the listened HTTP/3 connections.
	h3Listen []*quic.EarlyListener

	// httpsServer serves queries received over HTTPS.
	httpsServer *http.Server

	// h3Server serves queries received over HTTP/3.
	h3Server *http3.Server

	// dnsCryptUDPListen are the listened UDP connections for DNSCrypt.
	dnsCryptUDPListen []*net.UDPConn

	// dnsCryptTCPListen are the listened TCP connections for DNSCrypt.
	dnsCryptTCPListen []net.Listener

	// upstreamRTTStats maps the upstream address to its round-trip time
	// statistics.  It's holds the statistics for all upstreams to perform a
	// weighted random selection when using the load balancing mode.
	upstreamRTTStats map[string]upstreamRTTStats

	// dns64Prefs is a set of NAT64 prefixes that are used to detect and
	// construct DNS64 responses.  The DNS64 function is disabled if it is
	// empty.
	dns64Prefs netutil.SliceSubnetSet

	// Config is the proxy configuration.
	//
	// TODO(a.garipov): Remove this embed and create a proper initializer.
	Config

	// udpOOBSize is the size of the out-of-band data for UDP connections.
	udpOOBSize int

	// bindRetryCount is the number of retries for binding to an address for
	// listening.  Zero means one attempt and no retries.
	bindRetryCount uint

	// bindRetryIvl is the interval between attempts to bind to an address for
	// listening.
	bindRetryIvl time.Duration

	// counter counts message contexts created with [Proxy.newDNSContext].
	counter atomic.Uint64

	// RWMutex protects the whole proxy.
	//
	// TODO(e.burkov):  Find out what exactly it protects and name it properly.
	// Also make it a pointer.
	sync.RWMutex

	// rttLock protects upstreamRTTStats.
	//
	// TODO(e.burkov):  Make it a pointer.
	rttLock sync.Mutex

	// started indicates if the proxy has been started.
	started bool
}

// New creates a new Proxy with the specified configuration.  c must not be nil.
//
// TODO(e.burkov):  Cover with tests.
//
// TODO(e.burkov):  Add context.
func New(c *Config) (p *Proxy, err error) {
	p = &Proxy{
		Config: *c,
		privateNets: cmp.Or[netutil.SubnetSet](
			c.PrivateSubnets,
			netutil.SubnetSetFunc(netutil.IsLocallyServed),
		),
		beforeRequestHandler: cmp.Or[BeforeRequestHandler](
			c.BeforeRequestHandler,
			noopRequestHandler{},
		),
		requestHandler:   cmp.Or[Handler](c.RequestHandler, DefaultHandler{}),
		upstreamRTTStats: map[string]upstreamRTTStats{},
		rttLock:          sync.Mutex{},
		RWMutex:          sync.RWMutex{},
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

	p.CacheOptimisticAnswerTTL = cmp.Or(p.CacheOptimisticAnswerTTL, DefaultOptimisticAnswerTTL)
	p.CacheOptimisticMaxAge = cmp.Or(p.CacheOptimisticMaxAge, DefaultOptimisticMaxAge)

	p.initCache()

	if p.MaxGoroutines > 0 {
		p.logger.Info("max goroutines is set", "count", p.MaxGoroutines)

		p.requestsSema = syncutil.NewChanSemaphore(p.MaxGoroutines)
	} else {
		p.requestsSema = syncutil.EmptySemaphore{}
	}

	p.UpstreamMode = cmp.Or(p.UpstreamMode, UpstreamModeLoadBalance)
	if p.UpstreamMode == UpstreamModeFastestAddr {
		p.fastestAddr = fastip.New(&fastip.Config{
			Logger:          p.Logger,
			PingWaitTimeout: p.FastestPingTimeout,
		})
	}

	if bindRetries := c.BindRetryConfig; bindRetries != nil && bindRetries.Enabled {
		p.bindRetryCount = bindRetries.Count
		p.bindRetryIvl = bindRetries.Interval
	}

	err = p.setupDNS64()
	if err != nil {
		return nil, fmt.Errorf("setting up DNS64: %w", err)
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

// validateBasicAuth validates the basic-auth mode settings if p.Config.Userinfo
// is set.
func (p *Proxy) validateBasicAuth() (err error) {
	conf := p.Config
	if conf.Userinfo == nil {
		return nil
	}

	return validate.NotEmptySlice("HTTPSListenAddr", conf.HTTPSListenAddr)
}

// Returns true if proxy is started.  It is safe for concurrent use.
func (p *Proxy) isStarted() (ok bool) {
	p.RLock()
	defer p.RUnlock()

	return p.started
}

// type check
var _ service.Interface = (*Proxy)(nil)

// Start implements the [service.Interface] for *Proxy.
func (p *Proxy) Start(ctx context.Context) (err error) {
	p.logger.InfoContext(ctx, "starting dns proxy server")

	p.Lock()
	defer p.Unlock()

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

	p.serveListeners()

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

	p.Lock()
	defer p.Unlock()

	if !p.started {
		// TODO(a.garipov): Consider returning err.
		p.logger.WarnContext(ctx, "dns proxy server is not started")

		return nil
	}

	errs := p.closeListeners(nil)

	for _, u := range []*UpstreamConfig{
		p.UpstreamConfig,
		p.PrivateRDNSUpstreamConfig,
		p.Fallbacks,
	} {
		if u != nil {
			errs = closeAll(errs, u)
		}
	}

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

	res = closeAll(res, p.dnsCryptUDPListen...)
	p.dnsCryptUDPListen = nil

	res = closeAll(res, p.dnsCryptTCPListen...)
	p.dnsCryptTCPListen = nil

	return res
}

// addrFunc provides the address from the given A.
type addrFunc[A any] func(l A) (addr net.Addr)

// collectAddrs returns the slice of network addresses of the given listeners
// using the given addrFunc.
func collectAddrs[A any](listeners []A, af addrFunc[A]) (addrs []net.Addr) {
	for _, l := range listeners {
		addrs = append(addrs, af(l))
	}

	return addrs
}

// Addrs returns all listen addresses for the specified proto or nil if the
// proxy does not listen to it.  proto must be one of [Proto]: [ProtoTCP],
// [ProtoUDP], [ProtoTLS], [ProtoHTTPS], [ProtoQUIC], or [ProtoDNSCrypt].
func (p *Proxy) Addrs(proto Proto) (addrs []net.Addr) {
	p.RLock()
	defer p.RUnlock()

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
		// Using only UDP addrs here
		//
		// TODO(ameshkov): To do it better we should either do
		// ProtoDNSCryptTCP/ProtoDNSCryptUDP or we should change the
		// configuration so that it was not possible to set different ports for
		// TCP/UDP listeners.
		return collectAddrs(p.dnsCryptUDPListen, (*net.UDPConn).LocalAddr)
	default:
		// TODO(e.burkov):  Use [errors.ErrBadEnumValue].
		panic("proto must be 'tcp', 'tls', 'https', 'quic', 'dnscrypt' or 'udp'")
	}
}

// firstAddr returns the network address of the first listener in the given
// listeners or nil using the given addrFunc.
func firstAddr[A any](listeners []A, af addrFunc[A]) (addr net.Addr) {
	if len(listeners) == 0 {
		return nil
	}

	return af(listeners[0])
}

// Addr returns the first listen address for the specified proto or nil if the
// proxy does not listen to it.  proto must be one of [Proto]: [ProtoTCP],
// [ProtoUDP], [ProtoTLS], [ProtoHTTPS], [ProtoQUIC], or [ProtoDNSCrypt].
func (p *Proxy) Addr(proto Proto) (addr net.Addr) {
	p.RLock()
	defer p.RUnlock()

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
		return firstAddr(p.dnsCryptUDPListen, (*net.UDPConn).LocalAddr)
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
		private := p.PrivateRDNSUpstreamConfig
		if p.UsePrivateRDNS && d.IsPrivateClient && private != nil {
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
	return getUpstreams(p.UpstreamConfig, host), false
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
	if err != nil && !isPrivate && p.Fallbacks != nil {
		p.logger.Debug("using fallback", slogutil.KeyError, err)

		src = "fallback"

		// upstreams mustn't appear empty since they have been validated when
		// creating proxy.
		upstreams = p.Fallbacks.getUpstreamsForDomain(req.Question[0].Name)

		wrappedFallbacks = upstreamsWithStats(upstreams)
		resp, u, err = upstream.ExchangeParallel(wrappedFallbacks, req)
	}

	if err != nil {
		p.logger.Debug("resolving err", "src", src, slogutil.KeyError, err)
	}

	if resp != nil {
		p.logger.Debug("resolved", "upstream", u.Address(), "src", src)
	}

	unwrapped, stats := collectQueryStats(p.UpstreamMode, u, wrapped, wrappedFallbacks)
	d.queryStatistics = stats

	ctx := context.TODO()
	p.handleExchangeResult(ctx, d, req, resp, unwrapped)

	return resp != nil, err
}

// handleExchangeResult handles the result after the upstream exchange.  It sets
// resp and the upstream that has resolved the request in d.  If resp is nil, it
// generates a server failure response.  req must not be nil.
func (p *Proxy) handleExchangeResult(
	ctx context.Context,
	d *DNSContext,
	req *dns.Msg,
	resp *dns.Msg,
	u upstream.Upstream,
) {
	if resp == nil {
		d.Res = p.messages.NewMsgSERVFAIL(req)
		d.hasEDNS0 = false

		return
	}

	d.Upstream = u
	d.Res = resp

	p.setMinMaxTTL(ctx, resp)
	if len(req.Question) > 0 && len(resp.Question) == 0 {
		// Explicitly construct the question section since some upstreams may
		// respond with invalidly constructed messages which cause out-of-range
		// panics afterwards.
		//
		// See https://github.com/AdguardTeam/AdGuardHome/issues/3551.
		resp.Question = []dns.Question{req.Question[0]}
	}
}

// addDO adds EDNS0 RR if needed and sets DO bit of msg to true.
func addDO(msg *dns.Msg) {
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
// upstream servers.  It expects dctx is filled with the request, the client's
//
// TODO(e.burkov):  Add [context.Context].
func (p *Proxy) Resolve(dctx *DNSContext) (err error) {
	ctx := context.Background()

	if p.EnableEDNSClientSubnet {
		dctx.processECS(p.EDNSAddr, p.logger)
	}

	dctx.calcFlagsAndSize()

	cacheWorks := p.cacheWorks(dctx)
	if cacheWorks {
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
			dctx.scrub()

			return nil
		}

		// On cache miss request for DNSSEC from the upstream to cache it
		// afterwards.
		addDO(dctx.Req)
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

		// TODO(e.burkov):  Probably, FORMERR would be a better choice here.
		// Check out RFC.
		return p.messages.NewMsgSERVFAIL(d.Req)
	case p.RefuseAny && d.Req.Question[0].Qtype == dns.TypeANY:
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
