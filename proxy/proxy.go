// Package proxy implements a DNS proxy that supports all known DNS
// encryption protocols.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/dnsproxy/fastip"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
	gocache "github.com/patrickmn/go-cache"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/exp/slices"
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

const (
	// UnqualifiedNames is reserved name for "unqualified names only", ie names without dots
	UnqualifiedNames = "unqualified_names"
)

// Proxy combines the proxy server state and configuration
//
// TODO(a.garipov): Consider extracting conf blocks for better fieldalignment.
type Proxy struct {
	// counter is the counter of messages.  It must only be incremented
	// atomically, so it must be the first member of the struct to make sure
	// that it has a 64-bit alignment.
	//
	// See https://golang.org/pkg/sync/atomic/#pkg-note-BUG.
	counter uint64

	// started indicates if the proxy has been started.
	started bool

	// Listeners
	// --

	// udpListen are the listened UDP connections.
	udpListen []*net.UDPConn

	// tcpListen are the listened TCP connections.
	tcpListen []net.Listener

	// tlsListen are the listened TCP connections with TLS.
	tlsListen []net.Listener

	// quicListen are the listened QUIC connections.
	quicListen []*quic.EarlyListener

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

	// dnsCryptServer serves DNSCrypt queries.
	dnsCryptServer *dnscrypt.Server

	// Upstream
	// --

	// upstreamRTTStats is a map of upstream addresses and their rtt.  Used to
	// sort upstreams by their latency.
	upstreamRTTStats map[string]int

	// rttLock protects upstreamRTTStats.
	rttLock sync.Mutex

	// DNS64 (in case dnsproxy works in a NAT64/DNS64 network)
	// --

	// dns64Prefs is a set of NAT64 prefixes that are used to detect and
	// construct DNS64 responses.  The DNS64 function is disabled if it is
	// empty.
	dns64Prefs []netip.Prefix

	// Ratelimit
	// --

	// ratelimitBuckets is a storage for ratelimiters for individual IPs.
	ratelimitBuckets *gocache.Cache

	// ratelimitLock protects ratelimitBuckets.
	ratelimitLock sync.Mutex

	// proxyVerifier checks if the proxy is in the trusted list.
	proxyVerifier netutil.SubnetSet

	// DNS cache
	// --

	// cache is used to cache requests.  It is disabled if nil.
	//
	// TODO(d.kolyshev): Move this cache to [Proxy.UpstreamConfig] field.
	cache *cache

	// shortFlighter is used to resolve the expired cached requests without
	// repetitions.
	shortFlighter *optimisticResolver

	// FastestAddr module
	// --

	// fastestAddr finds the fastest IP address for the resolved domain.
	fastestAddr *fastip.FastestAddr

	// Other
	// --

	// bytesPool is a pool of byte slices used to read DNS packets.
	bytesPool *sync.Pool

	// udpOOBSize is the size of the out-of-band data for UDP connections.
	udpOOBSize int

	// RWMutex protects the whole proxy.
	sync.RWMutex

	// requestGoroutinesSema limits the number of simultaneous requests.
	//
	// TODO(a.garipov): Currently we have to pass this exact semaphore to
	// the workers, to prevent races on restart.  In the future we will need
	// a better restarting mechanism that completely prevents such invalid
	// states.
	//
	// See also: https://github.com/AdguardTeam/AdGuardHome/issues/2242.
	requestGoroutinesSema semaphore

	// Config is the proxy configuration.
	//
	// TODO(a.garipov): Remove this embed and create a proper initializer.
	Config
}

// Init populates fields of p but does not start listeners.
func (p *Proxy) Init() (err error) {
	// TODO(s.chzhen):  Consider moving to [Proxy.validateConfig].
	err = p.validateBasicAuth()
	if err != nil {
		return fmt.Errorf("basic auth: %w", err)
	}

	p.initCache()

	if p.MaxGoroutines > 0 {
		log.Info("dnsproxy: max goroutines is set to %d", p.MaxGoroutines)

		p.requestGoroutinesSema, err = newChanSemaphore(p.MaxGoroutines)
		if err != nil {
			return fmt.Errorf("can't init semaphore: %w", err)
		}
	} else {
		p.requestGoroutinesSema = newNoopSemaphore()
	}

	p.udpOOBSize = proxynetutil.UDPGetOOBSize()
	p.bytesPool = &sync.Pool{
		New: func() interface{} {
			// 2 bytes may be used to store packet length (see TCP/TLS)
			b := make([]byte, 2+dns.MaxMsgSize)

			return &b
		},
	}

	if p.UpstreamMode == UModeFastestAddr {
		log.Info("dnsproxy: fastest ip is enabled")

		p.fastestAddr = fastip.NewFastestAddr()
		if timeout := p.FastestPingTimeout; timeout > 0 {
			p.fastestAddr.PingWaitTimeout = timeout
		}
	}

	var trusted []*net.IPNet
	trusted, err = netutil.ParseSubnets(p.TrustedProxies...)
	if err != nil {
		return fmt.Errorf("initializing subnet detector for proxies verifying: %w", err)
	}

	p.proxyVerifier = netutil.SliceSubnetSet(trusted)

	err = p.setupDNS64()
	if err != nil {
		return fmt.Errorf("setting up DNS64: %w", err)
	}

	p.RatelimitWhitelist = slices.Clone(p.RatelimitWhitelist)
	slices.SortFunc(p.RatelimitWhitelist, netip.Addr.Compare)

	return nil
}

// validateBasicAuth validates the basic-auth mode settings if p.Config.Userinfo
// is set.
func (p *Proxy) validateBasicAuth() (err error) {
	conf := p.Config
	if conf.Userinfo == nil {
		return nil
	}

	if len(conf.HTTPSListenAddr) == 0 {
		return errors.Error("no https addrs")
	}

	return nil
}

// Start initializes the proxy server and starts listening
func (p *Proxy) Start() (err error) {
	log.Info("dnsproxy: starting dns proxy server")

	p.Lock()
	defer p.Unlock()

	if p.started {
		return errors.Error("server has been already started")
	}

	err = p.validateConfig()
	if err != nil {
		return err
	}

	err = p.Init()
	if err != nil {
		return err
	}

	// TODO(a.garipov): Accept a context into this method.
	ctx := context.Background()
	err = p.startListeners(ctx)
	if err != nil {
		return fmt.Errorf("starting listeners: %w", err)
	}

	p.started = true

	return nil
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

// Stop stops the proxy server including all its listeners
func (p *Proxy) Stop() error {
	log.Info("dnsproxy: stopping dns proxy server")

	p.Lock()
	defer p.Unlock()

	if !p.started {
		log.Info("dnsproxy: dns proxy server is not started")

		return nil
	}

	errs := closeAll(nil, p.tcpListen...)
	p.tcpListen = nil

	errs = closeAll(errs, p.udpListen...)
	p.udpListen = nil

	errs = closeAll(errs, p.tlsListen...)
	p.tlsListen = nil

	if p.httpsServer != nil {
		errs = closeAll(errs, p.httpsServer)
		p.httpsServer = nil

		// No need to close these since they're closed by httpsServer.Close().
		p.httpsListen = nil
	}

	if p.h3Server != nil {
		errs = closeAll(errs, p.h3Server)
		p.h3Server = nil
	}

	errs = closeAll(errs, p.h3Listen...)
	p.h3Listen = nil

	errs = closeAll(errs, p.quicListen...)
	p.quicListen = nil

	errs = closeAll(errs, p.dnsCryptUDPListen...)
	p.dnsCryptUDPListen = nil

	errs = closeAll(errs, p.dnsCryptTCPListen...)
	p.dnsCryptTCPListen = nil

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

	log.Println("dnsproxy: stopped dns proxy server")

	if len(errs) > 0 {
		return errors.List("stopping dns proxy server", errs...)
	}

	return nil
}

// Addrs returns all listen addresses for the specified proto or nil if the proxy does not listen to it.
// proto must be "tcp", "tls", "https", "quic", or "udp"
func (p *Proxy) Addrs(proto Proto) []net.Addr {
	p.RLock()
	defer p.RUnlock()

	var addrs []net.Addr

	switch proto {
	case ProtoTCP:
		for _, l := range p.tcpListen {
			addrs = append(addrs, l.Addr())
		}

	case ProtoTLS:
		for _, l := range p.tlsListen {
			addrs = append(addrs, l.Addr())
		}

	case ProtoHTTPS:
		for _, l := range p.httpsListen {
			addrs = append(addrs, l.Addr())
		}

	case ProtoUDP:
		for _, l := range p.udpListen {
			addrs = append(addrs, l.LocalAddr())
		}

	case ProtoQUIC:
		for _, l := range p.quicListen {
			addrs = append(addrs, l.Addr())
		}

	case ProtoDNSCrypt:
		// Using only UDP addrs here
		// TODO: to do it better we should either do ProtoDNSCryptTCP/ProtoDNSCryptUDP
		// or we should change the configuration so that it was not possible to
		// set different ports for TCP/UDP listeners.
		for _, l := range p.dnsCryptUDPListen {
			addrs = append(addrs, l.LocalAddr())
		}

	default:
		panic("proto must be 'tcp', 'tls', 'https', 'quic', 'dnscrypt' or 'udp'")
	}

	return addrs
}

// Addr returns the first listen address for the specified proto or null if the proxy does not listen to it
// proto must be "tcp", "tls", "https", "quic", or "udp"
func (p *Proxy) Addr(proto Proto) net.Addr {
	p.RLock()
	defer p.RUnlock()
	switch proto {
	case ProtoTCP:
		if len(p.tcpListen) == 0 {
			return nil
		}
		return p.tcpListen[0].Addr()

	case ProtoTLS:
		if len(p.tlsListen) == 0 {
			return nil
		}
		return p.tlsListen[0].Addr()

	case ProtoHTTPS:
		if len(p.httpsListen) == 0 {
			return nil
		}
		return p.httpsListen[0].Addr()

	case ProtoUDP:
		if len(p.udpListen) == 0 {
			return nil
		}
		return p.udpListen[0].LocalAddr()

	case ProtoQUIC:
		if len(p.quicListen) == 0 {
			return nil
		}
		return p.quicListen[0].Addr()

	case ProtoDNSCrypt:
		if len(p.dnsCryptUDPListen) == 0 {
			return nil
		}
		return p.dnsCryptUDPListen[0].LocalAddr()
	default:
		panic("proto must be 'tcp', 'tls', 'https', 'quic', 'dnscrypt' or 'udp'")
	}
}

// needsLocalUpstream returns true if the request should be handled by a private
// upstream servers.
func (p *Proxy) needsLocalUpstream(req *dns.Msg) (ok bool) {
	if req.Question[0].Qtype != dns.TypePTR {
		return false
	}

	host := req.Question[0].Name
	ip, err := netutil.IPFromReversedAddr(host)
	if err != nil {
		log.Debug("dnsproxy: failed to parse ip from ptr request: %s", err)

		return false
	}

	return p.shouldStripDNS64(ip)
}

// selectUpstreams returns the upstreams to use for the specified host.  It
// firstly considers custom upstreams if those aren't empty and then the
// configured ones.  The returned slice may be empty or nil.
func (p *Proxy) selectUpstreams(d *DNSContext) (upstreams []upstream.Upstream) {
	q := d.Req.Question[0]
	host := q.Name
	qtype := q.Qtype

	if !p.needsLocalUpstream(d.Req) {
		// TODO(e.burkov):  Use the same logic for private upstreams as well,
		// when those start supporting non-PTR requests.
		getUpstreams := (*UpstreamConfig).getUpstreamsForDomain
		if qtype == dns.TypeDS {
			getUpstreams = (*UpstreamConfig).getUpstreamsForDS
		}

		if custom := d.CustomUpstreamConfig; custom != nil {
			// Try to use custom.
			upstreams = getUpstreams(custom.upstream, host)
			if len(upstreams) > 0 {
				return upstreams
			}
		}

		// Use configured.
		return getUpstreams(p.UpstreamConfig, host)
	}

	// Use private upstreams.
	private := p.PrivateRDNSUpstreamConfig
	if private == nil {
		return nil
	}

	// TODO(e.burkov):  Detect against the actual configured subnet set.
	// Perhaps, even much earlier.
	if !netutil.IsLocallyServedAddr(d.Addr.Addr()) {
		return nil
	}

	return private.getUpstreamsForDomain(host)
}

// replyFromUpstream tries to resolve the request.
func (p *Proxy) replyFromUpstream(d *DNSContext) (ok bool, err error) {
	req := d.Req

	upstreams := p.selectUpstreams(d)
	if len(upstreams) == 0 {
		return false, fmt.Errorf("selecting general upstream: %w", upstream.ErrNoUpstreams)
	}

	start := time.Now()
	src := "upstream"

	// Perform the DNS request.
	resp, u, err := p.exchange(req, upstreams)
	if dns64Ups := p.performDNS64(req, resp, upstreams); dns64Ups != nil {
		u = dns64Ups
	} else if p.isBogusNXDomain(resp) {
		log.Debug("proxy: replying from upstream: response contains bogus-nxdomain ip")
		resp = p.genWithRCode(req, dns.RcodeNameError)
	}

	if err != nil && p.Fallbacks != nil {
		log.Debug("proxy: replying from upstream: using fallback due to %s", err)

		// Reset the timer.
		start = time.Now()
		src = "fallback"

		upstreams = p.Fallbacks.getUpstreamsForDomain(req.Question[0].Name)
		if len(upstreams) == 0 {
			return false, fmt.Errorf("selecting fallback upstream: %w", upstream.ErrNoUpstreams)
		}

		resp, u, err = upstream.ExchangeParallel(upstreams, req)
	}

	if err != nil {
		log.Debug("proxy: replying from %s: %s", src, err)
	}

	if resp != nil {
		rtt := time.Since(start)
		log.Debug("proxy: replying from %s: rtt is %s", src, rtt)

		d.QueryDuration = rtt
	}

	p.handleExchangeResult(d, req, resp, u)

	return resp != nil, err
}

// handleExchangeResult handles the result after the upstream exchange.  It sets
// the response to d and sets the upstream that have resolved the request.  If
// the response is nil, it generates a server failure response.
func (p *Proxy) handleExchangeResult(d *DNSContext, req, resp *dns.Msg, u upstream.Upstream) {
	if resp == nil {
		d.Res = p.genServerFailure(req)
		d.hasEDNS0 = false

		return
	}

	d.Upstream = u
	d.Res = resp

	p.setMinMaxTTL(resp)
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
// upstream servers.
func (p *Proxy) Resolve(dctx *DNSContext) (err error) {
	if p.EnableEDNSClientSubnet {
		dctx.processECS(p.EDNSAddr)
	}

	dctx.calcFlagsAndSize()

	// Also don't lookup the cache for responses with DNSSEC checking disabled
	// since only validated responses are cached and those may be not the
	// desired result for user specifying CD flag.
	cacheWorks := p.cacheWorks(dctx)
	if cacheWorks {
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

	if p.ResponseHandler != nil {
		p.ResponseHandler(dctx, err)
	}

	return err
}

// cacheWorks returns true if the cache works for the given context.  If not, it
// returns false and logs the reason why.
func (p *Proxy) cacheWorks(dctx *DNSContext) (ok bool) {
	var reason string
	switch {
	case p.cache == nil:
		reason = "disabled"
	case dctx.CustomUpstreamConfig != nil && dctx.CustomUpstreamConfig.cache == nil:
		// In case of custom upstream cache is not configured, the global proxy
		// cache cannot be used because different upstreams can return different
		// results.
		// See https://github.com/AdguardTeam/dnsproxy/issues/169.
		reason = "custom upstreams cache is not configured"
	case dctx.Req.CheckingDisabled:
		reason = "dnssec check disabled"
	default:
		return true
	}

	log.Debug("dnsproxy: cache: %s; not caching", reason)

	return false
}

// processECS adds EDNS Client Subnet data into the request from d.
func (dctx *DNSContext) processECS(cliIP net.IP) {
	if ecs, _ := ecsFromMsg(dctx.Req); ecs != nil {
		if ones, _ := ecs.Mask.Size(); ones != 0 {
			dctx.ReqECS = ecs

			log.Debug("dnsproxy: passing through ecs: %s", dctx.ReqECS)

			return
		}
	}

	// Set ECS.
	if cliIP == nil {
		cliIP = dctx.Addr.Addr().AsSlice()
	}

	if !netutil.IsSpecialPurpose(cliIP) {
		// A Stub Resolver MUST set SCOPE PREFIX-LENGTH to 0.  See RFC 7871
		// Section 6.
		dctx.ReqECS = setECS(dctx.Req, cliIP, 0)

		log.Debug("dnsproxy: setting ecs: %s", dctx.ReqECS)
	}
}

// newDNSContext returns a new properly initialized *DNSContext.
func (p *Proxy) newDNSContext(proto Proto, req *dns.Msg) (d *DNSContext) {
	return &DNSContext{
		Proto: proto,
		Req:   req,

		RequestID: atomic.AddUint64(&p.counter, 1),
	}
}
