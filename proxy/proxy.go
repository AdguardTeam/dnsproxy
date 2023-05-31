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
type Proxy struct {
	// counter is the counter of messages.  It must only be incremented
	// atomically, so it must be the first member of the struct to make sure
	// that it has a 64-bit alignment.
	//
	// See https://golang.org/pkg/sync/atomic/#pkg-note-BUG.
	counter uint64

	started bool // Started flag

	// Listeners
	// --

	udpListen         []*net.UDPConn       // UDP listen connections
	tcpListen         []net.Listener       // TCP listeners
	tlsListen         []net.Listener       // TLS listeners
	quicListen        []quic.EarlyListener // QUIC listeners
	httpsListen       []net.Listener       // HTTPS listeners
	httpsServer       *http.Server         // HTTPS server instance
	h3Listen          []quic.EarlyListener // HTTP/3 listeners
	h3Server          *http3.Server        // HTTP/3 server instance
	dnsCryptUDPListen []*net.UDPConn       // UDP listen connections for DNSCrypt
	dnsCryptTCPListen []net.Listener       // TCP listeners for DNSCrypt
	dnsCryptServer    *dnscrypt.Server     // DNSCrypt server instance

	// Upstream
	// --

	upstreamRttStats map[string]int // Map of upstream addresses and their rtt. Used to sort upstreams "from fast to slow"
	rttLock          sync.Mutex     // Synchronizes access to the upstreamRttStats map

	// DNS64 (in case dnsproxy works in a NAT64/DNS64 network)
	// --

	// dns64Prefs is a set of NAT64 prefixes that are used to detect and
	// construct DNS64 responses.  The DNS64 function is disabled if it is
	// empty.
	dns64Prefs []netip.Prefix

	// Ratelimit
	// --

	ratelimitBuckets *gocache.Cache // where the ratelimiters are stored, per IP
	ratelimitLock    sync.Mutex     // Synchronizes access to ratelimitBuckets

	// proxyVerifier checks if the proxy is in the trusted list.
	proxyVerifier netutil.SubnetSet

	// DNS cache
	// --

	// cache is used to cache requests.  It is disabled if nil.
	cache *cache
	// shortFlighter is used to resolve the expired cached requests without
	// repetitions.
	shortFlighter *optimisticResolver

	// FastestAddr module
	// --

	fastestAddr *fastip.FastestAddr // fastest-addr module

	// Other
	// --

	bytesPool    *sync.Pool // bytes pool to avoid unnecessary allocations when reading DNS packets
	udpOOBSize   int        // size for received OOB data
	sync.RWMutex            // protects parallel access to proxy structures

	// requestGoroutinesSema limits the number of simultaneous requests.
	//
	// TODO(a.garipov): Currently we have to pass this exact semaphore to
	// the workers, to prevent races on restart.  In the future we will need
	// a better restarting mechanism that completely prevents such invalid
	// states.
	//
	// See also: https://github.com/AdguardTeam/AdGuardHome/issues/2242.
	requestGoroutinesSema semaphore

	Config // proxy configuration
}

// Init populates fields of p but does not start listeners.
func (p *Proxy) Init() (err error) {
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

	return nil
}

// Start initializes the proxy server and starts listening
func (p *Proxy) Start() (err error) {
	log.Info("dnsproxy: starting dns proxy server")

	p.Lock()
	defer p.Unlock()

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

	if p.UpstreamConfig != nil {
		errs = closeAll(errs, p.UpstreamConfig)
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
// configured ones.  It returns false, if no upstreams are available for current
// request.
func (p *Proxy) selectUpstreams(d *DNSContext) (upstreams []upstream.Upstream, ok bool) {
	host := d.Req.Question[0].Name
	if p.needsLocalUpstream(d.Req) {
		if p.PrivateRDNSUpstreamConfig == nil {
			return nil, false
		}

		ip, _ := netutil.IPAndPortFromAddr(d.Addr)
		// TODO(e.burkov):  Detect against the actual configured subnet set.
		// Perhaps, even much earlier.
		if !netutil.IsLocallyServed(ip) {
			return nil, false
		}

		return p.PrivateRDNSUpstreamConfig.getUpstreamsForDomain(host), true
	}

	if d.CustomUpstreamConfig != nil {
		upstreams = d.CustomUpstreamConfig.getUpstreamsForDomain(host)
	}

	if upstreams != nil {
		return upstreams, true
	}

	return p.UpstreamConfig.getUpstreamsForDomain(host), true
}

// replyFromUpstream tries to resolve the request.
func (p *Proxy) replyFromUpstream(d *DNSContext) (ok bool, err error) {
	req := d.Req

	upstreams, ok := p.selectUpstreams(d)
	if !ok {
		return false, upstream.ErrNoUpstreams
	}

	start := time.Now()

	// Perform the DNS request.
	var reply *dns.Msg
	var u upstream.Upstream
	reply, u, err = p.exchange(req, upstreams)
	if dns64Ups := p.performDNS64(req, reply, upstreams); dns64Ups != nil {
		u = dns64Ups
	} else if p.isBogusNXDomain(reply) {
		log.Tracef("response ip is contained in bogus-nxdomain list")
		reply = p.genWithRCode(req, dns.RcodeNameError)
	}

	log.Tracef("RTT: %s", time.Since(start))

	if err != nil && p.Fallbacks != nil {
		log.Tracef("using the fallback upstream due to %s", err)

		reply, u, err = upstream.ExchangeParallel(p.Fallbacks, req)
	}

	if ok = reply != nil; ok {
		// This branch handles the successfully exchanged response.

		// Set upstream that have resolved the request to DNSContext.
		d.Upstream = u
		p.setMinMaxTTL(reply)

		// Explicitly construct the question section since some upstreams may
		// respond with invalidly constructed messages which cause out-of-range
		// panics afterwards.
		//
		// See https://github.com/AdguardTeam/AdGuardHome/issues/3551.
		if len(req.Question) > 0 && len(reply.Question) == 0 {
			reply.Question = []dns.Question{req.Question[0]}
		}
	} else {
		reply = p.genServerFailure(req)
		d.hasEDNS0 = false
	}
	d.Res = reply

	return ok, err
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

	// Use cache only if it's enabled and the query doesn't use custom upstream.
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
	case dctx.CustomUpstreamConfig != nil:
		// See https://github.com/AdguardTeam/dnsproxy/issues/169.
		reason = "custom upstreams used"
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
		cliIP, _ = netutil.IPAndPortFromAddr(dctx.Addr)
		if cliIP == nil {
			return
		}
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
		Proto:     proto,
		Req:       req,
		StartTime: time.Now(),

		RequestID: atomic.AddUint64(&p.counter, 1),
	}
}
