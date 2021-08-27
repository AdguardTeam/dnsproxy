// Package proxy implements a DNS proxy that supports all known DNS
// encryption protocols.
package proxy

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/dnsproxy/fastip"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/joomcode/errorx"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	gocache "github.com/patrickmn/go-cache"
	"golang.org/x/net/http2"
)

const (
	defaultTimeout   = 10 * time.Second
	minDNSPacketSize = 12 + 5

	ednsCSDefaultNetmaskV4 = 24  // default network mask for IPv4 address for EDNS ClientSubnet option
	ednsCSDefaultNetmaskV6 = 112 // default network mask for IPv6 address for EDNS ClientSubnet option
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

	udpListen         []*net.UDPConn   // UDP listen connections
	tcpListen         []net.Listener   // TCP listeners
	tlsListen         []net.Listener   // TLS listeners
	quicListen        []quic.Listener  // QUIC listeners
	httpsListen       []net.Listener   // HTTPS listeners
	httpsServer       []*http.Server   // HTTPS server instance
	dnsCryptUDPListen []*net.UDPConn   // UDP listen connections for DNSCrypt
	dnsCryptTCPListen []net.Listener   // TCP listeners for DNSCrypt
	dnsCryptServer    *dnscrypt.Server // DNSCrypt server instance

	// Upstream
	// --

	upstreamRttStats map[string]int // Map of upstream addresses and their rtt. Used to sort upstreams "from fast to slow"
	rttLock          sync.Mutex     // Synchronizes access to the upstreamRttStats map

	// DNS64 (in case dnsproxy works in a NAT64/DNS64 network)
	// --

	nat64Prefix     []byte     // NAT 64 prefix
	nat64PrefixLock sync.Mutex // Prefix lock

	// Ratelimit
	// --

	ratelimitBuckets *gocache.Cache // where the ratelimiters are stored, per IP
	ratelimitLock    sync.Mutex     // Synchronizes access to ratelimitBuckets

	// proxyVerifier checks if the proxy is in the trusted list.
	proxyVerifier *subnetDetector

	// DNS cache
	// --

	// cache is used to cache requests.  It is disabled if nil.
	cache *cache
	// shortFlighter is used to resolve the expired cached requests without
	// repetitions.
	shortFlighter *optimisticResolver
	// shortFlighterWithSubnet is used to resolve the expired cached
	// requests making sure that only one request for each cache item is
	// performed at a time.
	shortFlighterWithSubnet *optimisticResolver

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

// Init - initializes the proxy structures but does not start it
func (p *Proxy) Init() (err error) {
	p.initCache()

	if p.TLSConfig != nil && len(p.TLSConfig.NextProtos) == 0 {
		p.TLSConfig.NextProtos = append([]string{
			"http/1.1", http2.NextProtoTLS, NextProtoDQ,
		}, compatProtoDQ...)
	}

	if p.MaxGoroutines > 0 {
		log.Info("MaxGoroutines is set to %d", p.MaxGoroutines)

		p.requestGoroutinesSema, err = newChanSemaphore(p.MaxGoroutines)
		if err != nil {
			return fmt.Errorf("can't init semaphore: %w", err)
		}
	} else {
		p.requestGoroutinesSema = newNoopSemaphore()
	}

	if p.DNSCryptResolverCert != nil && p.DNSCryptProviderName != "" {
		log.Info("Initializing DNSCrypt: %s", p.DNSCryptProviderName)
		p.dnsCryptServer = &dnscrypt.Server{
			ProviderName: p.DNSCryptProviderName,
			ResolverCert: p.DNSCryptResolverCert,
			Handler: &dnsCryptHandler{
				proxy: p,

				requestGoroutinesSema: p.requestGoroutinesSema,
			},
		}
	}

	p.udpOOBSize = proxyutil.UDPGetOOBSize()
	p.bytesPool = &sync.Pool{
		New: func() interface{} {
			// 2 bytes may be used to store packet length (see TCP/TLS)
			b := make([]byte, 2+dns.MaxMsgSize)

			return &b
		},
	}

	if p.UpstreamMode == UModeFastestAddr {
		log.Printf("Fastest IP is enabled")
		p.fastestAddr = fastip.NewFastestAddr()
		if timeout := p.FastestPingTimeout; timeout > 0 {
			p.fastestAddr.PingWaitTimeout = timeout
		}
	}

	p.proxyVerifier, err = newSubnetDetector(p.TrustedProxies)
	if err != nil {
		return fmt.Errorf("initializing subnet detector for proxies verifying: %w", err)
	}

	return nil
}

// Start initializes the proxy server and starts listening
func (p *Proxy) Start() (err error) {
	p.Lock()
	defer p.Unlock()

	log.Info("Starting the DNS proxy server")
	err = p.validateConfig()
	if err != nil {
		return err
	}

	err = p.Init()
	if err != nil {
		return err
	}

	err = p.startListeners()
	if err != nil {
		return err
	}

	p.started = true
	return nil
}

// Stop stops the proxy server including all its listeners
func (p *Proxy) Stop() error {
	log.Info("Stopping the DNS proxy server")

	p.Lock()
	defer p.Unlock()
	if !p.started {
		log.Info("The DNS proxy server is not started")
		return nil
	}

	errs := []error{}

	for _, l := range p.tcpListen {
		err := l.Close()
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close TCP listening socket"))
		}
	}
	p.tcpListen = nil

	for _, l := range p.udpListen {
		err := l.Close()
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close UDP listening socket"))
		}
	}
	p.udpListen = nil

	for _, l := range p.tlsListen {
		err := l.Close()
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close TLS listening socket"))
		}
	}
	p.tlsListen = nil

	for _, srv := range p.httpsServer {
		err := srv.Close()
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close HTTPS server"))
		}
	}
	p.httpsListen = nil
	p.httpsServer = nil

	for _, l := range p.quicListen {
		err := l.Close()
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close QUIC listener"))
		}
	}
	p.quicListen = nil

	for _, l := range p.dnsCryptUDPListen {
		err := l.Close()
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close DNSCrypt UDP listening socket"))
		}
	}
	p.dnsCryptUDPListen = nil

	for _, l := range p.dnsCryptTCPListen {
		err := l.Close()
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close DNCrypt TCP listening socket"))
		}
	}
	p.dnsCryptTCPListen = nil

	p.started = false
	log.Println("Stopped the DNS proxy server")
	if len(errs) != 0 {
		return errorx.DecorateMany("Failed to stop DNS proxy server", errs...)
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

// replyFromUpstream tries to resolve the request and caches it if cacheWorks is
// true.
func (p *Proxy) replyFromUpstream(d *DNSContext) (ok bool, err error) {
	req := d.Req
	host := req.Question[0].Name
	var upstreams []upstream.Upstream
	// Get custom upstreams first.  Note that they might be empty.
	if d.CustomUpstreamConfig != nil {
		upstreams = d.CustomUpstreamConfig.getUpstreamsForDomain(host)
	}
	// If nothing is found in the custom upstreams, start using the default
	// ones.
	if upstreams == nil {
		upstreams = p.UpstreamConfig.getUpstreamsForDomain(host)
	}

	start := time.Now()

	// Perform the DNS request.
	var reply *dns.Msg
	var u upstream.Upstream
	reply, u, err = p.exchange(req, upstreams)
	if p.isNAT64PrefixAvailable() && p.isEmptyAAAAResponse(reply, req) {
		log.Tracef("Received an empty AAAA response, checking DNS64")
		reply, u, err = p.checkDNS64(req, reply, upstreams)
	} else if p.isBogusNXDomain(reply) {
		log.Tracef("Received IP from the bogus-nxdomain list, replacing response")
		reply = p.genWithRCode(reply, dns.RcodeNameError)
	}

	log.Tracef("RTT: %s", time.Since(start))

	if err != nil && p.Fallbacks != nil {
		log.Tracef("Using the fallback upstream due to %s", err)

		reply, u, err = upstream.ExchangeParallel(p.Fallbacks, req)
	}

	if reply != nil {
		// This branch handles the successfully exchanged response.

		// Set upstream that have resolved the request to DNSContext.
		d.Upstream = u
		p.setMinMaxTTL(reply)
		ok = true
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
func (p *Proxy) Resolve(d *DNSContext) (err error) {
	if p.Config.EnableEDNSClientSubnet {
		p.processECS(d)
	}

	d.calcFlagsAndSize()

	// Use cache only if it's enabled and the query doesn't use custom
	// upstreams.
	cacheWorks := p.cache != nil && d.CustomUpstreamConfig == nil
	if cacheWorks {
		if p.replyFromCache(d) {
			// Complete the response from cache.
			d.scrub()

			return nil
		}

		// On cache miss request for DNSSEC from the upstream to cache
		// it afterwards.
		addDO(d.Req)
	}

	var ok bool
	ok, err = p.replyFromUpstream(d)

	if cacheWorks && ok {
		// Cache the response with DNSSEC RRs.
		p.setInCache(d)
	}

	filterMsg(d.Res, d.Res, d.adBit, d.doBit, 0)

	// Complete the response.
	d.scrub()

	if p.ResponseHandler != nil {
		p.ResponseHandler(d, err)
	}

	return err
}

// Set EDNS Client-Subnet data in DNS request
func (p *Proxy) processECS(d *DNSContext) {
	d.ecsReqIP = nil
	d.ecsReqMask = uint8(0)

	ip, mask, _ := parseECS(d.Req)
	if mask == 0 {
		// Set EDNS Client-Subnet data
		var clientIP net.IP
		if p.Config.EDNSAddr != nil {
			clientIP = p.Config.EDNSAddr
		} else {
			switch addr := d.Addr.(type) {
			case *net.UDPAddr:
				clientIP = addr.IP
			case *net.TCPAddr:
				clientIP = addr.IP
			}
		}

		if clientIP != nil && isPublicIP(clientIP) {
			ip, mask = setECS(d.Req, clientIP, 0)
			log.Debug("Set ECS data: %s/%d", ip, mask)
		}
	} else {
		log.Debug("Passing through ECS data: %s/%d", ip, mask)
	}

	d.ecsReqIP = ip
	d.ecsReqMask = mask
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
