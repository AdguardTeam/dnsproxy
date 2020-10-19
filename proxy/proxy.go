// Package proxy implements a DNS proxy that supports all known DNS encryption protocols
package proxy

import (
	"net"
	"net/http"
	"sync"
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

const (
	// ProtoUDP is plain DNS-over-UDP
	ProtoUDP = "udp"
	// ProtoTCP is plain DNS-over-TCP
	ProtoTCP = "tcp"
	// ProtoTLS is DNS-over-TLS
	ProtoTLS = "tls"
	// ProtoHTTPS is DNS-over-HTTPS
	ProtoHTTPS = "https"
	// ProtoQUIC is QUIC transport
	ProtoQUIC = "quic"
	// ProtoDNSCrypt is DNSCrypt
	ProtoDNSCrypt = "dnscrypt"
	// UnqualifiedNames is reserved name for "unqualified names only", ie names without dots
	UnqualifiedNames = "unqualified_names"
)

// Proxy combines the proxy server state and configuration
type Proxy struct {
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

	nat64Prefix []byte     // NAT 64 prefix
	nat64Lock   sync.Mutex // Prefix lock

	// Ratelimit
	// --

	ratelimitBuckets *gocache.Cache // where the ratelimiters are stored, per IP
	ratelimitLock    sync.Mutex     // Synchronizes access to ratelimitBuckets

	// DNS cache
	// --

	cache       *cache       // cache instance (nil if cache is disabled)
	cacheSubnet *cacheSubnet // cache instance (nil if cache is disabled)

	// FastestAddr module
	// --

	fastestAddr *fastip.FastestAddr // fastest-addr module

	// Other
	// --

	bytesPool     *sync.Pool // bytes pool to avoid unnecessary allocations when reading DNS packets
	udpOOBSize    int        // size for received OOB data
	maxGoroutines chan bool  // limits the number of parallel queries. if nil, there's no limit
	sync.RWMutex             // protects parallel access to proxy structures

	Config // proxy configuration
}

// Init - initializes the proxy structures but does not start it
func (p *Proxy) Init() {
	if p.CacheEnabled {
		log.Printf("DNS cache is enabled")

		p.cache = &cache{
			cacheSize: p.CacheSizeBytes,
		}

		if p.Config.EnableEDNSClientSubnet {
			p.cacheSubnet = &cacheSubnet{
				cacheSize: p.CacheSizeBytes,
			}
		}
	}

	if p.TLSConfig != nil && len(p.TLSConfig.NextProtos) == 0 {
		p.TLSConfig.NextProtos = []string{
			"http/1.1",
			http2.NextProtoTLS,
			NextProtoDQ,
		}
		p.TLSConfig.NextProtos = append(p.TLSConfig.NextProtos, compatProtoDQ...)
	}

	if p.DNSCryptResolverCert != nil && p.DNSCryptProviderName != "" {
		log.Info("Initializing DNSCrypt: %s", p.DNSCryptProviderName)
		p.dnsCryptServer = &dnscrypt.Server{
			ProviderName: p.DNSCryptProviderName,
			ResolverCert: p.DNSCryptResolverCert,
			Handler:      &dnsCryptHandler{proxy: p},
		}
	}

	p.udpOOBSize = proxyutil.UDPGetOOBSize()
	p.bytesPool = &sync.Pool{
		New: func() interface{} {
			// 2 bytes may be used to store packet length (see TCP/TLS)
			return make([]byte, 2+dns.MaxMsgSize)
		},
	}

	if p.UpstreamMode == UModeFastestAddr {
		log.Printf("Fastest IP is enabled")
		p.fastestAddr = fastip.NewFastestAddr()
	}

	if p.MaxGoroutines > 0 {
		log.Info("MaxGoroutines is set to %d", p.MaxGoroutines)
		p.maxGoroutines = make(chan bool, p.MaxGoroutines)
	} else {
		// nil means there's no limit
		p.maxGoroutines = nil
	}
}

// Start initializes the proxy server and starts listening
func (p *Proxy) Start() error {
	p.Lock()
	defer p.Unlock()

	log.Info("Starting the DNS proxy server")
	err := p.validateConfig()
	if err != nil {
		return err
	}

	// Init proxy
	p.Init()

	// Start listeners
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

	if p.maxGoroutines != nil {
		close(p.maxGoroutines)
	}

	p.started = false
	log.Println("Stopped the DNS proxy server")
	if len(errs) != 0 {
		return errorx.DecorateMany("Failed to stop DNS proxy server", errs...)
	}
	return nil
}

// Addrs returns all listen addresses for the specified proto or nil if the proxy does not listen to it.
// proto must be "tcp", "tls", "https", "quic", or "udp"
func (p *Proxy) Addrs(proto string) []net.Addr {
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
func (p *Proxy) Addr(proto string) net.Addr {
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

// Resolve is the default resolving method used by the DNS proxy to query upstreams
func (p *Proxy) Resolve(d *DNSContext) error {
	if p.Config.EnableEDNSClientSubnet {
		p.processECS(d)
	}

	if p.replyFromCache(d) {
		return nil
	}

	host := d.Req.Question[0].Name
	var upstreams []upstream.Upstream

	// Get custom upstreams first -- note that they might be empty
	if d.CustomUpstreamConfig != nil {
		upstreams = d.CustomUpstreamConfig.getUpstreamsForDomain(host)
	}

	// If nothing found in the custom upstreams, start using the default ones
	if upstreams == nil {
		upstreams = p.UpstreamConfig.getUpstreamsForDomain(host)
	}

	// execute the DNS request
	startTime := time.Now()
	reply, u, err := p.exchange(d.Req, upstreams)
	if p.isEmptyAAAAResponse(reply, d.Req) {
		log.Tracef("Received empty AAAA response, checking DNS64")
		reply, u, err = p.checkDNS64(d.Req, reply, upstreams)
	} else if p.isBogusNXDomain(reply) {
		log.Tracef("Received IP from the bogus-nxdomain list, replacing response")
		reply = p.genNXDomain(reply)
	}

	rtt := int(time.Since(startTime) / time.Millisecond)
	log.Tracef("RTT: %d ms", rtt)

	if err != nil && p.Fallbacks != nil {
		log.Tracef("Using the fallback upstream due to %s", err)
		reply, u, err = upstream.ExchangeParallel(p.Fallbacks, d.Req)
	}

	// set Upstream that resolved DNS request to DNSContext
	if reply != nil {
		d.Upstream = u

		p.setMinMaxTTL(reply)

		// Saving cached response
		p.setInCache(d, reply)
	}

	if reply == nil {
		d.Res = p.genServerFailure(d.Req)
	} else {
		d.Res = reply
	}

	// truncate and compress the response
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
