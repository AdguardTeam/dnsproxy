// Package proxy implements a DNS proxy that supports all known DNS encryption protocols
package proxy

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/fastip"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
	gocache "github.com/patrickmn/go-cache"
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
	// UnqualifiedNames is reserved name for "unqualified names only", ie names without dots
	UnqualifiedNames = "unqualified_names"
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

// Proxy combines the proxy server state and configuration
type Proxy struct {
	started     bool         // Started flag
	udpListen   *net.UDPConn // UDP listen connection
	tcpListen   net.Listener // TCP listener
	tlsListen   net.Listener // TLS listener
	httpsListen net.Listener // HTTPS listener
	httpsServer *http.Server // HTTPS server instance

	upstreamRttStats map[string]int // Map of upstream addresses and their rtt. Used to sort upstreams "from fast to slow"
	rttLock          sync.Mutex     // Synchronizes access to the upstreamRttStats map

	nat64Prefix []byte     // NAT 64 prefix
	nat64Lock   sync.Mutex // Prefix lock

	ratelimitBuckets *gocache.Cache // where the ratelimiters are stored, per IP
	ratelimitLock    sync.Mutex     // Synchronizes access to ratelimitBuckets

	cache       *cache       // cache instance (nil if cache is disabled)
	cacheSubnet *cacheSubnet // cache instance (nil if cache is disabled)

	fastestAddr *fastip.FastestAddr // fastest-addr module

	udpOOBSize int // size for received OOB data

	Config // proxy configuration

	maxGoroutines chan bool // limits the number of parallel queries. if nil, there's no limit
	sync.RWMutex            // protects parallel access to proxy structures
}

// DNSContext represents a DNS request message context
type DNSContext struct {
	Proto              string              // "udp", "tcp", "tls", "https"
	Req                *dns.Msg            // DNS request
	Res                *dns.Msg            // DNS response from an upstream
	Conn               net.Conn            // underlying client connection. Can be null in the case of DOH.
	Addr               net.Addr            // client address.
	localIP            net.IP              // local IP address (for UDP socket)
	HTTPRequest        *http.Request       // HTTP request (for DOH only)
	HTTPResponseWriter http.ResponseWriter // HTTP response writer (for DOH only)
	StartTime          time.Time           // processing start time
	Upstream           upstream.Upstream   // upstream that resolved DNS request

	// CustomUpstreamConfig -- custom upstream servers configuration
	// to use for this request only.
	// If set, Resolve() uses it instead of default servers
	CustomUpstreamConfig *UpstreamConfig

	ecsReqIP   net.IP // ECS IP used in request
	ecsReqMask uint8  // ECS mask used in request
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

	p.udpOOBSize = udpGetOOBSize()

	if p.FindFastestAddr {
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

	log.Println("Starting the DNS proxy server")
	err := p.validateConfig()
	if err != nil {
		return err
	}

	// Init cache
	p.Init()

	err = p.startListeners()
	if err != nil {
		return err
	}

	p.started = true
	return nil
}

// Stop stops the proxy server including all its listeners
func (p *Proxy) Stop() error {
	log.Println("Stopping the DNS proxy server")

	p.Lock()
	defer p.Unlock()
	if !p.started {
		log.Println("The DNS proxy server is not started")
		return nil
	}

	errs := []error{}

	if p.tcpListen != nil {
		err := p.tcpListen.Close()
		p.tcpListen = nil
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close TCP listening socket"))
		}
	}

	if p.udpListen != nil {
		err := p.udpListen.Close()
		p.udpListen = nil
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close UDP listening socket"))
		}
	}

	if p.tlsListen != nil {
		err := p.tlsListen.Close()
		p.tlsListen = nil
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close TLS listening socket"))
		}
	}

	if p.httpsServer != nil {
		err := p.httpsServer.Close()
		p.httpsListen = nil
		p.httpsServer = nil
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close HTTPS server"))
		}
	}

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

// Addr returns the listen address for the specified proto or null if the proxy does not listen to it
// proto must be "tcp", "tls", "https" or "udp"
func (p *Proxy) Addr(proto string) net.Addr {
	p.RLock()
	defer p.RUnlock()
	switch proto {
	case ProtoTCP:
		if p.tcpListen == nil {
			return nil
		}
		return p.tcpListen.Addr()
	case ProtoTLS:
		if p.tlsListen == nil {
			return nil
		}
		return p.tlsListen.Addr()
	case ProtoHTTPS:
		if p.httpsListen == nil {
			return nil
		}
		return p.httpsListen.Addr()
	case ProtoUDP:
		if p.udpListen == nil {
			return nil
		}
		return p.udpListen.LocalAddr()
	default:
		panic("proto must be 'tcp', 'tls', 'https' or 'udp'")
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
	d.Res.Compress = true // some devices require DNS message compression

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
