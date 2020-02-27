// Package proxy implements a DNS proxy that supports all known DNS encryption protocols
package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/utils"
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

	Config // proxy configuration

	maxGoroutines chan bool // limits the number of parallel queries. if nil, there's no limit
	sync.RWMutex            // protects parallel access to proxy structures
}

// Config contains all the fields necessary for proxy configuration
type Config struct {
	UDPListenAddr *net.UDPAddr // if nil, then it does not listen for UDP
	TCPListenAddr *net.TCPAddr // if nil, then it does not listen for TCP

	HTTPSListenAddr *net.TCPAddr // if nil, then it does not listen for HTTPS (DoH)
	TLSListenAddr   *net.TCPAddr // if nil, then it does not listen for TLS (DoT)
	TLSConfig       *tls.Config  // necessary for listening for TLS

	Ratelimit          int      // max number of requests per second from a given IP (0 to disable)
	RatelimitWhitelist []string // a list of whitelisted client IP addresses

	RefuseAny  bool // if true, refuse ANY requests
	AllServers bool // if true, parallel queries to all configured upstream servers are enabled

	// Enable EDNS Client Subnet option
	// DNS requests to the upstream server will contain an OPT record with Client Subnet option.
	//  If the original request already has this option set, we pass it through as is.
	//  Otherwise, we set it ourselves using the client IP with subnet /24 (for IPv4) and /112 (for IPv6).
	//
	// If the upstream server supports ECS, it sets subnet number in the response.
	// This subnet number along with the client IP and other data is used as a cache key.
	// Next time, if a client from the same subnet requests this host name,
	//  we get the response from cache.
	// If another client from a different subnet requests this host name,
	//  we pass his request to the upstream server.
	//
	// If the upstream server doesn't support ECS (there's no subnet number in response),
	//  this response will be cached for all clients.
	//
	// If client IP is private (i.e. not public), we don't add EDNS record into a request.
	// And so there will be no EDNS record in response either.
	// We store these responses in general cache (without subnet)
	//  so they will never be used for clients with public IP addresses.
	EnableEDNSClientSubnet bool
	EDNSAddr               net.IP // ECS IP used in request

	CacheEnabled   bool   // cache status
	CacheSizeBytes int    // Cache size (in bytes). Default: 64k
	CacheMinTTL    uint32 // Minimum TTL for DNS entries (in seconds).
	CacheMaxTTL    uint32 // Maximum TTL for DNS entries (in seconds).

	Upstreams []upstream.Upstream // list of upstreams
	Fallbacks []upstream.Upstream // list of fallback resolvers (which will be used if regular upstream failed to answer)

	BeforeRequestHandler BeforeRequestHandler // callback that is called before each request
	RequestHandler       RequestHandler       // callback that can handle incoming DNS requests
	ResponseHandler      ResponseHandler      // response callback

	DomainsReservedUpstreams map[string][]upstream.Upstream // map of domains and lists of corresponding upstreams

	MaxGoroutines int // maximum number of goroutines processing the DNS requests (important for mobile)
}

// DNSContext represents a DNS request message context
type DNSContext struct {
	Proto              string              // "udp", "tcp", "tls", "https"
	Req                *dns.Msg            // DNS request
	Res                *dns.Msg            // DNS response from an upstream
	Conn               net.Conn            // underlying client connection. Can be null in the case of DOH.
	Addr               net.Addr            // client address.
	HTTPRequest        *http.Request       // HTTP request (for DOH only)
	HTTPResponseWriter http.ResponseWriter // HTTP response writer (for DOH only)
	StartTime          time.Time           // processing start time
	Upstream           upstream.Upstream   // upstream that resolved DNS request

	// Upstream servers to use for this request
	// If set, Resolve() uses it instead of default servers
	Upstreams []upstream.Upstream

	ecsReqIP   net.IP // ECS IP used in request
	ecsReqMask uint8  // ECS mask used in request
}

// UpstreamConfig is a wrapper for list of default upstreams and map of reserved domains and corresponding upstreams
type UpstreamConfig struct {
	Upstreams               []upstream.Upstream            // list of default upstreams
	DomainReservedUpstreams map[string][]upstream.Upstream // map of reserved domains and lists of corresponding upstreams
}

// ParseUpstreamsConfig returns UpstreamConfig and error if upstreams configuration is invalid
// default upstream syntax: <upstreamString>
// reserved upstream syntax: [/domain1/../domainN/]<upstreamString>
// More specific domains take priority over less specific domains,
// To exclude more specific domains from reserved upstreams querying you should use the following syntax: [/domain1/../domainN/]#
// So the following config: ["[/host.com/]1.2.3.4", "[/www.host.com/]2.3.4.5", "[/maps.host.com/]#", "3.4.5.6"]
// will send queries for *.host.com to 1.2.3.4, except for *.www.host.com, which will go to 2.3.4.5 and *.maps.host.com,
// which will go to default server 3.4.5.6 with all other domains
func ParseUpstreamsConfig(upstreamConfig, bootstrapDNS []string, timeout time.Duration) (UpstreamConfig, error) {
	return ParseUpstreamsConfigEx(upstreamConfig, bootstrapDNS, timeout, func(address string, opts upstream.Options) (upstream.Upstream, error) {
		return upstream.AddressToUpstream(address, opts)
	})
}

// AddressToUpstreamFunction is a type for a callback function which creates an upstream object
type AddressToUpstreamFunction func(address string, opts upstream.Options) (upstream.Upstream, error)

// ParseUpstreamsConfigEx is an extended version of ParseUpstreamsConfig() which has a custom callback function which creates an upstream object
func ParseUpstreamsConfigEx(upstreamConfig, bootstrapDNS []string, timeout time.Duration, addressToUpstreamFunction AddressToUpstreamFunction) (UpstreamConfig, error) {
	upstreams := []upstream.Upstream{}
	domainReservedUpstreams := map[string][]upstream.Upstream{}

	for i, u := range upstreamConfig {
		hosts := []string{}
		if strings.HasPrefix(u, "[/") {
			// split domains and upstream string
			domainsAndUpstream := strings.Split(strings.TrimPrefix(u, "[/"), "/]")
			if len(domainsAndUpstream) != 2 {
				return UpstreamConfig{}, fmt.Errorf("wrong upstream specification: %s", u)
			}

			// split domains list
			for _, host := range strings.Split(domainsAndUpstream[0], "/") {
				if host != "" {
					if err := utils.IsValidHostname(host); err != nil {
						return UpstreamConfig{}, err
					}
					hosts = append(hosts, strings.ToLower(host+"."))
				} else {
					// empty domain specification means `unqualified names only`
					hosts = append(hosts, UnqualifiedNames)
				}
			}
			u = domainsAndUpstream[1]
		}

		// # excludes more specific domain from reserved upstreams querying
		if u == "#" && len(hosts) > 0 {
			for _, host := range hosts {
				domainReservedUpstreams[host] = nil
			}
			continue
		}

		// create an upstream
		dnsUpstream, err := addressToUpstreamFunction(u, upstream.Options{Bootstrap: bootstrapDNS, Timeout: timeout})
		if err != nil {
			return UpstreamConfig{}, fmt.Errorf("cannot prepare the upstream %s (%s): %s", u, bootstrapDNS, err)
		}

		if len(hosts) > 0 {
			for _, host := range hosts {
				_, ok := domainReservedUpstreams[host]
				if !ok {
					domainReservedUpstreams[host] = []upstream.Upstream{}
				}
				domainReservedUpstreams[host] = append(domainReservedUpstreams[host], dnsUpstream)
			}
			log.Printf("Upstream %d: %s is reserved for next domains: %s", i, dnsUpstream.Address(), strings.Join(hosts, ", "))
		} else {
			log.Printf("Upstream %d: %s", i, dnsUpstream.Address())
			upstreams = append(upstreams, dnsUpstream)
		}
	}
	return UpstreamConfig{Upstreams: upstreams, DomainReservedUpstreams: domainReservedUpstreams}, nil
}

// Init - initializes the proxy structures but does not start it
func (p *Proxy) Init() {
	if p.CacheEnabled {
		log.Printf("DNS cache is enabled")

		p.cache = &cache{cacheSize: p.CacheSizeBytes,
			cacheMinTTL: p.CacheMinTTL,
			cacheMaxTTL: p.CacheMaxTTL}

		if p.Config.EnableEDNSClientSubnet {
			p.cacheSubnet = &cacheSubnet{cacheSize: p.CacheSizeBytes}
		}
	}

	if p.MaxGoroutines > 0 {
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

// getUpstreamsForDomain looks for a domain in reserved domains map and returns a list of corresponding upstreams.
// returns default upstreams list if domain isn't found. More specific domains take priority over less specific domains.
// For example, map contains the following keys: host.com and www.host.com
// If we are looking for domain mail.host.com, this method will return value of host.com key
// If we are looking for domain www.host.com, this method will return value of www.host.com key
// If more specific domain value is nil, it means that domain was excluded and should be exchanged with default upstreams
func (p *Proxy) getUpstreamsForDomain(host string) []upstream.Upstream {
	if len(p.DomainsReservedUpstreams) == 0 {
		return p.Upstreams
	}

	dotsCount := strings.Count(host, ".")
	if dotsCount < 2 {
		return p.DomainsReservedUpstreams[UnqualifiedNames]
	}

	for i := 1; i <= dotsCount; i++ {
		h := strings.SplitAfterN(host, ".", i)
		name := h[i-1]
		if u, ok := p.DomainsReservedUpstreams[strings.ToLower(name)]; ok {
			if u == nil {
				// domain was excluded from reserved upstreams querying
				return p.Upstreams
			}
			return u
		}
	}

	return p.Upstreams
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

// Resolve is the default resolving method used by the DNS proxy to query upstreams
func (p *Proxy) Resolve(d *DNSContext) error {
	if p.Config.EnableEDNSClientSubnet {
		p.processECS(d)
	}

	if p.replyFromCache(d) {
		return nil
	}

	// Get custom upstreams first -- note that they might be empty
	upstreams := d.Upstreams
	if len(upstreams) == 0 {
		// get upstreams for the specified hostname
		upstreams = p.getUpstreamsForDomain(d.Req.Question[0].Name)
	}

	// execute the DNS request
	startTime := time.Now()
	reply, u, err := p.exchange(d.Req, upstreams)
	if p.isEmptyAAAAResponse(reply, d.Req) {
		reply, u, err = p.checkDNS64(d.Req, reply, upstreams)
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

func (p *Proxy) exchange(req *dns.Msg, upstreams []upstream.Upstream) (reply *dns.Msg, u upstream.Upstream, err error) {
	if p.AllServers {
		reply, u, err = upstream.ExchangeParallel(upstreams, req)
		return
	}

	if len(upstreams) == 1 {
		u = upstreams[0]
		reply, _, err = exchangeWithUpstream(u, req)
		return
	}

	// sort upstreams by rtt from fast to slow
	sortedUpstreams := p.getSortedUpstreams(upstreams)

	errs := []error{}
	for _, dnsUpstream := range sortedUpstreams {
		reply, elapsed, err := exchangeWithUpstream(dnsUpstream, req)
		if err == nil {
			p.updateRtt(dnsUpstream.Address(), elapsed)
			return reply, dnsUpstream, err
		}
		errs = append(errs, err)
		p.updateRtt(dnsUpstream.Address(), int(defaultTimeout/time.Millisecond))
	}
	return nil, nil, errorx.DecorateMany("all upstreams failed to exchange request", errs...)
}

func (p *Proxy) getSortedUpstreams(u []upstream.Upstream) []upstream.Upstream {
	// clone upstreams list to avoid race conditions
	p.rttLock.Lock()
	clone := make([]upstream.Upstream, len(u))
	copy(clone, u)

	sort.Slice(clone, func(i, j int) bool {
		if p.upstreamRttStats[clone[i].Address()] < p.upstreamRttStats[clone[j].Address()] {
			return true
		}
		return false
	})
	p.rttLock.Unlock()

	return clone
}

// exchangeWithUpstream returns result of Exchange with elapsed time
func exchangeWithUpstream(u upstream.Upstream, req *dns.Msg) (*dns.Msg, int, error) {
	startTime := time.Now()
	reply, err := u.Exchange(req)
	elapsed := int(time.Since(startTime) / time.Millisecond)
	if err != nil {
		log.Tracef("upstream %s failed to exchange %s in %d milliseconds. Cause: %s", u.Address(), req.Question[0].String(), elapsed, err)
	} else {
		log.Tracef("upstream %s successfully finished exchange of %s. Elapsed %d ms.", u.Address(), req.Question[0].String(), elapsed)
	}
	return reply, elapsed, err
}

// updateRtt updates rtt in upstreamRttStats for given address
func (p *Proxy) updateRtt(address string, rtt int) {
	p.rttLock.Lock()
	if p.upstreamRttStats == nil {
		p.upstreamRttStats = map[string]int{}
	}
	p.upstreamRttStats[address] = (p.upstreamRttStats[address] + rtt) / 2
	p.rttLock.Unlock()
}

// validateConfig verifies that the supplied configuration is valid and returns an error if it's not
func (p *Proxy) validateConfig() error {
	if p.started {
		return errors.New("server has been already started")
	}

	if p.UDPListenAddr == nil && p.TCPListenAddr == nil && p.TLSListenAddr == nil && p.HTTPSListenAddr == nil {
		return errors.New("no listen address specified")
	}

	if p.TLSListenAddr != nil && p.TLSConfig == nil {
		return errors.New("cannot create a TLS listener without TLS config")
	}

	if p.HTTPSListenAddr != nil && p.TLSConfig == nil {
		return errors.New("cannot create an HTTPS listener without TLS config")
	}

	if len(p.Upstreams) == 0 {
		if len(p.DomainsReservedUpstreams) == 0 {
			return errors.New("no upstreams specified")
		}
		return errors.New("no default upstreams specified")
	}

	if p.Ratelimit > 0 {
		log.Printf("Ratelimit is enabled and set to %d rps", p.Ratelimit)
	}

	if p.RefuseAny {
		log.Print("The server is configured to refuse ANY requests")
	}

	return nil
}

// startListeners configures and starts listener loops
func (p *Proxy) startListeners() error {
	if p.UDPListenAddr != nil {
		log.Printf("Creating the UDP server socket")
		udpAddr := p.UDPListenAddr
		udpListen, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return errorx.Decorate(err, "couldn't listen to UDP socket")
		}
		p.udpListen = udpListen
		log.Printf("Listening to udp://%s", p.udpListen.LocalAddr())
	}

	if p.TCPListenAddr != nil {
		log.Printf("Creating the TCP server socket")
		tcpAddr := p.TCPListenAddr
		tcpListen, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return errorx.Decorate(err, "couldn't listen to TCP socket")
		}
		p.tcpListen = tcpListen
		log.Printf("Listening to tcp://%s", p.tcpListen.Addr())
	}

	if p.TLSListenAddr != nil {
		log.Printf("Creating the TLS server socket")
		tlsAddr := p.TLSListenAddr
		tcpListen, err := net.ListenTCP("tcp", tlsAddr)
		if err != nil {
			return errorx.Decorate(err, "could not start TLS listener")
		}
		p.tlsListen = tls.NewListener(tcpListen, p.TLSConfig)
		log.Printf("Listening to tls://%s", p.tlsListen.Addr())
	}

	if p.HTTPSListenAddr != nil {
		log.Printf("Creating the HTTPS server")
		tcpListen, err := net.ListenTCP("tcp", p.HTTPSListenAddr)
		if err != nil {
			return errorx.Decorate(err, "could not start HTTPS listener")
		}
		p.httpsListen = tls.NewListener(tcpListen, p.TLSConfig)
		log.Printf("Listening to https://%s", p.httpsListen.Addr())
		p.httpsServer = &http.Server{
			Handler:           p,
			ReadHeaderTimeout: defaultTimeout,
			WriteTimeout:      defaultTimeout,
		}
	}

	if p.udpListen != nil {
		go p.udpPacketLoop(p.udpListen)
	}

	if p.tcpListen != nil {
		go p.tcpPacketLoop(p.tcpListen, ProtoTCP)
	}

	if p.tlsListen != nil {
		go p.tcpPacketLoop(p.tlsListen, ProtoTLS)
	}

	if p.httpsListen != nil {
		go p.listenHTTPS()
	}

	return nil
}

// udpPacketLoop listens for incoming UDP packets
func (p *Proxy) udpPacketLoop(conn *net.UDPConn) {
	log.Printf("Entering the UDP listener loop on %s", conn.LocalAddr())
	b := make([]byte, dns.MaxMsgSize)
	for {
		p.RLock()
		if !p.started {
			return
		}
		p.RUnlock()

		n, addr, err := conn.ReadFrom(b)
		// documentation says to handle the packet even if err occurs, so do that first
		if n > 0 {
			// make a copy of all bytes because ReadFrom() will overwrite contents of b on next call
			// we need the contents to survive the call because we're handling them in goroutine
			packet := make([]byte, n)
			copy(packet, b)
			p.guardMaxGoroutines()
			go func() {
				p.handleUDPPacket(packet, addr, conn) // ignore errors
				p.freeMaxGoroutines()
			}()
		}
		if err != nil {
			if isConnClosed(err) {
				log.Printf("udpListen.ReadFrom() returned because we're reading from a closed connection, exiting loop")
				break
			}
			log.Printf("got error when reading from UDP listen: %s", err)
		}
	}
}

// handleUDPPacket processes the incoming UDP packet and sends a DNS response
func (p *Proxy) handleUDPPacket(packet []byte, addr net.Addr, conn *net.UDPConn) {
	log.Tracef("Start handling new UDP packet from %s", addr)

	msg := &dns.Msg{}
	err := msg.Unpack(packet)
	if err != nil {
		log.Printf("error handling UDP packet: %s", err)
		return
	}

	d := &DNSContext{
		Proto: "udp",
		Req:   msg,
		Addr:  addr,
		Conn:  conn,
	}

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
	}
}

// Writes a response to the UDP client
func (p *Proxy) respondUDP(d *DNSContext) error {
	resp := d.Res
	conn := d.Conn.(*net.UDPConn)

	bytes, err := resp.Pack()
	if err != nil {
		return errorx.Decorate(err, "couldn't convert message into wire format: %s", resp.String())
	}
	n, err := conn.WriteTo(bytes, d.Addr)
	if n == 0 && isConnClosed(err) {
		return err
	}
	if err != nil {
		return errorx.Decorate(err, "conn.WriteTo() returned error")
	}
	if n != len(bytes) {
		return fmt.Errorf("conn.WriteTo() returned with %d != %d", n, len(bytes))
	}
	return nil
}

// tcpPacketLoop listens for incoming TCP packets
// proto is either "tcp" or "tls"
func (p *Proxy) tcpPacketLoop(l net.Listener, proto string) {
	log.Printf("Entering the %s listener loop on %s", proto, l.Addr())
	for {
		clientConn, err := l.Accept()

		if err != nil {
			if isConnClosed(err) {
				log.Printf("tcpListen.Accept() returned because we're reading from a closed connection, exiting loop")
				break
			}
			log.Printf("got error when reading from TCP listen: %s", err)
		} else {
			p.guardMaxGoroutines()
			go func() {
				p.handleTCPConnection(clientConn, proto)
				p.freeMaxGoroutines()
			}()
		}
	}
}

// handleTCPConnection starts a loop that handles an incoming TCP connection
// proto is either "tcp" or "tls"
func (p *Proxy) handleTCPConnection(conn net.Conn, proto string) {
	log.Tracef("Start handling the new %s connection %s", proto, conn.RemoteAddr())
	defer conn.Close()

	for {
		p.RLock()
		if !p.started {
			return
		}
		p.RUnlock()

		conn.SetDeadline(time.Now().Add(defaultTimeout)) //nolint
		packet, err := readPrefixed(&conn)
		if err != nil {
			return
		}

		msg := &dns.Msg{}
		err = msg.Unpack(packet)
		if err != nil {
			log.Printf("error handling TCP packet: %s", err)
			return
		}

		d := &DNSContext{
			Proto: proto,
			Req:   msg,
			Addr:  conn.RemoteAddr(),
			Conn:  conn,
		}

		err = p.handleDNSRequest(d)
		if err != nil {
			log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
		}
	}
}

// Writes a response to the TCP (or TLS) client
func (p *Proxy) respondTCP(d *DNSContext) error {
	resp := d.Res
	conn := d.Conn

	bytes, err := resp.Pack()
	if err != nil {
		return errorx.Decorate(err, "couldn't convert message into wire format: %s", resp.String())
	}

	bytes, err = prefixWithSize(bytes)
	if err != nil {
		return errorx.Decorate(err, "couldn't add prefix with size")
	}

	n, err := conn.Write(bytes)
	if n == 0 && isConnClosed(err) {
		return err
	}
	if err != nil {
		return errorx.Decorate(err, "conn.Write() returned error")
	}
	if n != len(bytes) {
		return fmt.Errorf("conn.Write() returned with %d != %d", n, len(bytes))
	}
	return nil
}

// serveHttps starts the HTTPS server
func (p *Proxy) listenHTTPS() {
	log.Printf("Listening to DNS-over-HTTPS on %s", p.httpsListen.Addr())
	err := p.httpsServer.Serve(p.httpsListen)

	if err != http.ErrServerClosed {
		log.Printf("HTTPS server was closed unexpectedly: %s", err)
	} else {
		log.Printf("HTTPS server was closed")
	}
}

// ServeHTTP is the http.RequestHandler implementation that handles DOH queries
// Here is what it returns:
// http.StatusBadRequest - if there is no DNS request data
// http.StatusUnsupportedMediaType - if request content type is not application/dns-message
// http.StatusMethodNotAllowed - if request method is not GET or POST
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Tracef("Incoming HTTPS request on %s", r.URL)

	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if len(buf) == 0 || err != nil {
			log.Tracef("Cannot parse DNS request from %s", dnsParam)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			log.Tracef("Unsupported media type: %s", contentType)
			http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
			return
		}

		buf, err = ioutil.ReadAll(r.Body)
		if err != nil {
			log.Tracef("Cannot read the request body: %s", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
	default:
		log.Tracef("Wrong HTTP method: %s", r.Method)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	msg := new(dns.Msg)
	if err = msg.Unpack(buf); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	addr, _ := p.remoteAddr(r)

	d := &DNSContext{
		Proto:              ProtoHTTPS,
		Req:                msg,
		Addr:               addr,
		HTTPRequest:        r,
		HTTPResponseWriter: w,
	}

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
	}
}

// Get a client IP address from HTTP headers that proxy servers may set
func getIPFromHTTPRequest(r *http.Request) net.IP {
	names := []string{
		"CF-Connecting-IP", "True-Client-IP", // set by CloudFlare servers
		"X-Real-IP",
	}
	for _, name := range names {
		s := r.Header.Get(name)
		ip := net.ParseIP(s)
		if ip != nil {
			return ip
		}
	}

	s := r.Header.Get("X-Forwarded-For")
	s = splitNext(&s, ',') // get left-most IP address
	ip := net.ParseIP(s)
	if ip != nil {
		return ip
	}

	return nil
}

// Writes a response to the DOH client
func (p *Proxy) respondHTTPS(d *DNSContext) error {
	resp := d.Res
	w := d.HTTPResponseWriter

	bytes, err := resp.Pack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return errorx.Decorate(err, "couldn't convert message into wire format: %s", resp.String())
	}

	w.Header().Set("Server", "AdGuard DNS")
	w.Header().Set("Content-Type", "application/dns-message")
	_, err = w.Write(bytes)
	return err
}

func (p *Proxy) remoteAddr(r *http.Request) (net.Addr, error) {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, err
	}

	portValue, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}

	ip := getIPFromHTTPRequest(r)
	if ip != nil {
		log.Debug("Using IP address from HTTP request: %s", ip)
	} else {
		ip = net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", host)
		}
	}

	return &net.TCPAddr{IP: ip, Port: portValue}, nil
}

// guardMaxGoroutines makes sure that there are no more than p.MaxGoroutines parallel goroutines
func (p *Proxy) guardMaxGoroutines() {
	if p.maxGoroutines != nil {
		p.maxGoroutines <- true
	}
}

// freeMaxGoroutines allows other goroutines to do the job
func (p *Proxy) freeMaxGoroutines() {
	if p.maxGoroutines != nil {
		<-p.maxGoroutines
	}
}

// handleDNSRequest processes the incoming packet bytes and returns with an optional response packet.
func (p *Proxy) handleDNSRequest(d *DNSContext) error {
	d.StartTime = time.Now()
	p.logDNSMessage(d.Req)

	if p.BeforeRequestHandler != nil {
		ok, err := p.BeforeRequestHandler(p, d)
		if err != nil {
			log.Error("Error in the BeforeRequestHandler: %s", err)
			d.Res = p.genServerFailure(d.Req)
			p.respond(d)
			return nil
		}
		if !ok {
			return nil // do nothing, don't reply
		}
	}

	// ratelimit based on IP only, protects CPU cycles and outbound connections
	if d.Proto == ProtoUDP && p.isRatelimited(d.Addr) {
		log.Tracef("Ratelimiting %v based on IP only", d.Addr)
		return nil // do nothing, don't reply, we got ratelimited
	}

	if len(d.Req.Question) != 1 {
		log.Printf("got invalid number of questions: %v", len(d.Req.Question))
		d.Res = p.genServerFailure(d.Req)
	}

	// refuse ANY requests (anti-DDOS measure)
	if p.RefuseAny && len(d.Req.Question) > 0 && d.Req.Question[0].Qtype == dns.TypeANY {
		log.Tracef("Refusing type=ANY request")
		d.Res = p.genNotImpl(d.Req)
	}

	var err error

	if d.Res == nil {
		if len(p.Upstreams) == 0 {
			panic("SHOULD NOT HAPPEN: no default upstreams specified")
		}

		// execute the DNS request
		// if there is a custom middleware configured, use it
		if p.RequestHandler != nil {
			err = p.RequestHandler(p, d)
		} else {
			err = p.Resolve(d)
		}

		if err != nil {
			err = errorx.Decorate(err, "talking to dnsUpstream failed")
		}
	}

	p.logDNSMessage(d.Res)
	p.respond(d)
	return err
}

// respond writes the specified response to the client (or does nothing if d.Res is empty)
func (p *Proxy) respond(d *DNSContext) {
	if d.Res == nil {
		return
	}

	// d.Conn can be nil in the case of a DOH request
	if d.Conn != nil {
		d.Conn.SetWriteDeadline(time.Now().Add(defaultTimeout)) //nolint
	}

	var err error

	switch d.Proto {
	case ProtoUDP:
		err = p.respondUDP(d)
	case ProtoTCP:
		err = p.respondTCP(d)
	case ProtoTLS:
		err = p.respondTCP(d)
	case ProtoHTTPS:
		err = p.respondHTTPS(d)
	default:
		err = fmt.Errorf("SHOULD NOT HAPPEN - unknown protocol: %s", d.Proto)
	}

	if err != nil {
		if strings.HasSuffix(err.Error(), "use of closed network connection") {
			// This case may happen while we're restarting DNS server
			log.Debug("error while responding to a DNS request: %s", err)
		} else {
			log.Printf("error while responding to a DNS request: %s", err)
		}
	}
}

func (p *Proxy) genServerFailure(request *dns.Msg) *dns.Msg {
	resp := dns.Msg{}
	resp.SetRcode(request, dns.RcodeServerFailure)
	resp.RecursionAvailable = true
	return &resp
}

func (p *Proxy) genNotImpl(request *dns.Msg) *dns.Msg {
	resp := dns.Msg{}
	resp.SetRcode(request, dns.RcodeNotImplemented)
	resp.RecursionAvailable = true
	resp.SetEdns0(1452, false) // NOTIMPL without EDNS is treated as 'we don't support EDNS', so explicitly set it
	return &resp
}

func (p *Proxy) logDNSMessage(m *dns.Msg) {
	if m.Response {
		log.Tracef("OUT: %s", m)
	} else {
		log.Tracef("IN: %s", m)
	}
}
