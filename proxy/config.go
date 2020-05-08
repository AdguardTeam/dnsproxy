package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/utils"

	"github.com/AdguardTeam/dnsproxy/upstream"
)

// Config contains all the fields necessary for proxy configuration
type Config struct {
	// Listeners
	// --

	UDPListenAddr   *net.UDPAddr // if nil, then it does not listen for UDP
	TCPListenAddr   *net.TCPAddr // if nil, then it does not listen for TCP
	HTTPSListenAddr *net.TCPAddr // if nil, then it does not listen for HTTPS (DoH)
	TLSListenAddr   *net.TCPAddr // if nil, then it does not listen for TLS (DoT)
	TLSConfig       *tls.Config  // necessary for listening for TLS

	// Rate-limiting and anti-DNS amplification measures
	// --

	Ratelimit          int      // max number of requests per second from a given IP (0 to disable)
	RatelimitWhitelist []string // a list of whitelisted client IP addresses
	RefuseAny          bool     // if true, refuse ANY requests

	// Upstream DNS servers and their settings
	// --

	Upstreams                []upstream.Upstream            // list of upstreams
	Fallbacks                []upstream.Upstream            // list of fallback resolvers (which will be used if regular upstream failed to answer)
	AllServers               bool                           // if true, parallel queries to all configured upstream servers are enabled
	DomainsReservedUpstreams map[string][]upstream.Upstream // map of domains and lists of corresponding upstreams
	FindFastestAddr          bool                           // use Fastest Address algorithm

	// BogusNXDomain - transforms responses that contain only given IP addresses into NXDOMAIN
	// Similar to dnsmasq's "bogus-nxdomain"
	BogusNXDomain []net.IP

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

	// Cache settings
	// --

	CacheEnabled   bool   // cache status
	CacheSizeBytes int    // Cache size (in bytes). Default: 64k
	CacheMinTTL    uint32 // Minimum TTL for DNS entries (in seconds).
	CacheMaxTTL    uint32 // Maximum TTL for DNS entries (in seconds).

	// Handlers (for the case when dnsproxy is used as a library)
	// --

	BeforeRequestHandler BeforeRequestHandler // callback that is called before each request
	RequestHandler       RequestHandler       // callback that can handle incoming DNS requests
	ResponseHandler      ResponseHandler      // response callback

	// Other settings
	// --

	MaxGoroutines int // maximum number of goroutines processing the DNS requests (important for mobile)
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

	if len(bootstrapDNS) > 0 {
		for i, b := range bootstrapDNS {
			log.Info("Bootstrap %d: %s", i, b)
		}
	}

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

	if p.CacheMinTTL > 0 || p.CacheMaxTTL > 0 {
		log.Info("Cache TTL override is enabled. Min=%d, Max=%d", p.CacheMinTTL, p.CacheMaxTTL)
	}

	if p.Ratelimit > 0 {
		log.Info("Ratelimit is enabled and set to %d rps", p.Ratelimit)
	}

	if p.RefuseAny {
		log.Info("The server is configured to refuse ANY requests")
	}

	if len(p.BogusNXDomain) > 0 {
		log.Info("%d bogus-nxdomain IP specified", len(p.BogusNXDomain))
	}

	return nil
}
