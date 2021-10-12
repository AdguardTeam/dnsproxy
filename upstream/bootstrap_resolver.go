package upstream

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// Resolver is wrapper for resolver and it's address
type Resolver struct {
	resolver        *net.Resolver // net.Resolver
	resolverAddress string        // Resolver's address
	upstream        Upstream
}

// NewResolver creates an instance of a Resolver structure with defined net.Resolver and it's address
// resolverAddress -- is address of net.Resolver
// The host in the address parameter of Dial func will always be a literal IP address (from documentation)
// options are the upstream customization options, nil means use default
// options.
func NewResolver(resolverAddress string, options *Options) (*Resolver, error) {
	r := &Resolver{}

	// set default net.Resolver as a resolver if resolverAddress is empty
	if resolverAddress == "" {
		r.resolver = &net.Resolver{}
		return r, nil
	}

	if options == nil {
		options = &Options{}
	}

	r.resolverAddress = resolverAddress
	var err error
	opts := &Options{
		Timeout:                 options.Timeout,
		VerifyServerCertificate: options.VerifyServerCertificate,
	}
	r.upstream, err = AddressToUpstream(resolverAddress, opts)
	if err != nil {
		log.Error("AddressToUpstream: %s", err)
		return r, fmt.Errorf("AddressToUpstream: %s", err)
	}

	// Validate the bootstrap resolver. It must be either a plain DNS resolver.
	// Or a DOT/DOH resolver with an IP address (not a hostname).
	if !isResolverValidBootstrap(r.upstream) {
		r.upstream = nil
		log.Error("Resolver %s is not eligible to be a bootstrap DNS server", resolverAddress)
		return r, fmt.Errorf("Resolver %s is not eligible to be a bootstrap DNS server", resolverAddress)
	}

	return r, nil
}

// isResolverValidBootstrap checks if the upstream is eligible to be a bootstrap DNS server
// DNSCrypt and plain DNS resolvers are okay
// DOH and DOT are okay only in the case if an IP address is used in the IP address
func isResolverValidBootstrap(upstream Upstream) bool {
	if u, ok := upstream.(*dnsOverTLS); ok {
		urlAddr, err := url.Parse(u.Address())
		if err != nil {
			return false
		}
		host, _, err := net.SplitHostPort(urlAddr.Host)
		if err != nil {
			return false
		}

		if ip := net.ParseIP(host); ip != nil {
			return true
		}
		return false
	}

	if u, ok := upstream.(*dnsOverHTTPS); ok {
		urlAddr, err := url.Parse(u.Address())
		if err != nil {
			return false
		}
		host, _, err := net.SplitHostPort(urlAddr.Host)
		if err != nil {
			host = urlAddr.Host
		}

		if ip := net.ParseIP(host); ip != nil {
			return true
		}
		return false
	}

	a := upstream.Address()
	if strings.HasPrefix(a, "sdns://") {
		return true
	}

	if strings.HasPrefix(a, "tcp://") {
		a = a[len("tcp://"):]
	}

	host, _, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return true
}

type resultError struct {
	resp *dns.Msg
	err  error
}

func (r *Resolver) resolve(host string, qtype uint16, ch chan *resultError) {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{
			Name:   host,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		},
	}
	resp, err := r.upstream.Exchange(&req)
	ch <- &resultError{resp, err}
}

// LookupIPAddr returns result of LookupIPAddr method of Resolver's net.Resolver
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
<<<<<<< Updated upstream
<<<<<<< Updated upstream
=======
	log.Printf("passe par la?")
>>>>>>> Stashed changes
=======
	log.Printf("passe par la?")
>>>>>>> Stashed changes
	if r.resolver != nil {
		// use system resolver
		addrs, err := r.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		return proxyutil.SortIPAddrs(addrs), nil
	}

	if r.upstream == nil || len(host) == 0 {
		return []net.IPAddr{}, nil
	}

	if host[:1] != "." {
		host += "."
	}

	ch := make(chan *resultError)
	go r.resolve(host, dns.TypeA, ch)
	go r.resolve(host, dns.TypeAAAA, ch)

	var ipAddrs []net.IPAddr
	var errs []error
	n := 0
wait:
	for {
		var re *resultError
		select {
		case re = <-ch:
			if re.err != nil {
				errs = append(errs, re.err)
			} else {
				proxyutil.AppendIPAddrs(&ipAddrs, re.resp.Answer)
			}
			n++
			if n == 2 {
				break wait
			}
		}
	}

	if len(ipAddrs) == 0 && len(errs) != 0 {
		return []net.IPAddr{}, errs[0]
	}

	return proxyutil.SortIPAddrs(ipAddrs), nil
}
