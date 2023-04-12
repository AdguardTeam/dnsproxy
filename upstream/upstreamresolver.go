package upstream

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// Resolver is an alias for bootstrap.Resolver to avoid the import cycle.
type Resolver = bootstrap.Resolver

// NewResolver creates a Resolver.  resolverAddress should be either a plain IP
// address or empty.  If it is empty, the default [net.Resolver] is used, and
// sorting the resolved addresses is the caller's responsibility.  Otherwise, it
// creates an Upstream using opts.
//
// TODO(e.burkov):  Require resolverAddress not being empty and rename into
// NewUpstreamResolver.
func NewResolver(resolverAddress string, opts *Options) (r Resolver, err error) {
	if resolverAddress == "" {
		return &net.Resolver{}, nil
	}

	if opts == nil {
		opts = &Options{}
	}

	// TODO(ameshkov):  Aren't other options needed here?
	upsOpts := &Options{
		Timeout:                 opts.Timeout,
		VerifyServerCertificate: opts.VerifyServerCertificate,
	}

	ur := upstreamResolver{}
	ur.Upstream, err = AddressToUpstream(resolverAddress, upsOpts)
	if err != nil {
		err = fmt.Errorf("creating upstream: %w", err)
		log.Error("upstream bootstrap: %s", err)

		return ur, err
	}

	// Validate the bootstrap resolver.  It must be either a plain DNS resolver,
	// or a DoT/DoH resolver defined by IP address (not a hostname).
	if !isResolverValidBootstrap(ur.Upstream) {
		ur.Upstream = nil
		err = fmt.Errorf("resolver %q is not a valid bootstrap DNS server", resolverAddress)
		log.Error("upstream bootstrap: %s", err)
	}

	return ur, err
}

// isResolverValidBootstrap checks if the upstream is eligible to be a bootstrap
// DNS server DNSCrypt and plain DNS resolvers are okay DoH and DoT are okay
// only in the case if an IP address is used in the IP address.
//
// TODO(e.burkov):  Refactor using the actual upstream types instead of parsing
// their addresses.
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

	a = strings.TrimPrefix(a, "tcp://")

	host, _, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)

	return ip != nil
}

// upstreamResolver is a wrapper around Upstream that implements the
// [bootstrap.Resolver] interface.  It sorts the resolved addresses preferring
// IPv4.
type upstreamResolver struct {
	// Upstream is embedded here to avoid implementing another Upstream's
	// methods.
	Upstream
}

// type check
var _ Resolver = upstreamResolver{}

// LookupNetIP implements the [Resolver] interface for upstreamResolver.
//
// TODO(e.burkov):  Do not look up concurrently for "ip4" and "ip6" networks.
func (r upstreamResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) (ipAddrs []netip.Addr, err error) {
	// TODO(e.burkov):  Investigate when r.ups is nil and why.
	if r.Upstream == nil || host == "" {
		return []netip.Addr{}, nil
	}

	host = dns.Fqdn(host)

	var resCh chan *resolveResult
	n := 1
	switch network {
	case "ip4":
		resCh = make(chan *resolveResult, n)

		go r.resolveAsync(host, dns.TypeA, resCh)
	case "ip6":
		resCh = make(chan *resolveResult, n)

		go r.resolveAsync(host, dns.TypeAAAA, resCh)
	case "ip":
		n = 2
		resCh = make(chan *resolveResult, n)

		go r.resolveAsync(host, dns.TypeA, resCh)
		go r.resolveAsync(host, dns.TypeAAAA, resCh)
	default:
		return []netip.Addr{}, fmt.Errorf("unsupported network: %s", network)
	}

	var errs []error
	for ; n > 0; n-- {
		re := <-resCh
		if re.err != nil {
			errs = append(errs, re.err)

			continue
		}

		for _, rr := range re.resp.Answer {
			if addr, ok := netip.AddrFromSlice(proxyutil.IPFromRR(rr)); ok {
				ipAddrs = append(ipAddrs, addr)
			}
		}
	}

	// TODO(e.burkov):  Use [errors.Join] in Go 1.20.
	if len(ipAddrs) == 0 && len(errs) > 0 {
		return []netip.Addr{}, errs[0]
	}

	// Use the previous dnsproxy behavior: prefer IPv4 by default.
	//
	// TODO(a.garipov): Consider unexporting this entire method or documenting
	// that the order of addrs is undefined.
	proxynetutil.SortNetIPAddrs(ipAddrs, false)

	return ipAddrs, nil
}

// resolve performs a single DNS lookup of host.
func (r upstreamResolver) resolve(host string, qtype uint16) (resp *dns.Msg, err error) {
	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   host,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		}},
	}

	return r.Exchange(req)
}

// resolveResult is the result of a single concurrent lookup.
type resolveResult struct {
	resp *dns.Msg
	err  error
}

// resolveAsync performs a single DNS lookup and sends the result to ch.  It's
// intended to be used as a goroutine.
func (r upstreamResolver) resolveAsync(host string, qtype uint16, ch chan *resolveResult) {
	resp, err := r.resolve(host, qtype)
	ch <- &resolveResult{resp, err}
}
