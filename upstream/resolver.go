package upstream

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// Resolver is an alias for the internal [bootstrap.Resolver] to allow custom
// implementations.  Note, that the [net.Resolver] from standard library also
// implements this interface.
type Resolver = bootstrap.Resolver

// UpstreamResolver is a wrapper around Upstream that implements the
// [bootstrap.Resolver] interface.
type UpstreamResolver struct {
	// Upstream is used for lookups.  It must not be nil.
	Upstream
}

// NewUpstreamResolver creates an upstream that can be used as bootstrap
// [Resolver].  resolverAddress format is the same as in the
// [AddressToUpstream].  If the upstream can't be used as a bootstrap, the
// returned error will have the underlying type of [NotBootstrapError], and r
// itself will be fully usable.  Closing r.Upstream is caller's responsibility.
func NewUpstreamResolver(resolverAddress string, opts *Options) (r *UpstreamResolver, err error) {
	upsOpts := &Options{}

	// TODO(ameshkov):  Aren't other options needed here?
	if opts != nil {
		upsOpts.Timeout = opts.Timeout
		upsOpts.VerifyServerCertificate = opts.VerifyServerCertificate
		upsOpts.PreferIPv6 = opts.PreferIPv6
	}

	ups, err := AddressToUpstream(resolverAddress, upsOpts)
	if err != nil {
		err = fmt.Errorf("creating upstream: %w", err)
		log.Error("upstream bootstrap: %s", err)

		return nil, err
	}

	return &UpstreamResolver{Upstream: ups}, validateBootstrap(ups)
}

// NotBootstrapError is returned by [AddressToUpstream] when the parsed upstream
// can't be used as a bootstrap and wraps the actual reason.
type NotBootstrapError struct {
	// err is the actual reason why the upstream can't be used as a bootstrap.
	err error
}

// type check
var _ error = NotBootstrapError{}

// Error implements the [error] interface for NotBootstrapError.
func (e NotBootstrapError) Error() (msg string) {
	return fmt.Sprintf("not a bootstrap: %s", e.err)
}

// type check
var _ errors.Wrapper = NotBootstrapError{}

// Unwrap implements the [errors.Wrapper] interface.
func (e NotBootstrapError) Unwrap() (reason error) {
	return e.err
}

// validateBootstrap returns an error if u can't be used as a bootstrap.
func validateBootstrap(u Upstream) (err error) {
	var upsURL *url.URL
	switch u := u.(type) {
	case *dnsCrypt:
		return nil
	case *plainDNS:
		upsURL = u.addr
	case *dnsOverTLS:
		upsURL = u.addr
	case *dnsOverHTTPS:
		upsURL = u.addr
	case *dnsOverQUIC:
		upsURL = u.addr
	default:
		return fmt.Errorf("unknown upstream type: %T", u)
	}

	// Make sure the upstream doesn't need a bootstrap.
	_, err = netip.ParseAddr(upsURL.Hostname())
	if err != nil {
		return NotBootstrapError{err: err}
	}

	return nil
}

// type check
var _ Resolver = &UpstreamResolver{}

// LookupNetIP implements the [Resolver] interface for upstreamResolver.
//
// TODO(e.burkov):  Use context.
func (r *UpstreamResolver) LookupNetIP(
	_ context.Context,
	network string,
	host string,
) (ips []netip.Addr, err error) {
	if host == "" {
		return nil, nil
	}

	switch network {
	case "ip4", "ip6":
		host = dns.Fqdn(host)
		ips, err = r.resolve(host, network)
	case "ip":
		host = dns.Fqdn(host)
		resCh := make(chan any, 2)
		go r.resolveAsync(resCh, host, "ip4")
		go r.resolveAsync(resCh, host, "ip6")

		var errs []error
		for i := 0; i < 2; i++ {
			switch res := <-resCh; res := res.(type) {
			case error:
				errs = append(errs, res)
			case []netip.Addr:
				ips = append(ips, res...)
			}
		}

		err = errors.Join(errs...)
	default:
		return []netip.Addr{}, fmt.Errorf("unsupported network %s", network)
	}

	if len(ips) == 0 {
		ips = []netip.Addr{}
	}

	return ips, err
}

// resolve performs a single DNS lookup of host and returns all the valid
// addresses from the answer section of the response.  network must be either
// "ip4" or "ip6".
func (r *UpstreamResolver) resolve(host, network string) (addrs []netip.Addr, err error) {
	qtype := dns.TypeA
	if network == "ip6" {
		qtype = dns.TypeAAAA
	}

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

	resp, err := r.Upstream.Exchange(req)
	if err != nil || resp == nil {
		return nil, err
	}

	for _, rr := range resp.Answer {
		if addr := proxyutil.IPFromRR(rr); addr.IsValid() {
			addrs = append(addrs, addr)
		}
	}

	return addrs, nil
}

// resolveAsync performs a single DNS lookup and sends the result to ch.  It's
// intended to be used as a goroutine.
func (r *UpstreamResolver) resolveAsync(resCh chan<- any, host, network string) {
	resp, err := r.resolve(host, network)
	if err != nil {
		resCh <- err
	} else {
		resCh <- resp
	}
}

// StaticResolver is a resolver which always responds with an underlying slice
// of IP addresses.
type StaticResolver []netip.Addr

// type check
var _ Resolver = StaticResolver(nil)

// LookupNetIP implements the [Resolver] interface for StaticResolver.
func (r StaticResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) (addrs []netip.Addr, err error) {
	return slices.Clone(r), nil
}

// ConsequentResolver is a slice of resolvers that are queried in order until
// the first successful non-empty response, as opposed to just successful
// response requirement in [ParallelResolver].
type ConsequentResolver []Resolver

// type check
var _ Resolver = ConsequentResolver(nil)

// LookupNetIP implements the [Resolver] interface for ConsequentResolver.
func (resolvers ConsequentResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) (addrs []netip.Addr, err error) {
	if len(resolvers) == 0 {
		return nil, bootstrap.ErrNoResolvers
	}

	var errs []error
	for _, r := range resolvers {
		addrs, err = r.LookupNetIP(ctx, network, host)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}

		errs = append(errs, err)
	}

	return nil, errors.Join(errs...)
}

// ParallelResolver is an alias for the internal [bootstrap.ParallelResolver] to
// allow it's usage outside of the module.
type ParallelResolver = bootstrap.ParallelResolver
