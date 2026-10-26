package upstream

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
)

// Resolver resolves the hostnames to IP addresses.  Note, that [net.Resolver]
// from standard library also implements this interface.
type Resolver = bootstrap.Resolver

// StaticResolver is a resolver which always responds with an underlying slice
// of IP addresses.
type StaticResolver = bootstrap.StaticResolver

// ParallelResolver is a slice of resolvers that are queried concurrently until
// the first successful response is returned, as opposed to all resolvers being
// queried in order in [ConsequentResolver].
type ParallelResolver = bootstrap.ParallelResolver

// ConsequentResolver is a slice of resolvers that are queried in order until
// the first successful non-empty response, as opposed to just successful
// response requirement in [ParallelResolver].
type ConsequentResolver = bootstrap.ConsequentResolver

// UpstreamResolver is a wrapper around Upstream that implements the
// [bootstrap.Resolver] interface.
type UpstreamResolver struct {
	// Upstream is used for lookups.  It must not be nil.
	Upstream

	// Logger logs messages related to the upstream resolver's operations.  It
	// must not be nil.
	Logger *slog.Logger

	// Clock provides the current time.  It must not be nil.
	Clock timeutil.Clock
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
		upsOpts.Logger = cmp.Or(opts.Logger, slog.Default())
	}

	ups, err := AddressToUpstream(resolverAddress, upsOpts)
	if err != nil {
		return nil, fmt.Errorf("upstream bootstrap: creating upstream: %w", err)
	}

	opts = cmp.Or(opts, &Options{})

	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	if opts.Clock == nil {
		opts.Clock = &timeutil.SystemClock{}
	}

	return &UpstreamResolver{
		Upstream: ups,
		Logger:   opts.Logger,
		Clock:    opts.Clock,
	}, validateBootstrap(ups)
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

// LookupNetIP implements the [Resolver] interface for *UpstreamResolver.  It
// doesn't consider the TTL of the DNS records.
//
// TODO(e.burkov):  Investigate why the empty slice is returned instead of nil.
func (r *UpstreamResolver) LookupNetIP(
	ctx context.Context,
	network bootstrap.Network,
	host string,
) (ips []netip.Addr, err error) {
	if host == "" {
		return nil, nil
	}

	host = dns.Fqdn(strings.ToLower(host))

	res, err := r.lookupNetIP(ctx, network, host)
	if err != nil {
		return []netip.Addr{}, err
	}

	return res.addrs, err
}

// ipResult reflects a single A/AAAA record from the DNS response.  It's used
// to cache the results of lookups.
type ipResult struct {
	expire time.Time
	addrs  []netip.Addr
}

// lookupNetIP performs a DNS lookup of host and returns the result.  network
// must be either [bootstrap.NetworkIP4], [bootstrap.NetworkIP6], or
// [bootstrap.NetworkIP].  host must be in a lower-case FQDN form.
func (r *UpstreamResolver) lookupNetIP(
	ctx context.Context,
	network bootstrap.Network,
	host string,
) (result *ipResult, err error) {
	switch network {
	case bootstrap.NetworkIP4, bootstrap.NetworkIP6:
		return r.request(ctx, host, network)
	case bootstrap.NetworkIP:
		// Go on.
	default:
		return result, fmt.Errorf("unsupported network %s", network)
	}

	resCh := make(chan any, 2)
	go r.resolveAsync(ctx, resCh, host, bootstrap.NetworkIP4)
	go r.resolveAsync(ctx, resCh, host, bootstrap.NetworkIP6)

	var errs []error
	result = &ipResult{
		expire: r.Clock.Now(),
		// Set the slice initial capacity to 2, as we expect at most two results
		// (IPv4 and IPv6).
		addrs: make([]netip.Addr, 0, 2),
	}

	for range 2 {
		switch res := <-resCh; res := res.(type) {
		case error:
			errs = append(errs, res)
		case *ipResult:
			result.expire = res.expire
			result.addrs = append(result.addrs, res.addrs...)
		}
	}

	return result, errors.Join(errs...)
}

// request performs a single DNS lookup of host and returns all the valid
// addresses from the answer section of the response.  network must be either
// [bootstrap.NetworkIP4], or [bootstrap.NetworkIP6].  host must be in a
// lower-case FQDN form.
//
// TODO(e.burkov):  Consider NS and Extra sections when setting TTL.  Check out
// what RFCs say about it.
func (r *UpstreamResolver) request(
	ctx context.Context,
	host string,
	n bootstrap.Network,
) (res *ipResult, err error) {
	var qtype uint16
	switch n {
	case bootstrap.NetworkIP4:
		qtype = dns.TypeA
	case bootstrap.NetworkIP6:
		qtype = dns.TypeAAAA
	default:
		panic(fmt.Sprintf("unsupported network %q", n))
	}

	req := &dns.Msg{
		Id:               dns.Id(),
		RecursionDesired: true,
		Question: []dns.Question{{
			Name:   host,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		}},
	}

	// As per [Upstream.Exchange] documentation, the response is always returned
	// if no error occurred.
	resp, err := r.Exchange(ctx, req)
	if err != nil {
		return res, err
	}

	res = &ipResult{
		expire: r.Clock.Now(),
		addrs:  make([]netip.Addr, 0, len(resp.Answer)),
	}

	minTTL := dnsmsg.CacheTTL(ctx, r.Logger, resp)

	for _, rr := range resp.Answer {
		ip := proxyutil.IPFromRR(rr)
		if !ip.IsValid() {
			continue
		}

		res.addrs = append(res.addrs, ip)
	}
	res.expire = res.expire.Add(time.Duration(minTTL) * time.Second)

	return res, nil
}

// resolveAsync performs a single DNS lookup and sends the result to ch.  It's
// intended to be used as a goroutine.
func (r *UpstreamResolver) resolveAsync(
	ctx context.Context,
	resCh chan<- any,
	host, network string,
) {
	res, err := r.request(ctx, host, network)
	if err != nil {
		resCh <- err
	} else {
		resCh <- res
	}
}
