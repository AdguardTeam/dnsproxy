package upstream

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
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
		upsOpts.Logger = opts.Logger
	}

	ups, err := AddressToUpstream(resolverAddress, upsOpts)
	if err != nil {
		err = fmt.Errorf("upstream bootstrap: creating upstream: %w", err)

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
//
// TODO(e.burkov):  Use context.
func (r *UpstreamResolver) lookupNetIP(
	_ context.Context,
	network bootstrap.Network,
	host string,
) (result *ipResult, err error) {
	switch network {
	case bootstrap.NetworkIP4, bootstrap.NetworkIP6:
		return r.request(host, network)
	case bootstrap.NetworkIP:
		// Go on.
	default:
		return result, fmt.Errorf("unsupported network %s", network)
	}

	resCh := make(chan any, 2)
	go r.resolveAsync(resCh, host, bootstrap.NetworkIP4)
	go r.resolveAsync(resCh, host, bootstrap.NetworkIP6)

	var errs []error
	result = &ipResult{}

	for range 2 {
		switch res := <-resCh; res := res.(type) {
		case error:
			errs = append(errs, res)
		case *ipResult:
			if result.expire.Equal(time.Time{}) || res.expire.Before(result.expire) {
				result.expire = res.expire
			}
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
func (r *UpstreamResolver) request(host string, n bootstrap.Network) (res *ipResult, err error) {
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

	// As per [Upstream.Exchange] documentation, the response is always returned
	// if no error occurred.
	resp, err := r.Exchange(req)
	if err != nil {
		return res, err
	}

	res = &ipResult{
		expire: time.Now(),
		addrs:  make([]netip.Addr, 0, len(resp.Answer)),
	}
	var minTTL uint32 = math.MaxUint32

	for _, rr := range resp.Answer {
		ip := proxyutil.IPFromRR(rr)
		if !ip.IsValid() {
			continue
		}

		res.addrs = append(res.addrs, ip)
		minTTL = min(minTTL, rr.Header().Ttl)
	}
	res.expire = res.expire.Add(time.Duration(minTTL) * time.Second)

	return res, nil
}

// resolveAsync performs a single DNS lookup and sends the result to ch.  It's
// intended to be used as a goroutine.
func (r *UpstreamResolver) resolveAsync(resCh chan<- any, host, network string) {
	res, err := r.request(host, network)
	if err != nil {
		resCh <- err
	} else {
		resCh <- res
	}
}

// CachingResolver is a [Resolver] that caches the results of lookups.  It's
// required to be created with [NewCachingResolver].
type CachingResolver struct {
	// resolver is the underlying resolver to use for lookups.
	resolver *UpstreamResolver

	// mu protects cache and it's elements.
	mu *sync.RWMutex

	// cache is the set of resolved hostnames mapped to cached addresses.
	//
	// TODO(e.burkov):  Use expiration cache.
	cache map[string]*ipResult
}

// NewCachingResolver creates a new caching resolver that uses r for lookups.
func NewCachingResolver(r *UpstreamResolver) (cr *CachingResolver) {
	return &CachingResolver{
		resolver: r,
		mu:       &sync.RWMutex{},
		cache:    map[string]*ipResult{},
	}
}

// type check
var _ Resolver = (*CachingResolver)(nil)

// LookupNetIP implements the [Resolver] interface for *CachingResolver.
//
// TODO(e.burkov):  It may appear that several concurrent lookup results rewrite
// each other in the cache.
func (r *CachingResolver) LookupNetIP(
	ctx context.Context,
	network bootstrap.Network,
	host string,
) (addrs []netip.Addr, err error) {
	now := time.Now()
	host = dns.Fqdn(strings.ToLower(host))

	addrs = r.findCached(host, now)
	if addrs != nil {
		return slices.Clone(addrs), nil
	}

	res, err := r.resolver.lookupNetIP(ctx, network, host)
	if err != nil {
		return []netip.Addr{}, err
	}

	r.setCached(host, res)

	return slices.Clone(res.addrs), nil
}

// findCached returns the cached addresses for host if it's not expired yet, and
// the corresponding cached result, if any.  It's safe for concurrent use.
func (r *CachingResolver) findCached(host string, now time.Time) (addrs []netip.Addr) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res, ok := r.cache[host]
	if !ok || res.expire.Before(now) {
		return nil
	}

	return res.addrs
}

// setCached sets the result into the address cache for host.  It's safe for
// concurrent use.
func (r *CachingResolver) setCached(host string, res *ipResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.cache[host] = res
}
