package upstream

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// Resolver resolves the hostnames to IP addresses.  Note, that the
// [net.Resolver] from standard library also implements this interface.
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

// UpstreamResolver is a wrapper around [Upstream] that implements the
// [bootstrap.Resolver] interface.
type UpstreamResolver struct {
	// Upstream is used for lookups.  It must not be nil.
	Upstream
}

// NewUpstreamResolver creates an upstream that can be used as bootstrap
// [Resolver].  addr format is the same as in the [AddressToUpstream].  If the
// upstream can't be used as a bootstrap, the returned error will have the
// underlying type of [NotBootstrapError], but r won't be bootstrapped and
// therefore be usable anyway.  Closing the underlying [Upstream] is caller's
// responsibility.
func NewUpstreamResolver(addr string, opts *Options) (r *UpstreamResolver, err error) {
	upsOpts := &Options{}

	// TODO(ameshkov):  Aren't other options needed here?
	if opts != nil {
		upsOpts.Timeout = opts.Timeout
		upsOpts.VerifyServerCertificate = opts.VerifyServerCertificate
		upsOpts.PreferIPv6 = opts.PreferIPv6
	}

	ups, err := AddressToUpstream(addr, upsOpts)
	if err != nil {
		err = fmt.Errorf("creating upstream: %w", err)
		log.Error("upstream bootstrap: %s", err)

		return nil, err
	}

	return &UpstreamResolver{Upstream: ups}, validateBootstrap(ups)
}

// NotBootstrapError is returned by [NewUpstreamResolver] when the parsed
// [Upstream] can't be used as a bootstrap and wraps the actual reason, which is
// usually a [netip.ParseAddr] error.
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

// LookupNetIP implements the [Resolver] interface for *UpstreamResolver.
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

	rr, err := r.resolveIP(ctx, network, host)
	if err != nil {
		return []netip.Addr{}, err
	}

	return rr.addrs, err
}

// resolveResult is the result of a single DNS lookup for IP addresses.
type resolveResult struct {
	// name is the hostname in a lower-case form.
	name string

	// expire is the time when the result should not be considered usable
	// anymore.  It's essentially the minimum of all the TTL values of the
	// resource records in the answer section of the response.
	expire time.Time

	// addrs is the resolved set of addresses.
	addrs []netip.Addr
}

// compareNames is used to sort [resolveResult]s by [resolveResult.name].  It
// doesn't require other fields to be valid.
func (rr *resolveResult) compareNames(other *resolveResult) (res int) {
	return strings.Compare(rr.name, other.name)
}

// resolveIP performs a DNS lookup of host and returns the result.  network must
// be either [bootstrap.NetworkIP4], [bootstrap.NetworkIP6] or
// [bootstrap.NetworkIP].  host must be in a lower-case FQDN form.
//
// TODO(e.burkov):  Use context.
func (r *UpstreamResolver) resolveIP(
	_ context.Context,
	network bootstrap.Network,
	host string,
) (rr *resolveResult, err error) {
	switch network {
	case bootstrap.NetworkIP4, bootstrap.NetworkIP6:
		return r.resolve(host, network)
	case bootstrap.NetworkIP:
		// Go on.
	default:
		return nil, fmt.Errorf("unsupported network %s", network)
	}

	resCh := make(chan any, 2)
	go r.resolveAsync(resCh, host, bootstrap.NetworkIP4)
	go r.resolveAsync(resCh, host, bootstrap.NetworkIP6)

	var errs []error
	rr = &resolveResult{}

	for i := 0; i < 2; i++ {
		switch res := <-resCh; res := res.(type) {
		case error:
			errs = append(errs, res)
		case *resolveResult:
			rr.addrs = append(rr.addrs, res.addrs...)
			rr.name = res.name
			if rr.expire.IsZero() || res.expire.Before(rr.expire) {
				rr.expire = res.expire
			}
		}
	}

	return rr, errors.Join(errs...)
}

// resolve performs a single DNS lookup of host and returns all the valid
// addresses from the answer section of the response.  network must be either
// "ip4" or "ip6".
//
// TODO(e.burkov):  Consider returning NS and Extra sections for setting TTL
// properly.
func (r *UpstreamResolver) resolve(host, n bootstrap.Network) (res *resolveResult, err error) {
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

	resp, err := r.Exchange(req)
	if err != nil || resp == nil {
		return nil, err
	}

	res = &resolveResult{
		name:   host,
		expire: time.Now(),
	}

	var ttl uint32 = math.MaxUint32
	for _, rr := range resp.Answer {
		if ip := proxyutil.IPFromRR(rr); ip.IsValid() {
			res.addrs = append(res.addrs, ip)
			ttl = mathutil.Min(ttl, rr.Header().Ttl)
		}
	}

	res.expire = res.expire.Add(time.Duration(ttl) * time.Second)

	return res, nil
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

// CachingResolver is a [Resolver] that caches the results of lookups.  It's
// required to be created with [NewCachingResolver].
type CachingResolver struct {
	// resolver is the underlying resolver to use for lookups.
	resolver *UpstreamResolver

	// mu protects cached and it's elements.
	mu *sync.RWMutex

	// cached is the set of cached results sorted by [resolveResult.name].
	cached []*resolveResult
}

// NewCachingResolver creates a new caching resolver that uses r for lookups.
func NewCachingResolver(r *UpstreamResolver) (cr *CachingResolver) {
	return &CachingResolver{
		resolver: r,
		mu:       &sync.RWMutex{},
	}
}

// type check
var _ Resolver = (*CachingResolver)(nil)

// LookupNetIP implements the [Resolver] interface for *CachingResolver.
func (r *CachingResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) (addrs []netip.Addr, err error) {
	host = dns.Fqdn(strings.ToLower(host))

	addrs, res := r.findCached(host)
	if addrs != nil {
		return slices.Clone(addrs), nil
	}

	newRes, err := r.resolver.resolveIP(ctx, network, host)
	if err != nil {
		return []netip.Addr{}, err
	}

	if len(newRes.addrs) == 0 {
		return []netip.Addr{}, nil
	} else {
		addrs = slices.Clone(newRes.addrs)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if res == nil {
		i, _ := slices.BinarySearchFunc(r.cached, newRes, (*resolveResult).compareNames)
		r.cached = slices.Insert(r.cached, i, newRes)
	} else {
		*res = *newRes
	}

	return addrs, nil
}

// findCached returns the cached addresses for host if it's not expired yet, and
// the corresponding cached result, if any.
func (r *CachingResolver) findCached(host string) (addrs []netip.Addr, res *resolveResult) {
	target := &resolveResult{name: host}

	r.mu.RLock()
	defer r.mu.RUnlock()

	i, ok := slices.BinarySearchFunc(r.cached, target, (*resolveResult).compareNames)
	if ok {
		res = r.cached[i]
		if res.expire.After(time.Now()) {
			return res.addrs, res
		}

		return nil, res
	}

	return nil, nil
}
