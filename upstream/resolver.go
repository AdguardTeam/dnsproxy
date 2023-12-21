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

// Resolver is an alias for the internal [bootstrap.Resolver] to allow custom
// implementations.  Note, that the [net.Resolver] from standard library also
// implements this interface.
type Resolver = bootstrap.Resolver

// StaticResolver is a resolver which always responds with an underlying slice
// of IP addresses.
type StaticResolver = bootstrap.StaticResolver

// ConsequentResolver is a slice of resolvers that are queried in order until
// the first successful non-empty response, as opposed to just successful
// response requirement in [ParallelResolver].
type ConsequentResolver = bootstrap.ConsequentResolver

// ParallelResolver is an alias for the internal [bootstrap.ParallelResolver] to
// allow it's usage outside of the module.
type ParallelResolver = bootstrap.ParallelResolver

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

// LookupNetIP implements the [Resolver] interface for *UpstreamResolver.
//
// TODO(e.burkov):  Investigate why the empty slice is returned instead of nil.
func (r *UpstreamResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) (ips []netip.Addr, err error) {
	if host == "" {
		return nil, nil
	}

	rrs, err := r.lookupIPRecords(ctx, network, host)
	if err != nil {
		return []netip.Addr{}, err
	}

	ips = make([]netip.Addr, 0, len(rrs))
	for _, rr := range rrs {
		if ip := proxyutil.IPFromRR(rr); ip.IsValid() {
			ips = append(ips, ip)
		}
	}

	return slices.Clip(ips), err
}

// lookupIPRecords performs a DNS lookup of host and returns all the retrieved
// resource records.  network must be either "ip4", "ip6" or "ip".
//
// TODO(e.burkov):  Use context.
func (r *UpstreamResolver) lookupIPRecords(
	_ context.Context,
	network string,
	host string,
) (rrs []dns.RR, err error) {
	switch network {
	case "ip4", "ip6":
		rrs, err = r.resolve(host, network)
	case "ip":
		resCh := make(chan any, 2)
		go r.resolveAsync(resCh, host, "ip4")
		go r.resolveAsync(resCh, host, "ip6")

		var errs []error
		for i := 0; i < 2; i++ {
			switch res := <-resCh; res := res.(type) {
			case error:
				errs = append(errs, res)
			case []dns.RR:
				rrs = append(rrs, res...)
			}
		}

		err = errors.Join(errs...)
	default:
		return nil, fmt.Errorf("unsupported network %s", network)
	}

	return rrs, err
}

// resolve performs a single DNS lookup of host and returns all the valid
// addresses from the answer section of the response.  network must be either
// "ip4" or "ip6".
//
// TODO(e.burkov):  Consider returning NS and Extra sections for setting TTL
// properly.
func (r *UpstreamResolver) resolve(host, network string) (ans []dns.RR, err error) {
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
			Name:   dns.Fqdn(host),
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		}},
	}

	resp, err := r.Exchange(req)
	if err != nil || resp == nil {
		return nil, err
	}

	return resp.Answer, nil
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
	host = strings.ToLower(host)
	now := time.Now()

	addrs, res := r.findCached(host, now)
	if addrs != nil {
		return addrs, nil
	}

	rrs, err := r.resolver.lookupIPRecords(ctx, network, host)
	if err != nil {
		return []netip.Addr{}, err
	}

	var ttl uint32 = math.MaxUint32
	addrs = make([]netip.Addr, 0, len(rrs))
	for _, rr := range rrs {
		if ip := proxyutil.IPFromRR(rr); ip.IsValid() {
			addrs = append(addrs, ip)
			ttl = mathutil.Min(ttl, rr.Header().Ttl)
		}
	}

	if len(addrs) == 0 {
		return []netip.Addr{}, nil
	}

	expire := now.Add(time.Duration(ttl) * time.Second)

	r.mu.Lock()
	defer r.mu.Unlock()

	if res == nil {
		res = &resolveResult{name: host}

		i, _ := slices.BinarySearchFunc(r.cached, res, (*resolveResult).compareNames)
		r.cached = slices.Insert(r.cached, i, res)
	}

	res.expire = expire
	res.addrs = slices.Clone(addrs)

	return addrs, nil
}

// findCached returns the index of the cached result for host, or false if it's
// not found or expired.  The returned index is suitable for insertion anyway.
func (r *CachingResolver) findCached(
	host string,
	now time.Time,
) (addrs []netip.Addr, res *resolveResult) {
	target := &resolveResult{
		name: host,
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	i, ok := slices.BinarySearchFunc(r.cached, target, (*resolveResult).compareNames)
	if ok {
		res = r.cached[i]
		if res.expire.After(now) {
			return slices.Clone(res.addrs), nil
		}

		return nil, res
	}

	return nil, nil
}

// resolveResult is the result of a single DNS lookup for IP addresses.
type resolveResult struct {
	// name is the name of the host in a lower-case form.
	name string

	// expire is the time when the result should not be considered usable
	// anymore.  It's essentially the minimum of all the TTL values of the
	// resource records in the answer section of the response.
	expire time.Time

	// addrs is the resolved addresses set.
	addrs []netip.Addr
}

// compareNames compares the names of rr and other.
func (rr *resolveResult) compareNames(other *resolveResult) (res int) {
	return strings.Compare(rr.name, other.name)
}
