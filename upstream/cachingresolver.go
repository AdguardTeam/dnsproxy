package upstream

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/miekg/dns"
)

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
	cache map[cacheKey]*ipResult
}

// NewCachingResolver creates a new caching resolver that uses r for lookups.
func NewCachingResolver(r *UpstreamResolver) (cr *CachingResolver) {
	return &CachingResolver{
		resolver: r,
		mu:       &sync.RWMutex{},
		cache:    map[cacheKey]*ipResult{},
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

	key := cacheKey{
		network:       network,
		lowercaseHost: host,
	}

	addrs = r.findCached(key, now)
	if addrs != nil {
		return slices.Clone(addrs), nil
	}

	res, err := r.resolver.lookupNetIP(ctx, network, host)
	if err != nil {
		return []netip.Addr{}, err
	}

	r.setCached(key, res)

	return slices.Clone(res.addrs), nil
}

// findCached returns the cached addresses for host and network if it's not
// expired yet, and the corresponding cached result, if any.  It's safe for
// concurrent use.
func (r *CachingResolver) findCached(
	key cacheKey,
	now time.Time,
) (addrs []netip.Addr) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res, ok := r.cache[key]
	if !ok || res.expire.Before(now) {
		return nil
	}

	return res.addrs
}

// setCached sets the result into the address cache for host and network.  It's
// safe for concurrent use.
func (r *CachingResolver) setCached(key cacheKey, res *ipResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.cache[key] = res
}

// cacheKey represents a unique key for the address cache, consisting of the
// network and the host.
type cacheKey struct {
	// network is the network type.  It must be one of:
	//   - [bootstrap.NetworkIP4]
	//   - [bootstrap.NetworkIP6]
	//   - [bootstrap.NetworkIP]
	network bootstrap.Network

	// lowercaseHost is the hostname.  It must be lowercase only.
	lowercaseHost string
}
