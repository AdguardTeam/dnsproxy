package upstream

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// CachingResolver is a [Resolver] that caches the results of lookups.  It's
// required to be created with [NewCachingResolver].
type CachingResolver struct {
	// resolver is the underlying resolver to use for lookups.
	resolver *UpstreamResolver

	// queries is used to deduplicate concurrent lookups for the same key.
	queries *singleflight.Group

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
		queries:  &singleflight.Group{},
		cache:    map[cacheKey]*ipResult{},
	}
}

// type check
var _ Resolver = (*CachingResolver)(nil)

// LookupNetIP implements the [Resolver] interface for *CachingResolver.
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

	// TODO(m.kazantsev):  Use some hash as a key instead of the plain host and
	// network combination.
	v, err, _ := r.queries.Do(fmt.Sprintf("%s:%s", host, network), func() (any, error) {
		return r.lookupAndCache(ctx, key)
	})
	if err != nil {
		return []netip.Addr{}, err
	}

	if v == nil {
		return []netip.Addr{}, nil
	}

	res, ok := v.(*ipResult)
	if !ok {
		panic(fmt.Sprintf("invalid value from singleflight %v: bad type: %T", v, v))
	}

	if res == nil {
		return []netip.Addr{}, nil
	}

	return slices.Clone(res.addrs), nil
}

func (r *CachingResolver) lookupAndCache(
	ctx context.Context,
	key cacheKey,
) (res *ipResult, err error) {
	res, err = r.resolver.lookupNetIP(ctx, key.network, key.lowercaseHost)
	if err != nil {
		// Do not wrap the error, because it is informative enough as is.
		return nil, err
	}

	// Do not cache empty results.
	if res == nil || len(res.addrs) == 0 {
		return nil, nil
	}

	r.setCached(key, res)

	return res, nil
}

// findCached returns the cached addresses for host and network if it's not
// expired yet.  It's safe for concurrent use.
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
