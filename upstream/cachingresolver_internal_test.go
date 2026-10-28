package upstream

import (
	"context"
	"net/netip"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
)

// FindCached exports the internal method r.findCached for testing.
//
// TODO(e.burkov):  Find a way of testing without it.
func (r *CachingResolver) FindCached(
	host string,
	network bootstrap.Network,
	now time.Time,
) (addrs []netip.Addr, expire time.Time) {
	key := cacheKey{
		network:       network,
		lowercaseHost: host,
	}

	res := r.findCached(key, now)

	if res != nil {
		return res.addrs, res.expire
	}

	return nil, time.Time{}
}

// RequestResult exports the internal method r.request for testing.
func (r *UpstreamResolver) RequestResult(
	ctx context.Context,
	host string,
	n bootstrap.Network,
) (addrs []netip.Addr, expire time.Time, err error) {
	res, err := r.request(ctx, host, n)
	if err != nil {
		return nil, time.Time{}, err
	}

	return res.addrs, res.expire, err
}
