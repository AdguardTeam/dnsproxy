package upstream

import (
	"net/netip"
	"time"
)

// FindCached exports the internal method r.findCached for testing.
//
// TODO(e.burkov):  Find a way of testing without it.
func (r *CachingResolver) FindCached(host string, now time.Time) (addrs []netip.Addr) {
	return r.findCached(host, now)
}
