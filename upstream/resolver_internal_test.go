package upstream

import (
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
) (addrs []netip.Addr) {
	return r.findCached(host, network, now)
}
