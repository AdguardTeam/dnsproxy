// Package ratelimit provides a rate limiting functionality.
package ratelimit

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/netutil"
	rate "github.com/beefsack/go-rate"
	gocache "github.com/patrickmn/go-cache"
)

// middleware implements [proxy.Middleware] with rate limiting functionality.
//
// TODO(d.kolyshev): Use.
type middleware struct {
	buckets *gocache.Cache
	logger  *slog.Logger

	// mu protects buckets.
	mu *sync.Mutex

	allowlistAddrs netutil.SliceSubnetSet
	ratelimit      uint
	subnetLenIPv4  uint
	subnetLenIPv6  uint
}

// NewMiddleware returns middleware with rate limiting functionality.  c must be
// valid.
func NewMiddleware(c *Config) (m proxy.Middleware) {
	return &middleware{
		logger:         c.Logger,
		mu:             &sync.Mutex{},
		allowlistAddrs: c.AllowlistAddrs,
		ratelimit:      c.Ratelimit,
		subnetLenIPv4:  c.SubnetLenIPv4,
		subnetLenIPv6:  c.SubnetLenIPv6,
	}
}

// type check
var _ proxy.Middleware = (*middleware)(nil)

// Wrap implements the [proxy.Middleware] interface for *middleware.  If the
// client is rate limited, it returns [proxy.ErrDrop] to signal that no response
// should be sent.
func (m *middleware) Wrap(h proxy.Handler) (wrapped proxy.Handler) {
	f := func(p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
		if dctx.Proto == proxy.ProtoUDP && m.isRatelimited(dctx.Addr.Addr()) {
			m.logger.Debug("ratelimited based on ip only", "addr", dctx.Addr)

			return proxy.ErrDrop
		}

		return h.ServeDNS(p, dctx)
	}

	return proxy.HandlerFunc(f)
}

// limiterForIP returns a rate limiter for the specified IP address.
func (m *middleware) limiterForIP(ip string) (rl any) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.buckets == nil {
		m.buckets = gocache.New(time.Hour, time.Hour)
	}

	rl, ok := m.buckets.Get(ip)
	if !ok {
		rl = rate.New(int(m.ratelimit), time.Second)
		m.buckets.Set(ip, rl, time.Hour)
	}

	return rl
}

// isRatelimited checks if the specified address should be rate limited.
func (m *middleware) isRatelimited(addr netip.Addr) (ok bool) {
	addr = addr.Unmap()
	if m.allowlistAddrs.Contains(addr) {
		return false
	}

	var pref netip.Prefix
	if addr.Is4() {
		pref = netip.PrefixFrom(addr, int(m.subnetLenIPv4))
	} else {
		pref = netip.PrefixFrom(addr, int(m.subnetLenIPv6))
	}
	pref = pref.Masked()

	// TODO(d.kolyshev):  Improve caching.  Decrease allocations.
	ipStr := pref.Addr().String()
	value := m.limiterForIP(ipStr)
	rl, ok := value.(*rate.RateLimiter)
	if !ok {
		panic(fmt.Sprintf("invalid value found in ratelimit cache: bad type: %T", value))
	}

	allow, _ := rl.Try()

	return !allow
}
