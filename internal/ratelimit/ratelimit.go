// Package ratelimit provides a rate limiting functionality.
package ratelimit

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	rate "github.com/beefsack/go-rate"
	gocache "github.com/patrickmn/go-cache"
)

// Config is the configuration for the ratelimit handler.
type Config struct {
	// Logger is used for logging in the ratelimit handler. It must not be nil.
	Logger *slog.Logger

	// AllowlistAddrs is a list of IP addresses excluded from rate limiting.
	AllowlistAddrs []netip.Addr

	// Ratelimit is a maximum number of requests per second from a given IP (0
	// to disable).
	Ratelimit int

	// SubnetLenIPv4 is a subnet length for IPv4 addresses used for rate
	// limiting requests.
	SubnetLenIPv4 int

	// SubnetLenIPv6 is a subnet length for IPv6 addresses used for rate
	// limiting requests.
	SubnetLenIPv6 int
}

// handler implements [proxy.RequestHandler] with rate limiting functionality.
type handler struct {
	buckets *gocache.Cache
	handler proxy.RequestHandler
	logger  *slog.Logger

	// mu protects buckets.
	mu *sync.Mutex

	allowlistAddrs []netip.Addr
	ratelimit      int
	subnetLenIPv4  int
	subnetLenIPv6  int
}

// NewRatelimitedRequestHandler wraps a RequestHandler with rate limiting
// functionality.  h must not be nil, c must be valid.
//
// TODO(d.kolyshev): !! Use.
func NewRatelimitedRequestHandler(h proxy.RequestHandler, c *Config) (wrapped proxy.RequestHandler) {
	if c.Ratelimit <= 0 {
		return h
	}

	return &handler{
		handler:        h,
		logger:         c.Logger,
		mu:             &sync.Mutex{},
		allowlistAddrs: c.AllowlistAddrs,
		ratelimit:      c.Ratelimit,
		subnetLenIPv4:  c.SubnetLenIPv4,
		subnetLenIPv6:  c.SubnetLenIPv6,
	}
}

// type check
var _ proxy.RequestHandler = (*handler)(nil)

// Handle implements the [proxy.RequestHandler] interface for *handler.  If the
// client is rate limited, it returns [proxy.ErrDrop] to signal that no response
// should be sent.
func (h *handler) Handle(p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
	if dctx.Proto == proxy.ProtoUDP && h.isRatelimited(dctx.Addr.Addr()) {
		h.logger.Debug("ratelimited based on ip only", "addr", dctx.Addr)

		return proxy.ErrDrop
	}

	return h.handler.Handle(p, dctx)
}

// limiterForIP returns a rate limiter for the specified IP address.
func (h *handler) limiterForIP(ip string) interface{} {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.buckets == nil {
		h.buckets = gocache.New(time.Hour, time.Hour)
	}

	value, found := h.buckets.Get(ip)
	if !found {
		value = rate.New(h.ratelimit, time.Second)
		h.buckets.Set(ip, value, time.Hour)
	}

	return value
}

// isRatelimited checks if the specified address should be rate limited.
func (h *handler) isRatelimited(addr netip.Addr) (ok bool) {
	addr = addr.Unmap()
	_, ok = slices.BinarySearchFunc(h.allowlistAddrs, addr, netip.Addr.Compare)
	if ok {
		return false
	}

	var pref netip.Prefix
	if addr.Is4() {
		pref = netip.PrefixFrom(addr, h.subnetLenIPv4)
	} else {
		pref = netip.PrefixFrom(addr, h.subnetLenIPv6)
	}
	pref = pref.Masked()

	// TODO(d.kolyshev):  Improve caching.  Decrease allocations.
	ipStr := pref.Addr().String()
	value := h.limiterForIP(ipStr)
	rl, ok := value.(*rate.RateLimiter)
	if !ok {
		h.logger.Error(
			"invalid value found in ratelimit cache",
			slogutil.KeyError,
			fmt.Errorf("bad type %T", value),
		)

		return false
	}

	allow, _ := rl.Try()

	return !allow
}
