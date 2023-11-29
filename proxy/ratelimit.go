package proxy

import (
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/log"
	rate "github.com/beefsack/go-rate"
	gocache "github.com/patrickmn/go-cache"
	"golang.org/x/exp/slices"
)

func (p *Proxy) limiterForIP(ip string) interface{} {
	p.ratelimitLock.Lock()
	defer p.ratelimitLock.Unlock()
	if p.ratelimitBuckets == nil {
		p.ratelimitBuckets = gocache.New(time.Hour, time.Hour)
	}

	// check if ratelimiter for that IP already exists, if not, create
	value, found := p.ratelimitBuckets.Get(ip)
	if !found {
		value = rate.New(p.Ratelimit, time.Second)
		p.ratelimitBuckets.Set(ip, value, time.Hour)
	}

	return value
}

func (p *Proxy) isRatelimited(addr netip.Addr) (ok bool) {
	if p.Ratelimit <= 0 {
		// The ratelimit is disabled.
		return false
	}

	addr = addr.Unmap()
	// Already sorted by [Proxy.Init].
	_, ok = slices.BinarySearchFunc(p.RatelimitWhitelist, addr, netip.Addr.Compare)
	if ok {
		return false
	}

	var pref netip.Prefix
	if addr.Is4() {
		pref = netip.PrefixFrom(addr, p.RatelimitSubnetLenIPv4)
	} else {
		pref = netip.PrefixFrom(addr, p.RatelimitSubnetLenIPv6)
	}
	pref = pref.Masked()

	// TODO(s.chzhen):  Improve caching.  Decrease allocations.
	ipStr := pref.Addr().String()
	value := p.limiterForIP(ipStr)
	rl, ok := value.(*rate.RateLimiter)
	if !ok {
		log.Error("dnsproxy: %T found in ratelimit cache", value)

		return false
	}

	allow, _ := rl.Try()

	return !allow
}
