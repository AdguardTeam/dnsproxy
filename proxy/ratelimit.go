package proxy

import (
	"net"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
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

// isRatelimited checks if the specified IP is ratelimited.
func (p *Proxy) isRatelimited(addr net.Addr) (ok bool) {
	if p.Ratelimit <= 0 {
		// The ratelimit is disabled.
		return false
	}

	ip, _ := netutil.IPAndPortFromAddr(addr)
	if ip == nil {
		log.Printf("failed to split %v into host/port", addr)

		return false
	}

	ipStr := ip.String()

	if len(p.RatelimitWhitelist) > 0 {
		slices.Sort(p.RatelimitWhitelist)
		_, ok = slices.BinarySearch(p.RatelimitWhitelist, ipStr)
		if ok {
			// Don't ratelimit if the IP is allowlisted.
			return false
		}
	}

	if len(ip) == net.IPv4len {
		ip = ip.Mask(p.RatelimitSubnetMaskIPv4)
	} else {
		ip = ip.Mask(p.RatelimitSubnetMaskIPv6)
	}

	// TODO(s.chzhen):  Improve caching.  Decrease allocations.
	ipStr = ip.String()

	value := p.limiterForIP(ipStr)
	rl, ok := value.(*rate.RateLimiter)
	if !ok {
		log.Printf("SHOULD NOT HAPPEN: %T found in ratelimit cache", value)

		return false
	}

	allow, _ := rl.Try()

	return !allow
}
