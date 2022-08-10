package proxy

import (
	"net"
	"sort"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	rate "github.com/beefsack/go-rate"
	gocache "github.com/patrickmn/go-cache"
)

func (p *Proxy) limiterForIP(ip string) any {
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

// isRatelimited checks if the specified IP is ratelimited
func (p *Proxy) isRatelimited(addr net.Addr) bool {
	if p.Ratelimit <= 0 { // 0 -- disabled
		return false
	}

	ip, _ := netutil.IPAndPortFromAddr(addr)
	if ip == nil {
		log.Printf("failed to split %v into host/port", addr)

		return false
	}

	ipStr := ip.String()
	if len(p.RatelimitWhitelist) > 0 {
		i := sort.SearchStrings(p.RatelimitWhitelist, ipStr)
		if i < len(p.RatelimitWhitelist) && p.RatelimitWhitelist[i] == ipStr {
			// Don't ratelimit if the ip is allowlisted.
			return false
		}
	}

	value := p.limiterForIP(ipStr)
	rl, ok := value.(*rate.RateLimiter)
	if !ok {
		log.Println("SHOULD NOT HAPPEN: non-bool entry found in safebrowsing lookup cache")
		return false
	}

	allow, _ := rl.Try()
	return !allow
}
