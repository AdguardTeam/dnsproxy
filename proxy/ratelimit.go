package proxy

import (
	"net"
	"sort"
	"time"

	rate "github.com/beefsack/go-rate"
	"github.com/AdguardTeam/golibs/log"
	gocache "github.com/patrickmn/go-cache"
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

// isRatelimited checks if the specified IP is ratelimited
func (p *Proxy) isRatelimited(addr net.Addr) bool {
	if p.Ratelimit <= 0 { // 0 -- disabled
		return false
	}

	ip := getIPString(addr)
	if ip == "" {
		log.Printf("failed to split %v into host/port", addr)
		return false
	}

	if len(p.RatelimitWhitelist) > 0 {
		i := sort.SearchStrings(p.RatelimitWhitelist, ip)

		if i < len(p.RatelimitWhitelist) && p.RatelimitWhitelist[i] == ip {
			// found, don't ratelimit
			return false
		}
	}

	value := p.limiterForIP(ip)
	rl, ok := value.(*rate.RateLimiter)
	if !ok {
		log.Println("SHOULD NOT HAPPEN: non-bool entry found in safebrowsing lookup cache")
		return false
	}

	allow, _ := rl.Try()
	return !allow
}
