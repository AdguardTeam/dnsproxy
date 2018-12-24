package proxy

import (
	"net"
	"sort"
	"time"

	"github.com/beefsack/go-rate"
	gocache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

func (p *Proxy) limiterForIP(ip string) interface{} {
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

func (p *Proxy) isRatelimited(addr net.Addr) bool {
	if p.Ratelimit == 0 { // 0 -- disabled
		return false
	}

	ip := getIPString(addr)
	if ip == "" {
		log.Warnf("failed to split %v into host/port", addr)
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

func (p *Proxy) isRatelimitedForReply(ip string, size int) bool {
	if p.Ratelimit == 0 { // 0 -- disabled
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

	// For large UDP responses we try more times, effectively limiting per bandwidth
	// The exact number of times depends on the response size
	for i := 0; i < size/1000; i++ {
		allow, _ := rl.Try()
		if !allow { // not allowed -> ratelimited
			return true
		}
	}
	return false
}
