package proxy

import (
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// replyFromCache tries to get the response from general or subnet cache.
// Returns true on success.
func (p *Proxy) replyFromCache(d *DNSContext) (hit bool, isExpired bool) {
	if !p.Config.EnableEDNSClientSubnet {
		val, ok := p.cache.Get(d.Req)
		if val != nil {
			d.Res = val
			log.Debug("Serving cached response")

			return true, !ok
		}

		return false, false
	}

	if d.ecsReqMask != 0 && p.cacheSubnet != nil {
		val, ok := p.cacheSubnet.GetWithSubnet(d.Req, d.ecsReqIP, d.ecsReqMask)
		if val != nil {
			d.Res = val
			log.Debug("Serving response from subnet cache")

			return true, !ok
		}
	} else if d.ecsReqMask == 0 && p.cache != nil {
		val, ok := p.cache.Get(d.Req)
		if val != nil {
			d.Res = val
			log.Debug("Serving response from general cache")

			return true, !ok
		}
	}

	return false, false
}

// setInCache stores the response in general or subnet cache.
func (p *Proxy) setInCache(d *DNSContext, resp *dns.Msg) {
	if !p.Config.EnableEDNSClientSubnet {
		p.cache.Set(resp)
		return
	}

	ip, mask, scope := parseECS(resp)
	if ip != nil {
		if ip.Equal(d.ecsReqIP) && mask == d.ecsReqMask {
			log.Debug("ECS option in response: %s/%d", ip, scope)
			p.cacheSubnet.SetWithSubnet(resp, ip, scope)
		} else {
			log.Debug("Invalid response from server: ECS data mismatch: %s/%d -- %s/%d",
				d.ecsReqIP, d.ecsReqMask, ip, mask)
		}
	} else if d.ecsReqIP != nil {
		// server doesn't support ECS - cache response for all subnets
		p.cacheSubnet.SetWithSubnet(resp, ip, scope)
	} else {
		p.cache.Set(resp) // use general cache
	}
}
