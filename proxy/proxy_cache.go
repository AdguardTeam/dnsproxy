package proxy

import (
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// replyFromCache tries to get the response from general or subnet cache.
// Returns true on success.
func (p *Proxy) replyFromCache(d *DNSContext) (hit bool) {
	var ci *cacheItem
	hitMsg := "serving cached response"

	var expired bool
	var key []byte
	if !p.Config.EnableEDNSClientSubnet {
		ci, expired, key = p.cache.get(d.Req)
	} else if d.ecsReqMask != 0 {
		ci, expired, key = p.cache.getWithSubnet(d.Req, d.ecsReqIP, d.ecsReqMask)
		hitMsg = "serving response from subnet cache"
	} else {
		ci, expired, key = p.cache.get(d.Req)
		hitMsg = "serving response from general cache"
	}

	if hit = ci != nil; !hit {
		return hit
	}

	d.Res = ci.m
	d.CachedUpstreamAddr = ci.u

	log.Debug(hitMsg)

	if p.cache.optimistic && expired {
		// Build a reduced clone of the current context to avoid data race.
		minCtxClone := &DNSContext{
			// It is only read inside the optimistic resolver.
			CustomUpstreamConfig: d.CustomUpstreamConfig,
			ecsReqMask:           d.ecsReqMask,
		}
		if ecsReqIP := d.ecsReqIP; ecsReqIP != nil {
			minCtxClone.ecsReqIP = netutil.CloneIP(ecsReqIP)
		}
		if d.Req != nil {
			req := d.Req.Copy()
			addDO(req)
			minCtxClone.Req = req
		}

		go p.shortFlighter.ResolveOnce(minCtxClone, key)
	}

	return hit
}

// cacheResp stores the response of d if any in general or subnet cache.
func (p *Proxy) cacheResp(d *DNSContext) {
	upsAddr := ""
	if u := d.Upstream; u != nil {
		upsAddr = u.Address()
	}
	res := d.Res
	item := &cacheItem{
		m: res,
		u: upsAddr,
	}
	if !p.Config.EnableEDNSClientSubnet {
		p.cache.set(item)

		return
	}

	ip, mask, scope := parseECS(res)
	if ip != nil {
		if ip.Equal(d.ecsReqIP) && mask == d.ecsReqMask {
			log.Debug("ECS option in response: %s/%d", ip, scope)
			p.cache.setWithSubnet(item, ip, scope)
		} else {
			log.Debug("Invalid response from server: ECS data mismatch: %s/%d -- %s/%d",
				d.ecsReqIP, d.ecsReqMask, ip, mask)
		}
	} else if d.ecsReqIP != nil {
		// server doesn't support ECS - cache response for all subnets
		p.cache.setWithSubnet(item, ip, scope)
	} else {
		p.cache.set(item) // use general cache
	}
}
