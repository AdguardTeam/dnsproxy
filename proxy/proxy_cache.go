package proxy

import (
	"net"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// replyFromCache tries to get the response from general or subnet cache.
// Returns true on success.
func (p *Proxy) replyFromCache(d *DNSContext) (hit bool) {
	var val *dns.Msg
	hitMsg := "Serving cached response"

	var expired bool
	var withSubnet bool
	var key []byte
	if !p.Config.EnableEDNSClientSubnet {
		val, expired, key = p.cache.Get(d.Req)
	} else if withSubnet = d.ecsReqMask != 0; withSubnet {
		val, expired, key = p.cache.GetWithSubnet(d.Req, d.ecsReqIP, d.ecsReqMask)
		hitMsg = "Serving response from subnet cache"
	} else if d.ecsReqMask == 0 {
		val, expired, key = p.cache.Get(d.Req)
		hitMsg = "Serving response from general cache"
	}

	if hit = val != nil; hit {
		d.Res = val
		log.Debug(hitMsg)
	}

	if p.cache.optimistic && hit && expired {
		// Build the minimal copy of current context to avoid data race.
		minCtxCopy := &DNSContext{
			// It is only readed inside the optimistic resolver.
			CustomUpstreamConfig: d.CustomUpstreamConfig,
			ecsReqMask:           d.ecsReqMask,
		}
		if ecsReqIP := d.ecsReqIP; ecsReqIP != nil {
			minCtxCopy.ecsReqIP = make(net.IP, len(ecsReqIP))
			copy(minCtxCopy.ecsReqIP, ecsReqIP)
		}
		if d.Req != nil {
			req := d.Req.Copy()
			addDO(req)
			minCtxCopy.Req = req
		}

		if !withSubnet {
			go p.shortFlighter.ResolveOnce(minCtxCopy, key)
		} else {
			go p.shortFlighterWithSubnet.ResolveOnce(minCtxCopy, key)
		}
	}

	return hit
}

// setInCache stores the response in general or subnet cache.
func (p *Proxy) setInCache(d *DNSContext) {
	res := d.Res
	if !p.Config.EnableEDNSClientSubnet {
		p.cache.Set(res)

		return
	}

	ip, mask, scope := parseECS(res)
	if ip != nil {
		if ip.Equal(d.ecsReqIP) && mask == d.ecsReqMask {
			log.Debug("ECS option in response: %s/%d", ip, scope)
			p.cache.SetWithSubnet(res, ip, scope)
		} else {
			log.Debug("Invalid response from server: ECS data mismatch: %s/%d -- %s/%d",
				d.ecsReqIP, d.ecsReqMask, ip, mask)
		}
	} else if d.ecsReqIP != nil {
		// server doesn't support ECS - cache response for all subnets
		p.cache.SetWithSubnet(res, ip, scope)
	} else {
		p.cache.Set(res) // use general cache
	}
}
