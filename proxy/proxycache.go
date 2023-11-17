package proxy

import (
	"net"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// cacheForContext returns cache object for the given context.
func (p *Proxy) cacheForContext(d *DNSContext) (c *cache) {
	if d.CustomUpstreamConfig != nil && d.CustomUpstreamConfig.cache != nil {
		return d.CustomUpstreamConfig.cache
	}

	return p.cache
}

// replyFromCache tries to get the response from general or subnet cache.  In
// case the cache is present in d, it's used first.  Returns true on success.
func (p *Proxy) replyFromCache(d *DNSContext) (hit bool) {
	dctxCache := p.cacheForContext(d)

	var ci *cacheItem
	var hitMsg string
	var expired bool
	var key []byte

	// TODO(d.kolyshev): Use EnableEDNSClientSubnet from dctxCache.
	if !p.Config.EnableEDNSClientSubnet {
		ci, expired, key = dctxCache.get(d.Req)
		hitMsg = "serving cached response"
	} else if d.ReqECS != nil {
		ci, expired, key = dctxCache.getWithSubnet(d.Req, d.ReqECS)
		hitMsg = "serving response from subnet cache"
	} else {
		ci, expired, key = dctxCache.get(d.Req)
		hitMsg = "serving response from general cache"
	}

	if hit = ci != nil; !hit {
		return hit
	}

	d.Res = ci.m
	d.CachedUpstreamAddr = ci.u

	log.Debug("dnsproxy: cache: %s", hitMsg)

	if dctxCache.optimistic && expired {
		// Build a reduced clone of the current context to avoid data race.
		minCtxClone := &DNSContext{
			// It is only read inside the optimistic resolver.
			CustomUpstreamConfig: d.CustomUpstreamConfig,
			ReqECS:               netutil.CloneIPNet(d.ReqECS),
		}
		if d.Req != nil {
			minCtxClone.Req = d.Req.Copy()
			addDO(minCtxClone.Req)
		}

		go p.shortFlighter.ResolveOnce(minCtxClone, key)
	}

	return hit
}

// cacheResp stores the response from d in general or subnet cache.  In case the
// cache is present in d, it's used first.
func (p *Proxy) cacheResp(d *DNSContext) {
	dctxCache := p.cacheForContext(d)

	if !p.EnableEDNSClientSubnet {
		dctxCache.set(d.Res, d.Upstream)

		return
	}

	switch ecs, scope := ecsFromMsg(d.Res); {
	case ecs != nil && d.ReqECS != nil:
		ones, bits := ecs.Mask.Size()
		reqOnes, _ := d.ReqECS.Mask.Size()

		// If FAMILY, SOURCE PREFIX-LENGTH, and SOURCE PREFIX-LENGTH bits of
		// ADDRESS in the response don't match the non-zero fields in the
		// corresponding query, the full response MUST be dropped.
		//
		// See RFC 7871 Section 7.3.
		//
		// TODO(a.meshkov):  The whole response MUST be dropped if ECS in it
		// doesn't correspond.
		if !ecs.IP.Mask(ecs.Mask).Equal(d.ReqECS.IP.Mask(d.ReqECS.Mask)) || ones != reqOnes {
			log.Debug("dnsproxy: cache: bad response: ecs %s does not match %s", ecs, d.ReqECS)

			return
		}

		// If SCOPE PREFIX-LENGTH is not longer than SOURCE PREFIX-LENGTH, store
		// SCOPE PREFIX-LENGTH bits of ADDRESS, and then mark the response as
		// valid for all addresses that fall within that range.
		//
		// See RFC 7871 Section 7.3.1.
		if scope < reqOnes {
			ecs.Mask = net.CIDRMask(scope, bits)
			ecs.IP = ecs.IP.Mask(ecs.Mask)
		}

		log.Debug("dnsproxy: cache: ecs option in response: %s", ecs)

		dctxCache.setWithSubnet(d.Res, d.Upstream, ecs)
	case d.ReqECS != nil:
		// Cache the response for all subnets since the server doesn't support
		// EDNS Client Subnet option.
		dctxCache.setWithSubnet(d.Res, d.Upstream, &net.IPNet{IP: nil, Mask: nil})
	default:
		dctxCache.set(d.Res, d.Upstream)
	}
}

// ClearCache clears the DNS cache of p.
func (p *Proxy) ClearCache() {
	if p.cache != nil {
		p.cache.clearItems()
		p.cache.clearItemsWithSubnet()
		log.Debug("dnsproxy: cache: cleared")
	}
}
