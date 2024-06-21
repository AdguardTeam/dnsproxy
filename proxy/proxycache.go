package proxy

import (
	"net"
	"slices"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
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
	var cacheSource string
	var expired bool
	var key []byte

	// TODO(d.kolyshev): Use EnableEDNSClientSubnet from dctxCache.
	if p.Config.EnableEDNSClientSubnet && d.ReqECS != nil {
		ci, expired, key = dctxCache.getWithSubnet(d.Req, d.ReqECS)
		cacheSource = "subnet cache"
	} else {
		ci, expired, key = dctxCache.get(d.Req)
		cacheSource = "general cache"
	}

	if hit = ci != nil; !hit {
		return hit
	}

	d.Res = ci.m
	d.CachedUpstreamAddr = ci.u

	p.logger.Debug(
		"replying from cache",
		slogutil.KeyPrefix, CacheLogPrefix,
		"source", cacheSource,
		"ecs_enabled", p.Config.EnableEDNSClientSubnet,
	)

	if dctxCache.optimistic && expired {
		// Build a reduced clone of the current context to avoid data race.
		minCtxClone := &DNSContext{
			// It is only read inside the optimistic resolver.
			CustomUpstreamConfig: d.CustomUpstreamConfig,
			ReqECS:               cloneIPNet(d.ReqECS),
			IsPrivateClient:      d.IsPrivateClient,
		}
		if d.Req != nil {
			minCtxClone.Req = d.Req.Copy()
			addDO(minCtxClone.Req)
		}

		go p.shortFlighter.resolveOnce(minCtxClone, key, p.logger)
	}

	return hit
}

// cloneIPNet returns a deep clone of n.
func cloneIPNet(n *net.IPNet) (clone *net.IPNet) {
	if n == nil {
		return nil
	}

	return &net.IPNet{
		IP:   slices.Clone(n.IP),
		Mask: slices.Clone(n.Mask),
	}
}

// cacheResp stores the response from d in general or subnet cache.  In case the
// cache is present in d, it's used first.
func (p *Proxy) cacheResp(d *DNSContext) {
	dctxCache := p.cacheForContext(d)

	if !p.EnableEDNSClientSubnet {
		dctxCache.set(d.Res, d.Upstream, p.logger)

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
			p.logger.Debug(
				"ecs does not match",
				slogutil.KeyPrefix, CacheLogPrefix,
				"ecs", ecs,
				"req_ecs", d.ReqECS,
			)

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

		p.logger.Debug("ecs option in response", slogutil.KeyPrefix, CacheLogPrefix, "ecs", ecs)

		dctxCache.setWithSubnet(d.Res, d.Upstream, ecs, p.logger)
	case d.ReqECS != nil:
		// Cache the response for all subnets since the server doesn't support
		// EDNS Client Subnet option.
		dctxCache.setWithSubnet(d.Res, d.Upstream, &net.IPNet{IP: nil, Mask: nil}, p.logger)
	default:
		dctxCache.set(d.Res, d.Upstream, p.logger)
	}
}

// ClearCache clears the DNS cache of p.
func (p *Proxy) ClearCache() {
	if p.cache != nil {
		p.cache.clearItems()
		p.cache.clearItemsWithSubnet()
		p.logger.Debug("cleared", slogutil.KeyPrefix, CacheLogPrefix)
	}
}
