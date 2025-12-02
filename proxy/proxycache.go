package proxy

import (
	"net"
	"slices"
	"time"

	"github.com/miekg/dns"
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
	d.queryStatistics = cachedQueryStatistics(ci.u)

	p.logger.Debug(
		"replying from cache",
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

	// Trigger prefetch check on cache hit
	// Note: We trigger prefetch when hits reach threshold-1, so that the threshold-th access
	// will hit the prefetched cache. For example, if threshold=2:
	// - 1st access: hits=1, trigger prefetch
	// - 2nd access: hits=2, hit prefetched cache
	//
	// We skip this check for internal prefetch requests to avoid infinite retention loops
	// where the prefetch refresh itself counts as a hit.
	if !d.IsInternalPrefetch && p.Config.Prefetch != nil && p.Config.Prefetch.Enabled && p.cache.prefetchManager != nil {
		q := d.Req.Question[0]
		// CheckThreshold records the hit and returns true if hits >= threshold-1
		if p.cache.prefetchManager.CheckThreshold(q.Name, q.Qtype, d.ReqECS) {
			// Calculate approximate expiration time based on current time and TTL
			expireTime := time.Now().Add(time.Duration(ci.ttl) * time.Second)

			p.cache.prefetchManager.Add(q.Name, q.Qtype, d.ReqECS, d.CustomUpstreamConfig, expireTime)

			p.logger.Debug("prefetch triggered",
				"domain", q.Name,
				"qtype", dns.TypeToString[q.Qtype],
				"ttl", ci.ttl,
				"expire_time", expireTime)
		}
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
		dctxCache.set(d.Res, d.Upstream, d.IsInternalPrefetch, p.logger)

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
				"not caching response; subnet mismatch",
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

		p.logger.Debug("caching response", "ecs", ecs)

		dctxCache.setWithSubnet(d.Res, d.Upstream, ecs, d.IsInternalPrefetch, p.logger)
	case d.ReqECS != nil:
		// Cache the response for all subnets since the server doesn't support
		// EDNS Client Subnet option.
		dctxCache.setWithSubnet(d.Res, d.Upstream, &net.IPNet{IP: nil, Mask: nil}, d.IsInternalPrefetch, p.logger)
	default:
		dctxCache.set(d.Res, d.Upstream, d.IsInternalPrefetch, p.logger)
	}
}

// ClearCache clears the DNS cache of p.
func (p *Proxy) ClearCache() {
	if p.cache == nil {
		return
	}

	p.cache.clearItems()
	p.cache.clearItemsWithSubnet()
	p.logger.Debug("cache cleared")
}
