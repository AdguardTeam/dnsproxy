package proxy

import (
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// exchange -- sends DNS query to the upstream DNS server and returns the response
func (p *Proxy) exchange(req *dns.Msg, upstreams []upstream.Upstream) (reply *dns.Msg, u upstream.Upstream, err error) {
	qtype := req.Question[0].Qtype
	if p.UpstreamMode == UModeFastestAddr && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		reply, u, err = p.fastestAddr.ExchangeFastest(req, upstreams)
		return
	}

	if p.UpstreamMode == UModeParallel {
		reply, u, err = upstream.ExchangeParallel(upstreams, req)
		return
	}

	// UModeLoadBalance goes below

	if len(upstreams) == 1 {
		u = upstreams[0]
		reply, _, err = exchangeWithUpstream(u, req)
		return
	}

	// sort upstreams by rtt from fast to slow
	sortedUpstreams := p.getSortedUpstreams(upstreams)

	errs := []error{}
	for _, dnsUpstream := range sortedUpstreams {
		var elapsed int
		reply, elapsed, err = exchangeWithUpstream(dnsUpstream, req)
		if err == nil {
			p.updateRTT(dnsUpstream.Address(), elapsed)

			return reply, dnsUpstream, err
		}

		errs = append(errs, err)
		p.updateRTT(dnsUpstream.Address(), int(defaultTimeout/time.Millisecond))
	}

	return nil, nil, errors.List("all upstreams failed to exchange request", errs...)
}

func (p *Proxy) getSortedUpstreams(u []upstream.Upstream) []upstream.Upstream {
	// clone upstreams list to avoid race conditions
	clone := slices.Clone(u)

	p.rttLock.Lock()
	defer p.rttLock.Unlock()

	slices.SortFunc(clone, func(a, b upstream.Upstream) (res int) {
		// TODO(d.kolyshev): Use upstreams for sort comparing.
		return p.upstreamRTTStats[a.Address()] - p.upstreamRTTStats[b.Address()]
	})

	return clone
}

// exchangeWithUpstream returns result of Exchange with elapsed time
func exchangeWithUpstream(u upstream.Upstream, req *dns.Msg) (*dns.Msg, int, error) {
	startTime := time.Now()
	reply, err := u.Exchange(req)
	elapsed := time.Since(startTime)

	addr := u.Address()
	if err != nil {
		log.Error(
			"dnsproxy: upstream %s failed to exchange %s in %s: %s",
			addr,
			req.Question[0].String(),
			elapsed,
			err,
		)
	} else {
		log.Debug(
			"dnsproxy: upstream %s successfully finished exchange of %s; elapsed %s",
			addr,
			req.Question[0].String(),
			elapsed,
		)
	}

	return reply, int(elapsed.Milliseconds()), err
}

// updateRTT updates the round-trip time in upstreamRTTStats for given address.
func (p *Proxy) updateRTT(address string, rtt int) {
	p.rttLock.Lock()
	defer p.rttLock.Unlock()

	if p.upstreamRTTStats == nil {
		p.upstreamRTTStats = map[string]int{}
	}

	p.upstreamRTTStats[address] = (p.upstreamRTTStats[address] + rtt) / 2
}
