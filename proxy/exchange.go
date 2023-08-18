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
			p.updateRtt(dnsUpstream.Address(), elapsed)

			return reply, dnsUpstream, err
		}
		errs = append(errs, err)
		p.updateRtt(dnsUpstream.Address(), int(defaultTimeout/time.Millisecond))
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
		return p.upstreamRttStats[a.Address()] - p.upstreamRttStats[b.Address()]
	})

	return clone
}

// exchangeWithUpstream returns result of Exchange with elapsed time
func exchangeWithUpstream(u upstream.Upstream, req *dns.Msg) (*dns.Msg, int, error) {
	startTime := time.Now()
	reply, err := u.Exchange(req)
	elapsed := time.Since(startTime)
	if err != nil {
		log.Error(
			"upstream %s failed to exchange %s in %s. Cause: %s",
			u.Address(),
			req.Question[0].String(),
			elapsed,
			err,
		)
	} else {
		log.Tracef(
			"upstream %s successfully finished exchange of %s. Elapsed %s.",
			u.Address(),
			req.Question[0].String(),
			elapsed,
		)
	}

	return reply, int(elapsed.Milliseconds()), err
}

// updateRtt updates rtt in upstreamRttStats for given address
func (p *Proxy) updateRtt(address string, rtt int) {
	p.rttLock.Lock()
	defer p.rttLock.Unlock()

	if p.upstreamRttStats == nil {
		p.upstreamRttStats = map[string]int{}
	}
	p.upstreamRttStats[address] = (p.upstreamRttStats[address] + rtt) / 2
}
