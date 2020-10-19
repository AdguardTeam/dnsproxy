package proxy

import (
	"sort"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
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
		reply, elapsed, err := exchangeWithUpstream(dnsUpstream, req)
		if err == nil {
			p.updateRtt(dnsUpstream.Address(), elapsed)
			return reply, dnsUpstream, err
		}
		errs = append(errs, err)
		p.updateRtt(dnsUpstream.Address(), int(defaultTimeout/time.Millisecond))
	}
	return nil, nil, errorx.DecorateMany("all upstreams failed to exchange request", errs...)
}

func (p *Proxy) getSortedUpstreams(u []upstream.Upstream) []upstream.Upstream {
	// clone upstreams list to avoid race conditions
	p.rttLock.Lock()
	clone := make([]upstream.Upstream, len(u))
	copy(clone, u)

	sort.Slice(clone, func(i, j int) bool {
		if p.upstreamRttStats[clone[i].Address()] < p.upstreamRttStats[clone[j].Address()] {
			return true
		}
		return false
	})
	p.rttLock.Unlock()

	return clone
}

// exchangeWithUpstream returns result of Exchange with elapsed time
func exchangeWithUpstream(u upstream.Upstream, req *dns.Msg) (*dns.Msg, int, error) {
	startTime := time.Now()
	reply, err := u.Exchange(req)
	elapsed := int(time.Since(startTime) / time.Millisecond)
	if err != nil {
		log.Tracef("upstream %s failed to exchange %s in %d milliseconds. Cause: %s", u.Address(), req.Question[0].String(), elapsed, err)
	} else {
		log.Tracef("upstream %s successfully finished exchange of %s. Elapsed %d ms.", u.Address(), req.Question[0].String(), elapsed)
	}
	return reply, elapsed, err
}

// updateRtt updates rtt in upstreamRttStats for given address
func (p *Proxy) updateRtt(address string, rtt int) {
	p.rttLock.Lock()
	if p.upstreamRttStats == nil {
		p.upstreamRttStats = map[string]int{}
	}
	p.upstreamRttStats[address] = (p.upstreamRttStats[address] + rtt) / 2
	p.rttLock.Unlock()
}
