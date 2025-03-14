package proxy

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"gonum.org/v1/gonum/stat/sampleuv"
)

// exchangeUpstreams resolves req using the given upstreams.  It returns the DNS
// response, the upstream that successfully resolved the request, and the error
// if any.
func (p *Proxy) exchangeUpstreams(
	req *dns.Msg,
	ups []upstream.Upstream,
) (resp *dns.Msg, u upstream.Upstream, err error) {
	switch p.UpstreamMode {
	case UpstreamModeParallel:
		return upstream.ExchangeParallel(ups, req)
	case UpstreamModeFastestAddr:
		switch req.Question[0].Qtype {
		case dns.TypeA, dns.TypeAAAA:
			return p.fastestAddr.ExchangeFastest(req, ups)
		default:
			// Go on to the load-balancing mode.
		}
	default:
		// Go on to the load-balancing mode.
	}

	if len(ups) == 1 {
		u = ups[0]
		resp, _, err = p.exchange(u, req)
		if err != nil {
			return nil, nil, err
		}

		// TODO(e.burkov):  Consider updating the RTT of a single upstream.

		return resp, u, err
	}

	w := sampleuv.NewWeighted(p.calcWeights(ups), p.randSrc)
	var errs []error
	for i, ok := w.Take(); ok; i, ok = w.Take() {
		u = ups[i]

		var elapsed time.Duration
		resp, elapsed, err = p.exchange(u, req)
		if err == nil {
			p.updateRTT(u.Address(), elapsed)

			return resp, u, nil
		}

		errs = append(errs, err)

		// TODO(e.burkov):  Use the actual configured timeout or, perhaps, the
		// actual measured elapsed time.
		p.updateRTT(u.Address(), defaultTimeout)
	}

	err = fmt.Errorf("all upstreams failed to exchange request: %w", errors.Join(errs...))

	return nil, nil, err
}

// exchange returns the result of the DNS request exchange with the given
// upstream and the elapsed time in milliseconds.  It uses the given clock to
// measure the request duration.
func (p *Proxy) exchange(
	u upstream.Upstream,
	req *dns.Msg,
) (resp *dns.Msg, dur time.Duration, err error) {
	startTime := p.time.Now()
	resp, err = u.Exchange(req)

	// Don't use [time.Since] because it uses [time.Now].
	dur = p.time.Now().Sub(startTime)

	addr := u.Address()
	q := &req.Question[0]
	if err != nil {
		p.logger.Error(
			"exchange failed",
			"upstream", addr,
			"question", q,
			"duration", dur,
			slogutil.KeyError, err,
		)
	} else {
		p.logger.Debug(
			"exchange successfully finished",
			"upstream", addr,
			"question", q,
			"duration", dur,
		)
	}

	return resp, dur, err
}

// upstreamRTTStats is the statistics for a single upstream's round-trip time.
type upstreamRTTStats struct {
	// rttSum is the sum of all the round-trip times in microseconds.  The
	// float64 type is used since it's capable of representing about 285 years
	// in microseconds.
	rttSum float64

	// reqNum is the number of requests to the upstream.  The float64 type is
	// used since to avoid unnecessary type conversions.
	reqNum float64
}

// update returns updated stats after adding given RTT.
func (stats upstreamRTTStats) update(rtt time.Duration) (updated upstreamRTTStats) {
	return upstreamRTTStats{
		rttSum: stats.rttSum + float64(rtt.Microseconds()),
		reqNum: stats.reqNum + 1,
	}
}

// calcWeights returns the slice of weights, each corresponding to the upstream
// with the same index in the given slice.
func (p *Proxy) calcWeights(ups []upstream.Upstream) (weights []float64) {
	weights = make([]float64, 0, len(ups))

	p.rttLock.Lock()
	defer p.rttLock.Unlock()

	for _, u := range ups {
		stat := p.upstreamRTTStats[u.Address()]
		if stat.rttSum == 0 || stat.reqNum == 0 {
			// Use 1 as the default weight.
			weights = append(weights, 1)
		} else {
			weights = append(weights, 1/(stat.rttSum/stat.reqNum))
		}
	}

	return weights
}

// updateRTT updates the round-trip time in [upstreamRTTStats] for given
// address.
func (p *Proxy) updateRTT(address string, rtt time.Duration) {
	p.rttLock.Lock()
	defer p.rttLock.Unlock()

	if p.upstreamRTTStats == nil {
		p.upstreamRTTStats = map[string]upstreamRTTStats{}
	}

	p.upstreamRTTStats[address] = p.upstreamRTTStats[address].update(rtt)
}
