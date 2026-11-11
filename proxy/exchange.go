package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"gonum.org/v1/gonum/stat/sampleuv"
)

// Parameters of the load_balance round-trip time model, see [upstreamRTTStats].
// They were tuned by replaying exchange times recorded on a production
// deployment with six DoH upstreams.
const (
	// upstreamRTTExponent is p in an upstream's weight est^-p: an upstream
	// twice as slow gets an eighth of the share.  Against p = 2, p = 3 cut the
	// mean wait by about a quarter; higher values gained little and sent most
	// queries to one upstream.
	upstreamRTTExponent = 3

	// upstreamRTTRingSize is the number of latest successful exchange times
	// kept per upstream.  16 tracked the p90 and recovered from a slow first
	// answer better than 32.
	upstreamRTTRingSize = 16

	// upstreamRTTBaselineDecay is the time constant of an upstream's long-term
	// average.  4h follows a lasting change within hours, where 24h took days.
	upstreamRTTBaselineDecay = 4 * time.Hour

	// upstreamRTTBaselineMin is the number of answers before an upstream's
	// baseline is used.
	upstreamRTTBaselineMin = 5

	// upstreamRTTFailPull is the fade time of the first failure's penalty, in
	// units of [Proxy.upstreamRTTDecay].  4 halved the queries stalled by an
	// outage against 1.
	upstreamRTTFailPull = 4

	// upstreamRTTMaxPullDecay caps the fade time of a failing upstream's
	// penalty, so that a dead upstream is still probed about once a day.
	upstreamRTTMaxPullDecay = 24 * time.Hour
)

// exchangeUpstreams resolves req using the given upstreams.  It returns the DNS
// response, the upstream that successfully resolved the request, and the error
// if any.
func (p *Proxy) exchangeUpstreams(
	ctx context.Context,
	req *dns.Msg,
	ups []upstream.Upstream,
) (resp *dns.Msg, u upstream.Upstream, err error) {
	switch p.upstreamMode {
	case UpstreamModeParallel:
		return upstream.ExchangeParallel(ctx, ups, req)
	case UpstreamModeFastestAddr:
		switch req.Question[0].Qtype {
		case dns.TypeA, dns.TypeAAAA:
			return p.fastestAddr.ExchangeFastest(ctx, req, ups)
		default:
			// Go on to the load-balancing mode.
		}
	default:
		// Go on to the load-balancing mode.
	}

	if len(ups) == 1 {
		u = ups[0]
		resp, _, err = p.exchange(ctx, u, req)
		if err != nil {
			return nil, nil, err
		}

		// TODO(e.burkov):  Consider updating the RTT of a single upstream.

		return resp, u, err
	}

	w := sampleuv.NewWeighted(p.calcWeights(ctx, ups), p.randSrc)
	var errs []error
	for i, ok := w.Take(); ok; i, ok = w.Take() {
		u = ups[i]

		var elapsed time.Duration
		resp, elapsed, err = p.exchange(ctx, u, req)
		if err == nil {
			p.updateRTT(ctx, u.Address(), elapsed, true)

			return resp, u, nil
		}

		errs = append(errs, err)

		p.updateRTT(ctx, u.Address(), p.upstreamTimeout, false)
	}

	err = fmt.Errorf("all upstreams failed to exchange request: %w", errors.Join(errs...))

	return nil, nil, err
}

// exchange returns the result of the DNS request exchange with the given
// upstream and the elapsed time.  u and req must not be nil.
func (p *Proxy) exchange(
	ctx context.Context,
	u upstream.Upstream,
	req *dns.Msg,
) (resp *dns.Msg, dur time.Duration, err error) {
	startTime := p.time.Now()
	resp, err = u.Exchange(ctx, req)

	// Don't use [time.Since] because it uses [time.Now].
	dur = p.time.Now().Sub(startTime)

	addr := u.Address()
	q := &req.Question[0]
	if err != nil {
		p.logger.ErrorContext(
			ctx,
			"exchange failed",
			"upstream", addr,
			"question", q,
			"duration", dur,
			slogutil.KeyError, err,
		)
	} else {
		p.logger.DebugContext(
			ctx,
			"exchange successfully finished",
			"upstream", addr,
			"question", q,
			"duration", dur,
		)
	}

	return resp, dur, err
}

// upstreamRTTStats is the round-trip time model of one upstream in
// [UpstreamModeLoadBalance], with tau being [Proxy.upstreamRTTDecay]:
//
//   - The score is (p90/2 + mean)/2 of the latest successful exchange times.
//     The p90 term prices the upstream's tail, so occasional slow answers
//     lower its share more than the mean alone would.
//   - The estimate is the score, pulled towards a long-term baseline by a
//     factor of e per tau since the latest answer, so a stale score fades
//     even if the upstream is rarely picked.
//   - A failure sets the estimate to the timeout, which fades back over
//     [upstreamRTTStats.pullDecay].  Failures enter neither the ring nor the
//     baseline.
//   - The weight is est^-[upstreamRTTExponent], normalized, then pulled
//     towards the uniform share by [upstreamRTTStats.fill], so that a new or
//     recovering upstream is explored.
type upstreamRTTStats struct {
	// last is the time of the latest successful exchange, if any.
	last time.Time

	// failLast is the time of the latest failed exchange, if any.
	failLast time.Time

	// baseLast is the time of the latest update of base, if any.
	baseLast time.Time

	// ring holds the latest successful exchange times in microseconds:
	// ring[:ringLen] while it fills, then all of it with the oldest at
	// ringNext.
	ring [upstreamRTTRingSize]float64

	// score is [ringScore] of ring in microseconds, or zero if ring is empty.
	score float64

	// base is the long-term average of successful exchange times in
	// microseconds.
	base float64

	// baseNum is the number of samples in base.
	baseNum float64

	// baseMax is the largest of the first [upstreamRTTBaselineMin] samples in
	// microseconds.
	baseMax float64

	// ringLen is the number of samples in ring.
	ringLen int

	// ringNext is the index in ring of the next sample.
	ringNext int

	// fails is the number of consecutive failed exchanges.
	fails uint
}

// push adds a successful exchange time to the ring, replacing the oldest one
// once it's full.
func (stats *upstreamRTTStats) push(rtt time.Duration, now time.Time) {
	stats.last = now
	stats.ring[stats.ringNext] = float64(rtt.Microseconds())
	stats.ringNext = (stats.ringNext + 1) % upstreamRTTRingSize
	stats.ringLen = min(stats.ringLen+1, upstreamRTTRingSize)
	stats.score = ringScore(stats.ring[:stats.ringLen])
}

// ringScore returns (p90/2 + mean)/2 of samples, with the 90th percentile
// interpolated linearly between the closest ranks.  samples must not be empty or
// longer than [upstreamRTTRingSize].
func ringScore(samples []float64) (score float64) {
	buf := [upstreamRTTRingSize]float64{}
	sorted := buf[:len(samples)]
	copy(sorted, samples)
	slices.Sort(sorted)

	var sum float64
	for _, s := range sorted {
		sum += s
	}

	mean := sum / float64(len(sorted))

	pos := 0.9 * float64(len(sorted)-1)
	i := int(pos)
	p90 := sorted[i]
	if i+1 < len(sorted) {
		p90 += (pos - float64(i)) * (sorted[i+1] - sorted[i])
	}

	return (p90/2 + mean) / 2
}

// updateBase adds a successful exchange time to the baseline.  The baseline
// starts as the average of the first [upstreamRTTBaselineMin] samples without
// the largest one, so that one slow answer, such as the first over a new
// connection, can't keep the upstream out of use.  After that, the n-th sample
// weighs max(1/n, 1 - e^(-elapsed/tau)), so the baseline stays a plain average
// until it holds about tau's worth of samples instead of being dominated by
// the first ones.  tau must be positive.
func (stats *upstreamRTTStats) updateBase(rtt time.Duration, now time.Time, tau time.Duration) {
	elapsed := max(now.Sub(stats.baseLast), 0)
	stats.baseLast = now
	stats.baseNum++

	sample := float64(rtt.Microseconds())
	if stats.baseNum <= upstreamRTTBaselineMin {
		stats.baseMax = max(stats.baseMax, sample)
		stats.base += (sample - stats.base) / stats.baseNum
		if stats.baseNum == upstreamRTTBaselineMin {
			n := float64(upstreamRTTBaselineMin)
			stats.base = (n*stats.base - stats.baseMax) / (n - 1)
		}

		return
	}

	w := max(1/stats.baseNum, -math.Expm1(-elapsed.Seconds()/tau.Seconds()))
	stats.base += w * (sample - stats.base)
}

// pullDecay returns the fade time of a failing upstream's penalty:
// [upstreamRTTFailPull] times tau after the first failure, doubling with each
// consecutive one up to [upstreamRTTMaxPullDecay], so that a dead upstream is
// retried less and less often.  tau must be positive.
func (stats *upstreamRTTStats) pullDecay(tau time.Duration) (d time.Duration) {
	d = upstreamRTTFailPull * tau
	for i := uint(1); i < stats.fails && d < upstreamRTTMaxPullDecay; i++ {
		d *= 2
	}

	return max(tau, min(d, upstreamRTTMaxPullDecay))
}

// estimate returns the round-trip time estimate in microseconds at now, see
// [upstreamRTTStats].  An upstream that never answered is estimated at
// timeout.  tau and timeout must be positive.
func (stats *upstreamRTTStats) estimate(now time.Time, tau, timeout time.Duration) (est float64) {
	timeoutUS := float64(timeout.Microseconds())

	est = timeoutUS
	if stats.ringLen > 0 {
		est = stats.score
		if stats.baseNum >= upstreamRTTBaselineMin {
			age := max(now.Sub(stats.last), 0)
			w := math.Exp(-age.Seconds() / tau.Seconds())
			est = w*est + (1-w)*stats.base
		}
	}

	if stats.fails > 0 {
		age := max(now.Sub(stats.failLast), 0)
		w := math.Exp(-age.Seconds() / stats.pullDecay(tau).Seconds())
		est = w*timeoutUS + (1-w)*est
	}

	// Keep the weight finite for sub-microsecond answers.
	return max(est, 1)
}

// fill returns the fraction by which the weight is pulled towards the uniform
// share at now: the fraction of empty ring slots, scaled after a failure by
// 1 - e^(-age/[upstreamRTTStats.pullDecay]), so that the pull returns as the
// penalty fades.  tau must be positive.
func (stats *upstreamRTTStats) fill(now time.Time, tau time.Duration) (f float64) {
	f = float64(upstreamRTTRingSize-stats.ringLen) / upstreamRTTRingSize
	if stats.fails > 0 {
		age := max(now.Sub(stats.failLast), 0)
		f *= -math.Expm1(-age.Seconds() / stats.pullDecay(tau).Seconds())
	}

	return f
}

// calcWeights returns the selection weight of each of ups, see
// [upstreamRTTStats].  ups elements must not be nil.
func (p *Proxy) calcWeights(ctx context.Context, ups []upstream.Upstream) (weights []float64) {
	weights = make([]float64, 0, len(ups))
	fill := make([]float64, 0, len(ups))

	now := p.time.Now()

	var unmeasured upstreamRTTStats

	p.rttLock.Lock()
	for _, u := range ups {
		stat := p.upstreamRTTStats[u.Address()]
		if stat == nil {
			stat = &unmeasured
		}

		est := stat.estimate(now, p.upstreamRTTDecay, p.upstreamTimeout)
		weights = append(weights, math.Pow(est, -upstreamRTTExponent))
		fill = append(fill, stat.fill(now, p.upstreamRTTDecay))
	}
	p.rttLock.Unlock()

	var sum float64
	for _, w := range weights {
		sum += w
	}

	uniform := 1 / float64(len(ups))
	for i, w := range weights {
		weights[i] = (1-fill[i])*w/sum + fill[i]*uniform
	}

	if p.logger.Enabled(ctx, slog.LevelDebug) {
		p.logger.DebugContext(ctx, "load_balance weights", "weights", formatWeights(ups, weights))
	}

	return weights
}

// formatWeights returns weights, normalized to sum to 1, as space-separated
// address=weight pairs.  ups elements must not be nil.
func formatWeights(ups []upstream.Upstream, weights []float64) (s string) {
	var sum float64
	for _, w := range weights {
		sum += w
	}

	var num [16]byte

	b := &strings.Builder{}
	b.Grow(len(ups) * 48)
	for i, u := range ups {
		if i > 0 {
			b.WriteByte(' ')
		}

		b.WriteString(u.Address())
		b.WriteByte('=')
		b.Write(strconv.AppendFloat(num[:0], weights[i]/sum, 'f', 4, 64))
	}

	return b.String()
}

// updateRTT records the outcome of an exchange with the upstream at address.
func (p *Proxy) updateRTT(ctx context.Context, address string, rtt time.Duration, ok bool) {
	now := p.time.Now()

	p.rttLock.Lock()
	if p.upstreamRTTStats == nil {
		p.upstreamRTTStats = map[string]*upstreamRTTStats{}
	}

	stats := p.upstreamRTTStats[address]
	if stats == nil {
		stats = &upstreamRTTStats{}
		p.upstreamRTTStats[address] = stats
	}

	if ok {
		stats.push(rtt, now)
		stats.updateBase(rtt, now, upstreamRTTBaselineDecay)
		stats.fails = 0
	} else {
		stats.fails++
		stats.failLast = now
	}

	score, samples, base, fails := stats.score, stats.ringLen, stats.base, stats.fails
	p.rttLock.Unlock()

	// Don't box the arguments when the line isn't logged.
	if !p.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}

	p.logger.DebugContext(
		ctx,
		"updated upstream rtt",
		"upstream", address,
		"rtt", rtt,
		"ok", ok,
		"score", usDuration(score),
		"samples", samples,
		"base", usDuration(base),
		"fails", fails,
	)
}

// usDuration converts a round-trip time in microseconds to a duration.
func usDuration(us float64) (d time.Duration) {
	return time.Duration(math.Round(us)) * time.Microsecond
}
