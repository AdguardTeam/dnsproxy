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

const (
	// upstreamRTTExponent is the exponent of the upstreams' round-trip time
	// estimates in their weights in [UpstreamModeLoadBalance]: an upstream's
	// weight is its estimate to the power of -upstreamRTTExponent, so an
	// upstream twice as slow gets an eighth of the share.
	upstreamRTTExponent = 3

	// upstreamRTTRingSize is the number of the latest successful exchange
	// times kept per upstream for its score, see [upstreamRTTStats.push].
	// Until the ring is full, the upstream's weight is pulled towards the
	// uniform share by the fraction of empty slots, so that it's filled.
	upstreamRTTRingSize = 16

	// upstreamRTTBaselineDecay is the time constant of the upstreams'
	// long-term round-trip time moving average of successful exchanges.  The
	// estimate of an upstream that hasn't answered for a while is pulled
	// towards it, so that a stale score fades even if the upstream is rarely
	// chosen.
	upstreamRTTBaselineDecay = 4 * time.Hour

	// upstreamRTTBaselineMin is the number of successful exchanges before an
	// upstream's baseline is used.  The baseline then starts as the average of
	// these samples without the largest one, so that a single slow answer,
	// such as the first one over a new connection, doesn't keep the upstream
	// out of use.
	upstreamRTTBaselineMin = 5

	// upstreamRTTFailPull is the time constant of the pull of an upstream's
	// estimate away from the timeout after its first failure, in units of
	// [Proxy.upstreamRTTDecay], see [upstreamRTTStats.pullDecay].
	upstreamRTTFailPull = 4

	// upstreamRTTMaxPullDecay is the upper bound of the time constant of the
	// pull of a failing upstream's estimate, see
	// [upstreamRTTStats.pullDecay].
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

// upstreamRTTStats is the statistics for a single upstream's round-trip time.
type upstreamRTTStats struct {
	// last is the time of the latest successful exchange.  It's zero if there
	// were none.
	last time.Time

	// failLast is the time of the latest failed exchange.  It's zero if there
	// were none.
	failLast time.Time

	// baseLast is the time of the latest update of base.  It's zero if there
	// were no updates.
	baseLast time.Time

	// ring holds the round-trip times of the latest successful exchanges in
	// microseconds: ring[:ringLen] while it's filling, then all of it with the
	// oldest at ringNext.
	ring [upstreamRTTRingSize]float64

	// score is the score of the samples in ring in microseconds, see
	// [ringScore].  It's zero if ring is empty.
	score float64

	// base is the long-term moving average of the round-trip time of
	// successful exchanges in microseconds.  It's zero if there were no
	// updates.
	base float64

	// baseNum is the number of samples in base.
	baseNum float64

	// baseMax is the largest of the first [upstreamRTTBaselineMin] samples
	// in base, in microseconds.
	baseMax float64

	// ringLen is the number of samples in ring.
	ringLen int

	// ringNext is the index in ring of the next sample.
	ringNext int

	// fails is the number of consecutive failed exchanges.
	fails uint
}

// push adds given RTT of a successful exchange measured at now to the ring,
// replacing the oldest sample once it's full.
func (stats *upstreamRTTStats) push(rtt time.Duration, now time.Time) {
	stats.last = now
	stats.ring[stats.ringNext] = float64(rtt.Microseconds())
	stats.ringNext = (stats.ringNext + 1) % upstreamRTTRingSize
	stats.ringLen = min(stats.ringLen+1, upstreamRTTRingSize)
	stats.score = ringScore(stats.ring[:stats.ringLen])
}

// ringScore returns (p90/2 + mean)/2 of samples, where p90 is their 90th
// percentile, linearly interpolated between the closest ranks.  The p90 term
// prices an upstream's tail, so that occasional slow answers lower its share
// more than the mean alone would.  samples must not be empty or longer than
// [upstreamRTTRingSize].
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

// updateBase adds given RTT of a successful exchange measured at now to the
// baseline.  The baseline starts as the plain
// average of the first [upstreamRTTBaselineMin] samples without the largest
// one.  After that, a sample's weight is the larger of 1/n, for the n-th
// sample, and its time-decay weight, so that the baseline stays the plain
// average until it holds about tau's worth of samples.  Otherwise the first
// samples would dominate it for a long time.  tau must be positive.
func (stats *upstreamRTTStats) updateBase(rtt time.Duration, now time.Time, tau time.Duration) {
	elapsed := max(now.Sub(stats.baseLast), 0)
	stats.baseLast = now
	stats.baseNum++

	sample := float64(rtt.Microseconds())
	if stats.baseNum <= upstreamRTTBaselineMin {
		stats.baseMax = max(stats.baseMax, sample)
		stats.base += (sample - stats.base) / stats.baseNum
		if n := stats.baseNum; n == upstreamRTTBaselineMin {
			stats.base = (n*stats.base - stats.baseMax) / (n - 1)
		}

		return
	}

	w := max(1/stats.baseNum, -math.Expm1(-elapsed.Seconds()/tau.Seconds()))
	stats.base += w * (sample - stats.base)
}

// pullDecay returns the time constant of the pull of a failing upstream's
// estimate away from the timeout, and of its weight towards the uniform share,
// given the time constant tau.  It's [upstreamRTTFailPull] times tau after the
// first failure and doubles with each consecutive one after that, up to
// [upstreamRTTMaxPullDecay], so that a dead upstream is retried less and less
// often.  tau must be positive.
func (stats *upstreamRTTStats) pullDecay(tau time.Duration) (d time.Duration) {
	d = upstreamRTTFailPull * tau
	for i := uint(1); i < stats.fails && d < upstreamRTTMaxPullDecay; i++ {
		d *= 2
	}

	return max(tau, min(d, upstreamRTTMaxPullDecay))
}

// estimate returns the round-trip time estimate in microseconds at now:
//
//   - the score of the ring, or timeout if the upstream never answered;
//   - pulled towards the baseline, once it holds [upstreamRTTBaselineMin]
//     samples, by a factor of e per tau since the latest answer, so that a
//     stale score fades;
//   - after a failure, pulled from timeout back to the above by a factor of e
//     per [upstreamRTTStats.pullDecay] of tau since the latest failure.
//
// tau and timeout must be positive.
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

// fill returns the fraction by which the upstream's weight is pulled towards
// the uniform share at now: the fraction of empty slots in its ring, so that a
// new upstream is filled, and after a failure, that fraction scaled by 1 -
// e^(-age/d), where age is the time since the latest failure and d is
// [upstreamRTTStats.pullDecay] of tau.  tau must be positive.
func (stats *upstreamRTTStats) fill(now time.Time, tau time.Duration) (f float64) {
	f = float64(upstreamRTTRingSize-stats.ringLen) / upstreamRTTRingSize
	if stats.fails > 0 {
		age := max(now.Sub(stats.failLast), 0)
		f *= -math.Expm1(-age.Seconds() / stats.pullDecay(tau).Seconds())
	}

	return f
}

// calcWeights returns the slice of weights, each corresponding to the upstream
// with the same index in the given slice.  An upstream's weight is its
// [upstreamRTTStats.estimate] to the power of -[upstreamRTTExponent],
// normalized to sum to 1, then pulled towards 1/len(ups) by its
// [upstreamRTTStats.fill].  ups elements must not be nil.
func (p *Proxy) calcWeights(ctx context.Context, ups []upstream.Upstream) (weights []float64) {
	weights = make([]float64, 0, len(ups))
	fill := make([]float64, 0, len(ups))

	now := p.time.Now()

	// unmeasured stands in for the upstreams without statistics.
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

// formatWeights returns the weights normalized to sum to 1, as space-separated
// address=weight pairs.  ups elements must not be nil.
func formatWeights(ups []upstream.Upstream, weights []float64) (s string) {
	var sum float64
	for _, w := range weights {
		sum += w
	}

	// num is the buffer for a formatted weight, such as "0.1667".
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

// updateRTT updates the round-trip time in [upstreamRTTStats] for given
// address.  ok is false if the exchange failed; failures don't affect the ring
// or the baseline.
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

	// Copy the logged values under the lock.
	score, samples, base, fails := stats.score, stats.ringLen, stats.base, stats.fails
	p.rttLock.Unlock()

	// Check the level first, so that the arguments aren't converted to
	// interface values when the line isn't logged.
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
