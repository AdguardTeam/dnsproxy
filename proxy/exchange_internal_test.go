package proxy

import (
	"context"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamWithErrorRate returns an [upstream.Upstream] that responds with an
// error every [rate] requests.  The returned upstream isn't safe for concurrent
// use.
func newUpstreamWithErrorRate(rate uint, name string) (u upstream.Upstream) {
	var n uint

	return &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			n++
			if n%rate == 0 {
				return nil, assert.AnError
			}

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return name },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
}

// measuredUpstream is an [upstream.Upstream] that increments the counter every
// time it's used.
type measuredUpstream struct {
	// Upstream is embedded here to avoid implementing all the methods.
	upstream.Upstream

	// stats is the statistics collector for current upstream.
	stats map[string]int64
}

// type check
var _ upstream.Upstream = measuredUpstream{}

// Exchange implements the [upstream.Upstream] interface for measuredUpstream.
func (u measuredUpstream) Exchange(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	u.stats[u.Address()]++

	return u.Upstream.Exchange(ctx, req)
}

// pickShare returns the fraction of n picks that went to addr.
func pickShare(picks map[string]int64, addr string, n int) (f float64) {
	return float64(picks[addr]) / float64(n)
}

func TestProxy_Exchange_loadBalance(t *testing.T) {
	// Make the test deterministic.
	randSrc := rand.New(rand.NewPCG(42, 42))

	const (
		testRTT     = 1 * time.Second
		requestsNum = 10_000

		// reqInterval is the time between requests.  requestsNum requests
		// span many [DefaultUpstreamRTTDecay] periods.
		reqInterval = DefaultUpstreamRTTDecay / 100
	)

	// clock returns the value of currentNow and advances it by a microsecond.
	// Upstreams advance currentNow by their RTT.
	currentNow := time.Unix(0, 0)
	clock := &faketime.Clock{
		OnNow: func() (now time.Time) {
			now, currentNow = currentNow, currentNow.Add(time.Microsecond)

			return now
		},
	}

	fastUps := &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = currentNow.Add(testRTT / 100)

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "fast" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
	slowerUps := &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = currentNow.Add(testRTT / 10)

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "slower" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
	slowestUps := &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = currentNow.Add(testRTT / 2)

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "slowest" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	err1Ups := &testUpstream{
		OnExchange: func(_ context.Context, _ *dns.Msg) (r *dns.Msg, err error) {
			return nil, assert.AnError
		},
		OnAddress: func() (addr string) { return "error1" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
	err2Ups := &testUpstream{
		OnExchange: func(_ context.Context, _ *dns.Msg) (r *dns.Msg, err error) {
			return nil, assert.AnError
		},
		OnAddress: func() (addr string) { return "error2" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	singleError := &sync.Once{}
	// fastestUps responds with an error on the first request.
	fastestUps := &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			singleError.Do(func() { err = assert.AnError })
			currentNow = currentNow.Add(testRTT / 200)

			return (&dns.Msg{}).SetReply(req), err
		},
		OnAddress: func() (addr string) { return "fastest" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	each200 := newUpstreamWithErrorRate(200, "each_200")
	each100 := newUpstreamWithErrorRate(100, "each_100")
	each50 := newUpstreamWithErrorRate(50, "each_50")

	testCases := []struct {
		// check asserts the properties of the picks per upstream address.
		check func(t *testing.T, picks map[string]int64)
		// wantRTT, if not nil, are the expected RTT estimates at the end.
		wantRTT map[string]time.Duration
		name    string
		servers []upstream.Upstream
	}{{
		check: func(t *testing.T, picks map[string]int64) {
			// Every ring is filled first, then shares go as RTT^-3, so a 10x
			// slower upstream gets about 1/1000.
			assert.GreaterOrEqual(t, picks[slowerUps.Address()], int64(upstreamRTTRingSize))
			assert.GreaterOrEqual(t, picks[slowestUps.Address()], int64(upstreamRTTRingSize))
			assert.Greater(t, pickShare(picks, fastUps.Address(), requestsNum), 0.99)
			assert.Less(t, pickShare(picks, slowerUps.Address(), requestsNum), 0.01)
			assert.Less(t, pickShare(picks, slowestUps.Address(), requestsNum), 0.01)
		},
		wantRTT: map[string]time.Duration{
			fastUps.Address():    testRTT / 100,
			slowerUps.Address():  testRTT / 10,
			slowestUps.Address(): testRTT / 2,
		},
		name:    "all_good",
		servers: []upstream.Upstream{slowestUps, slowerUps, fastUps},
	}, {
		check: func(t *testing.T, picks map[string]int64) {
			// An upstream that never answers is still probed, less and less
			// often, as its penalty fades slower after each failure.
			assert.Positive(t, picks[err1Ups.Address()])
			assert.Less(t, pickShare(picks, err1Ups.Address(), requestsNum), 0.01)
			assert.Greater(t, pickShare(picks, fastUps.Address(), requestsNum), 0.99)
		},
		name:    "one_bad",
		servers: []upstream.Upstream{fastUps, err1Ups, slowerUps},
	}, {
		check: func(t *testing.T, picks map[string]int64) {
			// Every request tries every upstream.
			assert.Equal(t, map[string]int64{
				err1Ups.Address(): requestsNum,
				err2Ups.Address(): requestsNum,
			}, picks)
		},
		name:    "all_bad",
		servers: []upstream.Upstream{err2Ups, err1Ups},
	}, {
		check: func(t *testing.T, picks map[string]int64) {
			// A single failure fades, and the fastest upstream takes over.
			assert.Greater(t, pickShare(picks, fastestUps.Address(), requestsNum), 0.8)
			assert.Greater(t, picks[fastUps.Address()], picks[slowerUps.Address()])
		},
		wantRTT: map[string]time.Duration{
			fastUps.Address():    testRTT / 100,
			slowerUps.Address():  testRTT / 10,
			fastestUps.Address(): testRTT / 200,
		},
		name:    "error_once",
		servers: []upstream.Upstream{fastUps, slowerUps, fastestUps},
	}, {
		check: func(t *testing.T, picks map[string]int64) {
			// The more often an upstream fails, the fewer requests it gets.
			assert.Greater(t, picks[each200.Address()], picks[each100.Address()])
			assert.Greater(t, picks[each100.Address()], picks[each50.Address()])
		},
		name:    "error_each_nth",
		servers: []upstream.Upstream{each200, each100, each50},
	}}

	req := dnsproxytest.NewTestRequest()
	cli := netip.AddrPortFrom(netutil.IPv4Localhost(), 1234)

	for _, tc := range testCases {
		ups := []upstream.Upstream{}
		stats := map[string]int64{}
		for _, s := range tc.servers {
			ups = append(ups, measuredUpstream{
				Upstream: s,
				stats:    stats,
			})
		}

		p := mustNew(t, &Config{
			Logger:        testLogger,
			UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
			TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
			UpstreamConfig: &UpstreamConfig{
				Upstreams: ups,
			},
			TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		})
		p.time = clock
		p.randSrc = randSrc

		check, wantRTT := tc.check, tc.wantRTT

		t.Run(tc.name, func(t *testing.T) {
			for range requestsNum {
				ctx := testutil.ContextWithTimeout(t, defaultTimeout)

				_ = p.Resolve(ctx, &DNSContext{Req: req, Addr: cli})
				currentNow = currentNow.Add(reqInterval)
			}

			check(t, stats)

			// A constant RTT scores 3/4 of itself: (p90/2 + mean)/2.
			for addr, rtt := range wantRTT {
				got := p.upstreamRTTStats[addr].score
				assert.InEpsilon(t, 0.75*float64(rtt.Microseconds()), got, 1e-3, addr)
			}
		})
	}
}

func TestRingScore(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		samples []float64
		want    float64
	}{{
		name:    "single",
		samples: []float64{4_000},
		want:    3_000,
	}, {
		name:    "constant",
		samples: []float64{2_000, 2_000, 2_000},
		want:    1_500,
	}, {
		// mean 5.5, p90 at rank 8.1 of 0..9: 9.1.
		name:    "interpolated",
		samples: []float64{10, 1, 9, 2, 8, 3, 7, 4, 6, 5},
		want:    (9.1/2 + 5.5) / 2,
	}, {
		// One slow answer of 16 moves the mean by 1/16 of it and p90 not at
		// all.
		name:    "outlier",
		samples: append(slices.Repeat([]float64{1_000}, 15), 17_000),
		want:    (1_000/2 + 2_000) / 2,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			samples := slices.Clone(tc.samples)
			assert.InDelta(t, tc.want, ringScore(tc.samples), 1e-9)
			assert.Equal(t, samples, tc.samples, "samples must not be modified")
		})
	}
}

func TestUpstreamRTTStats_push(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0)

	t.Run("first_sample", func(t *testing.T) {
		t.Parallel()

		got := &upstreamRTTStats{}
		got.push(4*time.Millisecond, start)
		assert.Equal(t, start, got.last)
		assert.Equal(t, 1, got.ringLen)
		assert.InDelta(t, 3_000, got.score, 1e-9)
	})

	t.Run("wraps", func(t *testing.T) {
		t.Parallel()

		stats := &upstreamRTTStats{}
		for i := range 20 {
			stats.push(time.Duration(i+1)*time.Millisecond, start)
		}

		// Only 5..20 ms remain: mean 12.5, p90 at rank 13.5 of 0..15: 18.5.
		assert.Equal(t, upstreamRTTRingSize, stats.ringLen)
		assert.InDelta(t, (18_500.0/2+12_500)/2, stats.score, 1e-9)
	})
}

func TestProxy_exchangeUpstreams_failurePenalty(t *testing.T) {
	t.Parallel()

	const upsTimeout = 3 * time.Second

	newErrUps := func(addr string) (u upstream.Upstream) {
		return &testUpstream{
			OnExchange: func(_ context.Context, _ *dns.Msg) (r *dns.Msg, err error) {
				return nil, assert.AnError
			},
			OnAddress: func() (a string) { return addr },
			OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
		}
	}

	ups := []upstream.Upstream{newErrUps("error1"), newErrUps("error2")}
	p := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: ups,
		},
		TrustedProxies:  dnsproxytest.DefaultTrustedProxies,
		UpstreamTimeout: upsTimeout,
	})

	// Both upstreams fail, so both are tried and penalized.
	ctx := testutil.ContextWithTimeout(t, defaultTimeout)
	_, _, err := p.exchangeUpstreams(ctx, dnsproxytest.NewTestRequest(), ups)
	require.Error(t, err)

	for _, u := range ups {
		stat := p.upstreamRTTStats[u.Address()]
		assert.Equal(t, uint(1), stat.fails)
		assert.Zero(t, stat.ringLen)

		est := stat.estimate(stat.failLast, p.upstreamRTTDecay, p.upstreamTimeout)
		assert.Equal(t, float64(upsTimeout.Microseconds()), est)
	}
}

func TestUpstreamRTTStats_updateBase(t *testing.T) {
	t.Parallel()

	const (
		tau     = 10 * time.Second
		prevRTT = 100 * time.Millisecond
		newRTT  = 10 * time.Millisecond
	)

	prevUS := float64(prevRTT.Microseconds())
	newUS := float64(newRTT.Microseconds())

	start := time.Unix(0, 0)
	warmingUp := upstreamRTTStats{
		baseLast: start,
		base:     prevUS,
		baseNum:  1,
		baseMax:  prevUS,
	}
	// lastWarmUp holds a slow first answer and three fast ones.
	lastWarmUp := upstreamRTTStats{
		baseLast: start,
		base:     (5*prevUS + 3*newUS) / 4,
		baseNum:  upstreamRTTBaselineMin - 1,
		baseMax:  5 * prevUS,
	}
	warmedUp := upstreamRTTStats{
		baseLast: start,
		base:     prevUS,
		baseNum:  upstreamRTTBaselineMin,
	}
	warm := upstreamRTTStats{
		baseLast: start,
		base:     prevUS,
		baseNum:  1e6,
	}

	testCases := []struct {
		now      time.Time
		name     string
		stats    upstreamRTTStats
		wantBase float64
	}{{
		now:      start,
		stats:    upstreamRTTStats{},
		name:     "first_sample",
		wantBase: newUS,
	}, {
		now:      start,
		stats:    warmingUp,
		name:     "warm_up_averages",
		wantBase: (prevUS + newUS) / 2,
	}, {
		now:      start.Add(tau),
		stats:    warmingUp,
		name:     "warm_up_ignores_decay",
		wantBase: (prevUS + newUS) / 2,
	}, {
		now:      start.Add(tau),
		stats:    lastWarmUp,
		name:     "warm_up_drops_largest",
		wantBase: newUS,
	}, {
		now:      start.Add(tau),
		stats:    warmedUp,
		name:     "warmed_up_decay_wins",
		wantBase: newUS + (prevUS-newUS)/math.E,
	}, {
		now:      start,
		stats:    warm,
		name:     "warm_no_time_passed",
		wantBase: prevUS + (newUS-prevUS)/(warm.baseNum+1),
	}, {
		now:      start.Add(tau),
		stats:    warm,
		name:     "warm_one_tau",
		wantBase: newUS + (prevUS-newUS)/math.E,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.stats
			got.updateBase(newRTT, tc.now, tau)
			assert.InDelta(t, tc.wantBase, got.base, 1e-6)
			assert.Equal(t, tc.now, got.baseLast)
			assert.Equal(t, tc.stats.baseNum+1, got.baseNum)
		})
	}
}

func TestUpstreamRTTStats_estimate(t *testing.T) {
	t.Parallel()

	const (
		tau     = 10 * time.Second
		timeout = 5 * time.Second
		score   = 4_000.0
		base    = 10_000.0
	)

	timeoutUS := float64(timeout.Microseconds())
	start := time.Unix(0, 0)
	stats := upstreamRTTStats{
		last:    start,
		score:   score,
		base:    base,
		baseNum: upstreamRTTBaselineMin,
		ringLen: upstreamRTTRingSize,
	}

	// failing has answered at start and failed one pull later.
	failing := stats
	failing.fails = 1
	failing.failLast = start.Add(-failing.pullDecay(tau))

	testCases := []struct {
		now   time.Time
		name  string
		stats upstreamRTTStats
		want  float64
	}{{
		now:   start,
		stats: upstreamRTTStats{},
		name:  "unmeasured",
		want:  timeoutUS,
	}, {
		now:   start.Add(100 * tau),
		stats: upstreamRTTStats{last: start, score: score, ringLen: 1, base: base, baseNum: upstreamRTTBaselineMin - 1},
		name:  "no_baseline",
		want:  score,
	}, {
		now:   start,
		stats: stats,
		name:  "fresh",
		want:  score,
	}, {
		now:   start.Add(-time.Second),
		stats: stats,
		name:  "clock_backwards",
		want:  score,
	}, {
		now:   start.Add(tau),
		stats: stats,
		name:  "one_tau",
		want:  base + (score-base)/math.E,
	}, {
		now:   start.Add(100 * tau),
		stats: stats,
		name:  "stale",
		want:  base,
	}, {
		now:   start,
		stats: upstreamRTTStats{fails: 1, failLast: start},
		name:  "never_answered_failed",
		want:  timeoutUS,
	}, {
		now:   start,
		stats: failing,
		name:  "failure_one_pull",
		want:  score + (timeoutUS-score)/math.E,
	}, {
		now:   start,
		stats: upstreamRTTStats{last: start, ringLen: 1},
		name:  "sub_microsecond",
		want:  1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.InDelta(t, tc.want, tc.stats.estimate(tc.now, tau, timeout), 1e-6)
		})
	}
}

func TestUpstreamRTTStats_fill(t *testing.T) {
	t.Parallel()

	const tau = 10 * time.Second

	start := time.Unix(0, 0)
	failed := upstreamRTTStats{fails: 1, failLast: start}
	pull := failed.pullDecay(tau)

	testCases := []struct {
		now   time.Time
		name  string
		stats upstreamRTTStats
		want  float64
	}{{
		now:   start,
		stats: upstreamRTTStats{},
		name:  "empty",
		want:  1,
	}, {
		now:   start,
		stats: upstreamRTTStats{ringLen: upstreamRTTRingSize / 2},
		name:  "half",
		want:  0.5,
	}, {
		now:   start,
		stats: upstreamRTTStats{ringLen: upstreamRTTRingSize},
		name:  "full",
		want:  0,
	}, {
		now:   start,
		stats: failed,
		name:  "failed_fresh",
		want:  0,
	}, {
		now:   start.Add(pull),
		stats: failed,
		name:  "failed_one_pull",
		want:  1 - 1/math.E,
	}, {
		now:   start.Add(100 * pull),
		stats: failed,
		name:  "failed_stale",
		want:  1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.InDelta(t, tc.want, tc.stats.fill(tc.now, tau), 1e-9)
		})
	}
}

func TestProxy_calcWeights(t *testing.T) {
	t.Parallel()

	newUps := func(addr string) (u upstream.Upstream) {
		return &testUpstream{
			OnAddress: func() (a string) { return addr },
		}
	}

	ups := []upstream.Upstream{newUps("fast"), newUps("slow"), newUps("unmeasured")}

	p := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: ups,
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	})
	now := time.Unix(1_000_000, 0)
	p.time = &faketime.Clock{
		OnNow: func() (n time.Time) { return now },
	}

	ctx := testutil.ContextWithTimeout(t, defaultTimeout)

	full := func(score float64) (s *upstreamRTTStats) {
		return &upstreamRTTStats{
			last:    now,
			score:   score,
			base:    score,
			baseNum: upstreamRTTBaselineMin,
			ringLen: upstreamRTTRingSize,
		}
	}

	t.Run("exponent", func(t *testing.T) {
		p.upstreamRTTStats["fast"] = full(1_000)
		p.upstreamRTTStats["slow"] = full(2_000)

		w := p.calcWeights(ctx, ups)
		require.Len(t, w, len(ups))

		// Twice as slow gets an eighth of the weight, and an unmeasured
		// upstream, with an empty ring, gets the uniform share.
		assert.InDelta(t, 8, w[0]/w[1], 1e-9)
		assert.InDelta(t, 1.0/3, w[2], 1e-9)
	})

	measured := []upstream.Upstream{ups[0], ups[1]}
	p.upstreamRTTStats["fast"] = full(1_000)

	t.Run("filling", func(t *testing.T) {
		// Half the ring is empty, so half the weight is the uniform share.
		half := full(2_000)
		half.ringLen = upstreamRTTRingSize / 2
		p.upstreamRTTStats["slow"] = half

		w := p.calcWeights(ctx, measured)
		assert.InDelta(t, 0.5*(1.0/9)+0.5*0.5, w[1], 1e-9)
	})

	// failed is an upstream whose only exchange failed.
	failed := &upstreamRTTStats{fails: 1}

	t.Run("failed_fresh", func(t *testing.T) {
		failed.failLast = now
		p.upstreamRTTStats["slow"] = failed

		w := p.calcWeights(ctx, measured)
		assert.Less(t, w[1], 1e-6)
	})

	t.Run("failed_stale", func(t *testing.T) {
		failed.failLast = now.Add(-100 * failed.pullDecay(p.upstreamRTTDecay))
		p.upstreamRTTStats["slow"] = failed

		w := p.calcWeights(ctx, measured)
		assert.InDelta(t, 0.5, w[1], 1e-6)
	})

	t.Run("slow_first_answer", func(t *testing.T) {
		// A single slow answer doesn't exclude the upstream: 15 of its 16
		// slots are empty, so it gets 15/16 of the uniform share.
		slow := &upstreamRTTStats{}
		slow.push(500*time.Millisecond, now)
		p.upstreamRTTStats["slow"] = slow

		w := p.calcWeights(ctx, measured)
		assert.InDelta(t, 15.0/16*0.5, w[1], 1e-6)
	})
}

func TestFormatWeights(t *testing.T) {
	t.Parallel()

	newUps := func(addr string) (u upstream.Upstream) {
		return &testUpstream{
			OnAddress: func() (a string) { return addr },
		}
	}

	ups := []upstream.Upstream{
		newUps("https://1.1.1.1:443/dns-query"),
		newUps("https://8.8.8.8:443/dns-query"),
		newUps("https://freedns.controld.com:443/p0"),
	}

	// The weights are normalized and have 4 decimals, as with "%.4f".
	got := formatWeights(ups, []float64{2, 1, 1e-6})
	assert.Equal(t, "https://1.1.1.1:443/dns-query=0.6667 "+
		"https://8.8.8.8:443/dns-query=0.3333 "+
		"https://freedns.controld.com:443/p0=0.0000", got)
}

func TestProxy_updateRTT(t *testing.T) {
	t.Parallel()

	const (
		addr = "upstream"
		rtt  = 10 * time.Millisecond
	)

	p := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{&testUpstream{
				OnAddress: func() (a string) { return addr },
			}},
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	})

	ctx := testutil.ContextWithTimeout(t, defaultTimeout)

	// A failure updates neither the ring nor the baseline.
	p.updateRTT(ctx, addr, p.upstreamTimeout, false)
	stat := p.upstreamRTTStats[addr]
	assert.Zero(t, stat.ringLen)
	assert.Zero(t, stat.base)
	assert.Zero(t, stat.baseNum)
	assert.Equal(t, uint(1), stat.fails)
	assert.False(t, stat.failLast.IsZero())

	p.updateRTT(ctx, addr, p.upstreamTimeout, false)
	assert.Equal(t, uint(2), p.upstreamRTTStats[addr].fails)

	p.updateRTT(ctx, addr, rtt, true)
	stat = p.upstreamRTTStats[addr]
	assert.Equal(t, 1, stat.ringLen)
	assert.InDelta(t, 0.75*float64(rtt.Microseconds()), stat.score, 1e-9)
	assert.Equal(t, float64(rtt.Microseconds()), stat.base)
	assert.Equal(t, 1.0, stat.baseNum)
	assert.Zero(t, stat.fails)
}

func TestUpstreamRTTStats_pullDecay(t *testing.T) {
	t.Parallel()

	const tau = 2 * time.Minute

	testCases := []struct {
		name  string
		fails uint
		want  time.Duration
	}{{
		name:  "one_failure",
		fails: 1,
		want:  upstreamRTTFailPull * tau,
	}, {
		name:  "two_failures",
		fails: 2,
		want:  2 * upstreamRTTFailPull * tau,
	}, {
		name:  "four_failures",
		fails: 4,
		want:  8 * upstreamRTTFailPull * tau,
	}, {
		name:  "capped",
		fails: 1_000,
		want:  upstreamRTTMaxPullDecay,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stats := upstreamRTTStats{fails: tc.fails}
			assert.Equal(t, tc.want, stats.pullDecay(tau))
		})
	}

	t.Run("tau_above_cap", func(t *testing.T) {
		t.Parallel()

		stats := upstreamRTTStats{fails: 3}
		assert.Equal(t, 2*upstreamRTTMaxPullDecay, stats.pullDecay(2*upstreamRTTMaxPullDecay))
	})
}
