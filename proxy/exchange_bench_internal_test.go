package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

const (
	// benchRTTSamples is the number of precomputed round-trip times of each
	// upstream in [newBenchUpstream].
	benchRTTSamples = 1024

	// benchReqInterval is the time between requests, about the rate of cache
	// misses on a production node.
	benchReqInterval = 1600 * time.Millisecond

	// benchWarmUp is the number of requests before the timed loop, so that the
	// upstreams' statistics are in a steady state.
	benchWarmUp = 1_000

	// benchFailEvery is the period of failures of the failing upstream.
	benchFailEvery = 4
)

// benchRTTProfile is the round-trip time distribution of a benchmark upstream:
// log-normal with the given median.
type benchRTTProfile struct {
	// median is the median round-trip time.
	median time.Duration

	// sigma is the standard deviation of the logarithm of the round-trip time.
	sigma float64
}

// benchRTTProfiles are the round-trip time distributions of the benchmark
// upstreams, modelled on six DoH upstreams in production.  The first one is
// the failing upstream in the failure cases, so that it's picked often.  They
// repeat for more upstreams.
var benchRTTProfiles = []benchRTTProfile{{
	median: 3 * time.Millisecond,
	sigma:  0.3,
}, {
	median: 3 * time.Millisecond,
	sigma:  0.3,
}, {
	median: 8 * time.Millisecond,
	sigma:  0.4,
}, {
	median: 8 * time.Millisecond,
	sigma:  0.4,
}, {
	median: 20 * time.Millisecond,
	sigma:  0.5,
}, {
	median: 40 * time.Millisecond,
	sigma:  0.8,
}}

// benchClock is a clock for benchmarks.  Upstreams advance it by their
// round-trip times, and benchmarks by the time between requests.  It's safe
// for concurrent use.
type benchClock struct {
	// nanos is the current time in nanoseconds since the Unix epoch.
	nanos atomic.Int64
}

// Now implements the [timeutil.Clock] interface for *benchClock.
func (c *benchClock) Now() (now time.Time) {
	return time.Unix(0, c.nanos.Load())
}

// add advances c by d.
func (c *benchClock) add(d time.Duration) {
	c.nanos.Add(int64(d))
}

// lockedSource is a [rand.Source] safe for concurrent use.
type lockedSource struct {
	// mu protects src.
	mu *sync.Mutex

	// src is the underlying source.
	src rand.Source
}

// Uint64 implements the [rand.Source] interface for *lockedSource.
func (s *lockedSource) Uint64() (n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.src.Uint64()
}

// benchEnv is the environment of a load-balancing benchmark.
type benchEnv struct {
	// clock is the proxy's clock.
	clock *benchClock

	// exchanges is the number of exchanges with all upstreams.
	exchanges *atomic.Int64

	// req is the request sent for every query.
	req *dns.Msg

	// p is the proxy under test.
	p *Proxy

	// ups are the upstreams of p.
	ups []upstream.Upstream
}

// newBenchEnv returns a benchmark environment with n upstreams.  If failing is
// true, the first upstream fails every [benchFailEvery] exchanges.
func newBenchEnv(b *testing.B, n int, failing bool, logger *slog.Logger) (env *benchEnv) {
	b.Helper()

	env = &benchEnv{
		clock:     &benchClock{},
		exchanges: &atomic.Int64{},
		req:       (&dns.Msg{}).SetQuestion("example.org.", dns.TypeA),
	}

	for i := range n {
		var failEvery int64
		if failing && i == 0 {
			failEvery = benchFailEvery
		}

		env.ups = append(env.ups, env.newUpstream(i, failEvery))
	}

	env.p = mustNew(b, &Config{
		Logger:        logger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: env.ups,
		},
		UpstreamMode:   UpstreamModeLoadBalance,
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	})
	env.p.time = env.clock
	env.p.randSrc = rand.New(rand.NewPCG(42, 42))

	return env
}

// newUpstream returns the i-th upstream of env, with round-trip times drawn
// from the i-th of [benchRTTProfiles], repeated.  It advances env.clock by
// them, counts its exchanges in env.exchanges, and fails every failEvery
// exchanges if failEvery is positive.  It's safe for concurrent use.
func (env *benchEnv) newUpstream(i int, failEvery int64) (u upstream.Upstream) {
	prof := benchRTTProfiles[i%len(benchRTTProfiles)]
	r := rand.New(rand.NewPCG(uint64(i), 42))
	rtts := make([]time.Duration, benchRTTSamples)
	for j := range rtts {
		rtts[j] = time.Duration(float64(prof.median) * math.Exp(prof.sigma*r.NormFloat64()))
	}

	var num atomic.Int64
	resp := (&dns.Msg{}).SetReply(env.req)
	addr := fmt.Sprintf("u%d", i)

	return &testUpstream{
		OnExchange: func(_ context.Context, _ *dns.Msg) (_ *dns.Msg, err error) {
			env.exchanges.Add(1)
			k := num.Add(1)
			env.clock.add(rtts[k%benchRTTSamples])
			if failEvery > 0 && k%failEvery == 0 {
				return nil, assert.AnError
			}

			return resp, nil
		},
		OnAddress: func() (a string) { return addr },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
}

// query resolves env.req using env.ups and advances env.clock by
// [benchReqInterval].
func (env *benchEnv) query(ctx context.Context) (err error) {
	_, _, err = env.p.exchangeUpstreams(ctx, env.req, env.ups)
	env.clock.add(benchReqInterval)

	return err
}

// warmUp sends [benchWarmUp] queries and then resets the exchange counter.
func (env *benchEnv) warmUp(b *testing.B, ctx context.Context) {
	b.Helper()

	for range benchWarmUp {
		if err := env.query(ctx); err != nil {
			b.Fatal(err)
		}
	}

	env.exchanges.Store(0)
}

// reportExchanges reports the number of exchanges per query as the "exch/op"
// metric.  It must be called after the timed loop.
func (env *benchEnv) reportExchanges(b *testing.B) {
	b.Helper()

	b.ReportMetric(float64(env.exchanges.Load())/float64(b.N), "exch/op")
}

// BenchmarkProxy_exchangeUpstreams measures the cost of a load-balanced cache
// miss, excluding the network: the upstreams' weights, the weighted pick, the
// exchange with an instant upstream, and the round-trip time update.  It only
// uses code that exists at both the original round-trip time selection and the
// fork's, so that the same file benchmarks either.
func BenchmarkProxy_exchangeUpstreams(b *testing.B) {
	debugLogger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	testCases := []struct {
		logger  *slog.Logger
		name    string
		n       int
		failing bool
	}{{
		logger:  testLogger,
		name:    "n=2/log=info",
		n:       2,
		failing: false,
	}, {
		logger:  testLogger,
		name:    "n=6/log=info",
		n:       6,
		failing: false,
	}, {
		logger:  testLogger,
		name:    "n=16/log=info",
		n:       16,
		failing: false,
	}, {
		logger:  debugLogger,
		name:    "n=6/log=debug",
		n:       6,
		failing: false,
	}, {
		logger:  testLogger,
		name:    "n=6/fail=1/log=info",
		n:       6,
		failing: true,
	}}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			ctx := context.Background()
			env := newBenchEnv(b, tc.n, tc.failing, tc.logger)
			env.warmUp(b, ctx)

			b.ReportAllocs()
			for b.Loop() {
				if err := env.query(ctx); err != nil {
					b.Fatal(err)
				}
			}

			env.reportExchanges(b)
		})
	}

	// Most recent results:
	//
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/dnsproxy/proxy
	//	cpu: Apple M3 Pro
	//	BenchmarkProxy_exchangeUpstreams/n=2/log=info-4         	 2287138	       515.2 ns/op	         1.000 exch/op	     128 B/op	      10 allocs/op
	//	BenchmarkProxy_exchangeUpstreams/n=6/log=info-4         	 1410781	       855.2 ns/op	         1.000 exch/op	     272 B/op	      11 allocs/op
	//	BenchmarkProxy_exchangeUpstreams/n=16/log=info-4        	  655818	      1779 ns/op	         1.000 exch/op	     592 B/op	      11 allocs/op
	//	BenchmarkProxy_exchangeUpstreams/n=6/log=debug-4        	  303004	      3929 ns/op	         1.000 exch/op	     744 B/op	      33 allocs/op
	//	BenchmarkProxy_exchangeUpstreams/n=6/fail=1/log=info-4  	 1347042	       887.3 ns/op	         1.000 exch/op	     272 B/op	      11 allocs/op
}

// BenchmarkProxy_exchangeUpstreams_parallel measures the contention of
// concurrent load-balanced cache misses with 6 upstreams.  The goroutines share
// the clock, so the measured round-trip times include the other goroutines'
// advances and are larger than the upstreams' own.
func BenchmarkProxy_exchangeUpstreams_parallel(b *testing.B) {
	ctx := context.Background()
	env := newBenchEnv(b, 6, false, testLogger)
	env.p.randSrc = &lockedSource{
		mu:  &sync.Mutex{},
		src: rand.NewPCG(42, 42),
	}
	env.warmUp(b, ctx)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := env.query(ctx); err != nil {
				b.Error(err)

				return
			}
		}
	})

	env.reportExchanges(b)

	// Most recent results:
	//
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/dnsproxy/proxy
	//	cpu: Apple M3 Pro
	//	BenchmarkProxy_exchangeUpstreams_parallel     	 1311153	       904.3 ns/op	         1.000 exch/op	     272 B/op	      11 allocs/op
	//	BenchmarkProxy_exchangeUpstreams_parallel-2   	 1000000	      1115 ns/op	         1.000 exch/op	     272 B/op	      11 allocs/op
	//	BenchmarkProxy_exchangeUpstreams_parallel-4   	  880927	      1334 ns/op	         1.000 exch/op	     272 B/op	      11 allocs/op
}
