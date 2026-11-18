package proxy

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// Common load balance test values.
const (
	testLoadBalanceRTT         = 1 * time.Second
	testLoadBalanceRequestsNum = 10_000
)

// Common load balance test upstream names.
const (
	testUpstreamNameFast    = "fast"
	testUpstreamNameSlower  = "slower"
	testUpstreamNameSlowest = "slowest"
	testUpstreamNameError1  = "error1"
	testUpstreamNameError2  = "error2"
	testUpstreamNameFastest = "fastest"
	testUpstreamNameEach200 = "each_200"
	testUpstreamNameEach100 = "each_100"
	testUpstreamNameEach50  = "each_50"
)

// newUpstreamWithErrorRate returns an [upstream.Upstream] that responds with an
// error every [rate] requests.  The returned upstream isn't safe for concurrent
// use.
func newUpstreamWithErrorRate(tb testing.TB, rate uint, name string) (u upstream.Upstream) {
	tb.Helper()

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

// newUpstreamWithRTT returns an upstream that increases currentNow by rtt from
// the zero time on every exchange.
func newUpstreamWithRTT(
	tb testing.TB,
	name string,
	rtt time.Duration,
	currentNow *time.Time,
) (u *testUpstream) {
	tb.Helper()

	return &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			*currentNow = time.Unix(0, 0).Add(rtt)

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return name },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
}

func TestProxy_Exchange_loadBalance(t *testing.T) {
	// Make the test deterministic.
	randSrc := rand.New(rand.NewPCG(42, 42))

	// zeroingClock returns the value of currentNow and sets it back to
	// zeroTime, so that all the calls since the second one return the same zero
	// value until currentNow is modified elsewhere.
	zeroTime := time.Unix(0, 0)
	currentNow := zeroTime
	zeroingClock := &faketime.Clock{
		OnNow: func() (now time.Time) {
			now, currentNow = currentNow, zeroTime

			return now
		},
	}

	constClock := &faketime.Clock{
		OnNow: func() (now time.Time) {
			now, currentNow = currentNow, currentNow.Add(testLoadBalanceRTT/50)

			return now
		},
	}

	fastUps := newUpstreamWithRTT(t, testUpstreamNameFast, testLoadBalanceRTT/100, &currentNow)
	slowerUps := newUpstreamWithRTT(t, testUpstreamNameSlower, testLoadBalanceRTT/10, &currentNow)
	slowestUps := newUpstreamWithRTT(t, testUpstreamNameSlowest, testLoadBalanceRTT/2, &currentNow)
	err1Ups := newUpstreamWithErrorRate(t, 1, testUpstreamNameError1)
	err2Ups := newUpstreamWithErrorRate(t, 1, testUpstreamNameError2)

	singleError := &sync.Once{}
	// fastestUps responds with an error on the first request.
	fastestUps := &testUpstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			singleError.Do(func() { err = assert.AnError })
			currentNow = zeroTime.Add(testLoadBalanceRTT / 200)

			return (&dns.Msg{}).SetReply(req), err
		},
		OnAddress: func() (addr string) { return testUpstreamNameFastest },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	each200 := newUpstreamWithErrorRate(t, 200, testUpstreamNameEach200)
	each100 := newUpstreamWithErrorRate(t, 100, testUpstreamNameEach100)
	each50 := newUpstreamWithErrorRate(t, 50, testUpstreamNameEach50)

	testCases := []struct {
		wantStat map[string]int64
		clock    timeutil.Clock
		name     string
		servers  []upstream.Upstream
	}{{
		wantStat: map[string]int64{
			testUpstreamNameFast:    8910,
			testUpstreamNameSlower:  902,
			testUpstreamNameSlowest: 188,
		},
		clock:   zeroingClock,
		name:    "all_good",
		servers: []upstream.Upstream{slowestUps, slowerUps, fastUps},
	}, {
		wantStat: map[string]int64{
			testUpstreamNameFast:   9110,
			testUpstreamNameSlower: 890,
			testUpstreamNameError1: 6,
		},
		clock:   zeroingClock,
		name:    "one_bad",
		servers: []upstream.Upstream{fastUps, err1Ups, slowerUps},
	}, {
		wantStat: map[string]int64{
			testUpstreamNameError1: testLoadBalanceRequestsNum,
			testUpstreamNameError2: testLoadBalanceRequestsNum,
		},
		clock:   zeroingClock,
		name:    "all_bad",
		servers: []upstream.Upstream{err2Ups, err1Ups},
	}, {
		wantStat: map[string]int64{
			testUpstreamNameFast:    7222,
			testUpstreamNameSlower:  748,
			testUpstreamNameFastest: 2031,
		},
		clock:   zeroingClock,
		name:    "error_once",
		servers: []upstream.Upstream{fastUps, slowerUps, fastestUps},
	}, {
		wantStat: map[string]int64{
			testUpstreamNameEach200: 5258,
			testUpstreamNameEach100: 3142,
			testUpstreamNameEach50:  1690,
		},
		clock:   constClock,
		name:    "error_each_nth",
		servers: []upstream.Upstream{each200, each100, each50},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			subtestProxyExchangeLoadBalance(t, tc.servers, tc.clock, tc.wantStat, randSrc)
		})
	}
}

// subtestProxyExchangeLoadBalance checks the request distribution for servers.
// wantStat and randSrc must not be nil.
func subtestProxyExchangeLoadBalance(
	tb testing.TB,
	servers []upstream.Upstream,
	clock timeutil.Clock,
	wantStat map[string]int64,
	randSrc *rand.Rand,
) {
	req := dnsproxytest.NewTestRequest()
	cli := netip.AddrPortFrom(netutil.IPv4Localhost(), 1234)

	ups := []upstream.Upstream{}
	stats := map[string]int64{}
	for _, s := range servers {
		ups = append(ups, measuredUpstream{
			Upstream: s,
			stats:    stats,
		})
	}

	p := newTestProxy(tb, &Config{
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

	for range testLoadBalanceRequestsNum {
		ctx := testutil.ContextWithTimeout(tb, defaultTimeout)

		_ = p.Resolve(ctx, &DNSContext{Req: req, Addr: cli})
	}

	assert.Equal(tb, wantStat, stats)
}
