package proxy

import (
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

// newUpstreamWithErrorRate returns an [upstream.Upstream] that responds with an
// error every [rate] requests.  The returned upstream isn't safe for concurrent
// use.
func newUpstreamWithErrorRate(rate uint, name string) (u upstream.Upstream) {
	var n uint

	return &dnsproxytest.Upstream{
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
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
func (u measuredUpstream) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	u.stats[u.Address()]++

	return u.Upstream.Exchange(req)
}

func TestProxy_Exchange_loadBalance(t *testing.T) {
	// Make the test deterministic.
	randSrc := rand.New(rand.NewPCG(42, 42))

	const (
		testRTT     = 1 * time.Second
		requestsNum = 10_000
	)

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
			now, currentNow = currentNow, currentNow.Add(testRTT/50)

			return now
		},
	}

	fastUps := &dnsproxytest.Upstream{
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = zeroTime.Add(testRTT / 100)

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "fast" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
	slowerUps := &dnsproxytest.Upstream{
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = zeroTime.Add(testRTT / 10)

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "slower" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
	slowestUps := &dnsproxytest.Upstream{
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = zeroTime.Add(testRTT / 2)

			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "slowest" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	err1Ups := &dnsproxytest.Upstream{
		OnExchange: func(_ *dns.Msg) (r *dns.Msg, err error) { return nil, assert.AnError },
		OnAddress:  func() (addr string) { return "error1" },
		OnClose:    func() (_ error) { panic(testutil.UnexpectedCall()) },
	}
	err2Ups := &dnsproxytest.Upstream{
		OnExchange: func(_ *dns.Msg) (r *dns.Msg, err error) { return nil, assert.AnError },
		OnAddress:  func() (addr string) { return "error2" },
		OnClose:    func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	singleError := &sync.Once{}
	// fastestUps responds with an error on the first request.
	fastestUps := &dnsproxytest.Upstream{
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			singleError.Do(func() { err = assert.AnError })
			currentNow = zeroTime.Add(testRTT / 200)

			return (&dns.Msg{}).SetReply(req), err
		},
		OnAddress: func() (addr string) { return "fastest" },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	each200 := newUpstreamWithErrorRate(200, "each_200")
	each100 := newUpstreamWithErrorRate(100, "each_100")
	each50 := newUpstreamWithErrorRate(50, "each_50")

	testCases := []struct {
		wantStat map[string]int64
		clock    timeutil.Clock
		name     string
		servers  []upstream.Upstream
	}{{
		wantStat: map[string]int64{
			fastUps.Address():    8910,
			slowerUps.Address():  902,
			slowestUps.Address(): 188,
		},
		clock:   zeroingClock,
		name:    "all_good",
		servers: []upstream.Upstream{slowestUps, slowerUps, fastUps},
	}, {
		wantStat: map[string]int64{
			fastUps.Address():   9110,
			slowerUps.Address(): 890,
			err1Ups.Address():   6,
		},
		clock:   zeroingClock,
		name:    "one_bad",
		servers: []upstream.Upstream{fastUps, err1Ups, slowerUps},
	}, {
		wantStat: map[string]int64{
			err1Ups.Address(): requestsNum,
			err2Ups.Address(): requestsNum,
		},
		clock:   zeroingClock,
		name:    "all_bad",
		servers: []upstream.Upstream{err2Ups, err1Ups},
	}, {
		wantStat: map[string]int64{
			fastUps.Address():    7222,
			slowerUps.Address():  748,
			fastestUps.Address(): 2031,
		},
		clock:   zeroingClock,
		name:    "error_once",
		servers: []upstream.Upstream{fastUps, slowerUps, fastestUps},
	}, {
		wantStat: map[string]int64{
			each200.Address(): 5258,
			each100.Address(): 3142,
			each50.Address():  1690,
		},
		clock:   constClock,
		name:    "error_each_nth",
		servers: []upstream.Upstream{each200, each100, each50},
	}}

	req := newTestMessage()
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
			UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
			TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
			UpstreamConfig: &UpstreamConfig{
				Upstreams: ups,
			},
			TrustedProxies: defaultTrustedProxies,
		})
		p.time = tc.clock
		p.randSrc = randSrc

		wantStat := tc.wantStat

		t.Run(tc.name, func(t *testing.T) {
			for range requestsNum {
				_ = p.Resolve(&DNSContext{Req: req, Addr: cli})
			}

			assert.Equal(t, wantStat, stats)
		})
	}
}
