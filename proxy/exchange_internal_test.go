package proxy

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/rand"
)

// fakeClock is the function-based implementation of the [clock] interface.
type fakeClock struct {
	onNow func() (now time.Time)
}

// type check
var _ clock = (*fakeClock)(nil)

// Now implements the [clock] interface for *fakeClock.
func (c *fakeClock) Now() (now time.Time) { return c.onNow() }

// newUpstreamWithErrorRate returns an [upstream.Upstream] that responds with an
// error every [rate] requests.  The returned upstream isn't safe for concurrent
// use.
func newUpstreamWithErrorRate(rate uint, name string) (u upstream.Upstream) {
	var n uint

	return &fakeUpstream{
		onExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			n++
			if n%rate == 0 {
				return nil, assert.AnError
			}

			return (&dns.Msg{}).SetReply(req), nil
		},
		onAddress: func() (addr string) { return name },
		onClose:   func() (_ error) { panic("not implemented") },
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
	randSrc := rand.NewSource(42)

	const (
		testRTT     = 1 * time.Second
		requestsNum = 10_000
	)

	// zeroingClock returns the value of currentNow and sets it back to
	// zeroTime, so that all the calls since the second one return the same zero
	// value until currentNow is modified elsewhere.
	zeroTime := time.Unix(0, 0)
	currentNow := zeroTime
	zeroingClock := &fakeClock{
		onNow: func() (now time.Time) {
			now, currentNow = currentNow, zeroTime

			return now
		},
	}
	constClock := &fakeClock{
		onNow: func() (now time.Time) {
			now, currentNow = currentNow, currentNow.Add(testRTT/50)

			return now
		},
	}

	fastUps := &fakeUpstream{
		onExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = zeroTime.Add(testRTT / 100)

			return (&dns.Msg{}).SetReply(req), nil
		},
		onAddress: func() (addr string) { return "fast" },
		onClose:   func() (_ error) { panic("not implemented") },
	}
	slowerUps := &fakeUpstream{
		onExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = zeroTime.Add(testRTT / 10)

			return (&dns.Msg{}).SetReply(req), nil
		},
		onAddress: func() (addr string) { return "slower" },
		onClose:   func() (_ error) { panic("not implemented") },
	}
	slowestUps := &fakeUpstream{
		onExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			currentNow = zeroTime.Add(testRTT / 2)

			return (&dns.Msg{}).SetReply(req), nil
		},
		onAddress: func() (addr string) { return "slowest" },
		onClose:   func() (_ error) { panic("not implemented") },
	}

	err1Ups := &fakeUpstream{
		onExchange: func(_ *dns.Msg) (r *dns.Msg, err error) { return nil, assert.AnError },
		onAddress:  func() (addr string) { return "error1" },
		onClose:    func() (_ error) { panic("not implemented") },
	}
	err2Ups := &fakeUpstream{
		onExchange: func(_ *dns.Msg) (r *dns.Msg, err error) { return nil, assert.AnError },
		onAddress:  func() (addr string) { return "error2" },
		onClose:    func() (_ error) { panic("not implemented") },
	}

	singleError := &sync.Once{}
	// fastestUps responds with an error on the first request.
	fastestUps := &fakeUpstream{
		onExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			singleError.Do(func() { err = assert.AnError })
			currentNow = zeroTime.Add(testRTT / 200)

			return (&dns.Msg{}).SetReply(req), err
		},
		onAddress: func() (addr string) { return "fastest" },
		onClose:   func() (_ error) { panic("not implemented") },
	}

	each200 := newUpstreamWithErrorRate(200, "each_200")
	each100 := newUpstreamWithErrorRate(100, "each_100")
	each50 := newUpstreamWithErrorRate(50, "each_50")

	testCases := []struct {
		wantStat map[string]int64
		clock    clock
		name     string
		servers  []upstream.Upstream
	}{{
		wantStat: map[string]int64{
			fastUps.Address():    8917,
			slowerUps.Address():  911,
			slowestUps.Address(): 172,
		},
		clock:   zeroingClock,
		name:    "all_good",
		servers: []upstream.Upstream{slowestUps, slowerUps, fastUps},
	}, {
		wantStat: map[string]int64{
			fastUps.Address():   9081,
			slowerUps.Address(): 919,
			err1Ups.Address():   7,
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
			fastUps.Address():    7803,
			slowerUps.Address():  833,
			fastestUps.Address(): 1365,
		},
		clock:   zeroingClock,
		name:    "error_once",
		servers: []upstream.Upstream{fastUps, slowerUps, fastestUps},
	}, {
		wantStat: map[string]int64{
			each200.Address(): 5316,
			each100.Address(): 3090,
			each50.Address():  1683,
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
			UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
			TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
			UpstreamConfig: &UpstreamConfig{
				Upstreams: ups,
			},
			TrustedProxies:         defaultTrustedProxies,
			RatelimitSubnetLenIPv4: 24,
			RatelimitSubnetLenIPv6: 64,
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
