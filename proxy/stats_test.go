package proxy_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectQueryStats(t *testing.T) {
	const (
		listenIP = "127.0.0.1"
	)

	var (
		testReq = &dns.Msg{
			Question: []dns.Question{{
				Name:   "test.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		defaultTrustedProxies netutil.SubnetSet = netutil.SliceSubnetSet{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::0/0"),
		}

		localhostAnyPort = netip.MustParseAddrPort(netutil.JoinHostPort(listenIP, 0))
	)

	ups := &dnsproxytest.FakeUpstream{
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "upstream" },
		OnClose:   func() (err error) { return nil },
	}

	failUps := &dnsproxytest.FakeUpstream{
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			return nil, errors.Error("exchange error")
		},
		OnAddress: func() (addr string) { return "fail.upstream" },
		OnClose:   func() (err error) { return nil },
	}

	conf := &proxy.Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
	}

	testCases := []struct {
		wantErr           assert.ErrorAssertionFunc
		wantMainErr       assert.BoolAssertionFunc
		wantFallbackErr   assert.BoolAssertionFunc
		config            *proxy.UpstreamConfig
		fallbackConfig    *proxy.UpstreamConfig
		name              string
		mode              proxy.UpstreamMode
		wantMainCount     int
		wantFallbackCount int
	}{{
		wantErr:         assert.NoError,
		wantMainErr:     assert.False,
		wantFallbackErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:              "load_balance_success",
		mode:              proxy.UpstreamModeLoadBalance,
		wantMainCount:     1,
		wantFallbackCount: 0,
	}, {
		wantErr:         assert.Error,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.True,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps},
		},
		name:              "load_balance_bad",
		mode:              proxy.UpstreamModeLoadBalance,
		wantMainCount:     1,
		wantFallbackCount: 2,
	}, {
		wantErr:         assert.NoError,
		wantMainErr:     assert.False,
		wantFallbackErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups, failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:              "parallel_success",
		mode:              proxy.UpstreamModeParallel,
		wantMainCount:     1,
		wantFallbackCount: 0,
	}, {
		wantErr:         assert.NoError,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:              "parallel_bad_fallback_success",
		mode:              proxy.UpstreamModeParallel,
		wantMainCount:     1,
		wantFallbackCount: 1,
	}, {
		wantErr:         assert.Error,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.True,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps, failUps},
		},
		name:              "parallel_bad",
		mode:              proxy.UpstreamModeParallel,
		wantMainCount:     2,
		wantFallbackCount: 3,
	}, {
		wantErr:         assert.NoError,
		wantMainErr:     assert.False,
		wantFallbackErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:              "fastest_single_success",
		mode:              proxy.UpstreamModeFastestAddr,
		wantMainCount:     1,
		wantFallbackCount: 0,
	}, {
		wantErr:         assert.NoError,
		wantMainErr:     assert.False,
		wantFallbackErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups, ups},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:              "fastest_multiple_success",
		mode:              proxy.UpstreamModeFastestAddr,
		wantMainCount:     2,
		wantFallbackCount: 0,
	}, {
		wantErr:         assert.NoError,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups, failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:              "fastest_mixed_success",
		mode:              proxy.UpstreamModeFastestAddr,
		wantMainCount:     2,
		wantFallbackCount: 0,
	}, {
		wantErr:         assert.Error,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.True,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps, failUps},
		},
		name:              "fastest_multiple_bad",
		mode:              proxy.UpstreamModeFastestAddr,
		wantMainCount:     2,
		wantFallbackCount: 3,
	}, {
		wantErr:         assert.NoError,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:              "fastest_bad_fallback_success",
		mode:              proxy.UpstreamModeFastestAddr,
		wantMainCount:     2,
		wantFallbackCount: 1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf.UpstreamConfig = tc.config
			conf.Fallbacks = tc.fallbackConfig
			conf.UpstreamMode = tc.mode

			p, err := proxy.New(conf)
			require.NoError(t, err)

			d := &proxy.DNSContext{Req: testReq}

			err = p.Resolve(d)
			tc.wantErr(t, err)

			stats := d.QueryStatistics()
			assertQueryStats(
				t,
				stats,
				tc.wantMainCount,
				tc.wantMainErr,
				tc.wantFallbackCount,
				tc.wantFallbackErr,
			)
		})
	}
}

// assertQueryStats asserts the statistics using the provided parameters.
func assertQueryStats(
	t *testing.T,
	stats *proxy.QueryStatistics,
	wantMainCount int,
	wantMainErr assert.BoolAssertionFunc,
	wantFallbackCount int,
	wantFallbackErr assert.BoolAssertionFunc,
) {
	t.Helper()

	main := stats.Main()
	assert.Lenf(t, main, wantMainCount, "main stats count")

	fallback := stats.Fallback()
	assert.Lenf(t, fallback, wantFallbackCount, "fallback stats count")

	wantMainErr(t, isErrorInStats(main), "main err")
	wantFallbackErr(t, isErrorInStats(fallback), "fallback err")
}

// isErrorInStats is a helper function for tests that returns true if the
// upstream statistics contain an DNS lookup error.
func isErrorInStats(stats []*proxy.UpstreamStatistics) (ok bool) {
	for _, u := range stats {
		if u.Error != nil {
			return true
		}
	}

	return false
}
