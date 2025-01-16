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
		isExchangeErr  assert.BoolAssertionFunc
		config         *proxy.UpstreamConfig
		fallbackConfig *proxy.UpstreamConfig
		name           string
		mode           proxy.UpstreamMode
		mainCount      int
		fallbackCount  int
		isMainErr      bool
		isFallbackErr  bool
	}{{
		isExchangeErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:          "load_balance_success",
		mode:          proxy.UpstreamModeLoadBalance,
		mainCount:     1,
		fallbackCount: 0,
		isMainErr:     false,
		isFallbackErr: false,
	}, {
		isExchangeErr: assert.True,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps},
		},
		name:          "load_balance_bad",
		mode:          proxy.UpstreamModeLoadBalance,
		mainCount:     1,
		fallbackCount: 2,
		isMainErr:     true,
		isFallbackErr: true,
	}, {
		isExchangeErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups, failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:          "parallel_success",
		mode:          proxy.UpstreamModeParallel,
		mainCount:     1,
		fallbackCount: 0,
		isMainErr:     false,
		isFallbackErr: false,
	}, {
		isExchangeErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:          "parallel_bad_fallback_success",
		mode:          proxy.UpstreamModeParallel,
		mainCount:     1,
		fallbackCount: 1,
		isMainErr:     true,
		isFallbackErr: false,
	}, {
		isExchangeErr: assert.True,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps, failUps},
		},
		name:          "parallel_bad",
		mode:          proxy.UpstreamModeParallel,
		mainCount:     2,
		fallbackCount: 3,
		isMainErr:     true,
		isFallbackErr: true,
	}, {
		isExchangeErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:          "fastest_single_success",
		mode:          proxy.UpstreamModeFastestAddr,
		mainCount:     1,
		fallbackCount: 0,
		isMainErr:     false,
		isFallbackErr: false,
	}, {
		isExchangeErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups, ups},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:          "fastest_multiple_success",
		mode:          proxy.UpstreamModeFastestAddr,
		mainCount:     2,
		fallbackCount: 0,
		isMainErr:     false,
		isFallbackErr: false,
	}, {
		isExchangeErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups, failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:          "fastest_mixed_success",
		mode:          proxy.UpstreamModeFastestAddr,
		mainCount:     2,
		fallbackCount: 0,
		isMainErr:     true,
		isFallbackErr: false,
	}, {
		isExchangeErr: assert.True,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps, failUps},
		},
		name:          "fastest_multiple_bad",
		mode:          proxy.UpstreamModeFastestAddr,
		mainCount:     2,
		fallbackCount: 3,
		isMainErr:     true,
		isFallbackErr: true,
	}, {
		isExchangeErr: assert.False,
		config: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{failUps, failUps},
		},
		fallbackConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		name:          "fastest_bad_fallback_success",
		mode:          proxy.UpstreamModeFastestAddr,
		mainCount:     2,
		fallbackCount: 1,
		isMainErr:     true,
		isFallbackErr: false,
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
			tc.isExchangeErr(t, err != nil)

			stats := d.QueryStatistics()
			assertQueryStats(
				t,
				stats,
				tc.mainCount,
				tc.isMainErr,
				tc.fallbackCount,
				tc.isFallbackErr,
			)
		})
	}
}

// assertQueryStats asserts the statistics using the provided parameters.
func assertQueryStats(
	t *testing.T,
	stats *proxy.QueryStatistics,
	mainCount int,
	isMainErr bool,
	fallbackCount int,
	isFallbackErr bool,
) {
	t.Helper()

	main := stats.Main()
	assert.Equal(t, mainCount, len(main), "main stats count")

	fallback := stats.Fallback()
	assert.Equal(t, fallbackCount, len(fallback), "fallback stats count")

	assert.Equal(t, isMainErr, isErrorInStats(main), "main err")
	assert.Equal(t, isFallbackErr, isErrorInStats(fallback), "fallback err")
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
