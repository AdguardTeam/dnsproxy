package proxy_test

import (
	"context"
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/dnsproxytest"
	proxytest "github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common mock upstreams for tests.
var (
	testSuccessUpstream = &dnsproxytest.Upstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() (addr string) { return "upstream" },
		OnClose:   func() (err error) { return nil },
	}

	testFailUpstream = &dnsproxytest.Upstream{
		OnExchange: func(_ context.Context, _ *dns.Msg) (resp *dns.Msg, err error) {
			return nil, assert.AnError
		},
		OnAddress: func() (addr string) { return "fail.upstream" },
		OnClose:   func() (err error) { return nil },
	}
)

func TestDNSContext_QueryStatistics_loadBalance(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantErr           assert.ErrorAssertionFunc
		wantMainErr       assert.BoolAssertionFunc
		wantFallbackErr   assert.BoolAssertionFunc
		upstreamConf      *proxy.UpstreamConfig
		fallbackConf      *proxy.UpstreamConfig
		name              string
		wantMainCount     int
		wantFallbackCount int
	}{{
		wantErr:         assert.NoError,
		wantMainErr:     assert.False,
		wantFallbackErr: assert.False,
		upstreamConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream},
		},
		fallbackConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream},
		},
		name:              "success",
		wantMainCount:     1,
		wantFallbackCount: 0,
	}, {
		wantErr:         assert.Error,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.True,
		upstreamConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testFailUpstream},
		},
		fallbackConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testFailUpstream, testFailUpstream},
		},
		name:              "bad",
		wantMainCount:     1,
		wantFallbackCount: 2,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := &proxy.Config{
				Logger:         testLogger,
				UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
				TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
				TrustedProxies: proxytest.DefaultTrustedProxies,
				UpstreamConfig: tc.upstreamConf,
				Fallbacks:      tc.fallbackConf,
				UpstreamMode:   proxy.UpstreamModeLoadBalance,
			}

			testQueryStats(
				t,
				conf,
				tc.wantErr,
				tc.wantMainCount,
				tc.wantMainErr,
				tc.wantFallbackCount,
				tc.wantFallbackErr,
			)
		})
	}
}

func TestDNSContext_QueryStatistics_parallel(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantErr           assert.ErrorAssertionFunc
		wantMainErr       assert.BoolAssertionFunc
		wantFallbackErr   assert.BoolAssertionFunc
		upstreamConf      *proxy.UpstreamConfig
		fallbackConf      *proxy.UpstreamConfig
		name              string
		wantMainCount     int
		wantFallbackCount int
	}{{
		wantErr:         assert.NoError,
		wantMainErr:     assert.False,
		wantFallbackErr: assert.False,
		upstreamConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream, testFailUpstream},
		},
		fallbackConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream},
		},
		name:              "success",
		wantMainCount:     1,
		wantFallbackCount: 0,
	}, {
		wantErr:         assert.NoError,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.False,
		upstreamConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testFailUpstream},
		},
		fallbackConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream},
		},
		name:              "bad_fallback_success",
		wantMainCount:     1,
		wantFallbackCount: 1,
	}, {
		wantErr:         assert.Error,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.True,
		upstreamConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testFailUpstream, testFailUpstream},
		},
		fallbackConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testFailUpstream, testFailUpstream, testFailUpstream},
		},
		name:              "bad",
		wantMainCount:     2,
		wantFallbackCount: 3,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := &proxy.Config{
				Logger:         testLogger,
				UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
				TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
				TrustedProxies: proxytest.DefaultTrustedProxies,
				UpstreamConfig: tc.upstreamConf,
				Fallbacks:      tc.fallbackConf,
				UpstreamMode:   proxy.UpstreamModeParallel,
			}

			testQueryStats(
				t,
				conf,
				tc.wantErr,
				tc.wantMainCount,
				tc.wantMainErr,
				tc.wantFallbackCount,
				tc.wantFallbackErr,
			)
		})
	}
}

func TestDNSContext_QueryStatistics_fastest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantErr           assert.ErrorAssertionFunc
		wantMainErr       assert.BoolAssertionFunc
		wantFallbackErr   assert.BoolAssertionFunc
		upstreamConf      *proxy.UpstreamConfig
		fallbackConf      *proxy.UpstreamConfig
		name              string
		wantMainCount     int
		wantFallbackCount int
	}{{
		wantErr:         assert.NoError,
		wantMainErr:     assert.False,
		wantFallbackErr: assert.False,
		upstreamConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream},
		},
		fallbackConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream},
		},
		name:              "single_success",
		wantMainCount:     1,
		wantFallbackCount: 0,
	}, {
		wantErr:         assert.NoError,
		wantMainErr:     assert.False,
		wantFallbackErr: assert.False,
		upstreamConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream, testSuccessUpstream},
		},
		fallbackConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream},
		},
		name:              "multiple_success",
		wantMainCount:     2,
		wantFallbackCount: 0,
	}, {
		wantErr:         assert.NoError,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.False,
		upstreamConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream, testFailUpstream},
		},
		fallbackConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream},
		},
		name:              "mixed_success",
		wantMainCount:     2,
		wantFallbackCount: 0,
	}, {
		wantErr:         assert.Error,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.True,
		upstreamConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testFailUpstream, testFailUpstream},
		},
		fallbackConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testFailUpstream, testFailUpstream, testFailUpstream},
		},
		name:              "multiple_bad",
		wantMainCount:     2,
		wantFallbackCount: 3,
	}, {
		wantErr:         assert.NoError,
		wantMainErr:     assert.True,
		wantFallbackErr: assert.False,
		upstreamConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testFailUpstream, testFailUpstream},
		},
		fallbackConf: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{testSuccessUpstream},
		},
		name:              "bad_fallback_success",
		wantMainCount:     2,
		wantFallbackCount: 1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := &proxy.Config{
				Logger:         testLogger,
				UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
				TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
				TrustedProxies: proxytest.DefaultTrustedProxies,
				UpstreamConfig: tc.upstreamConf,
				Fallbacks:      tc.fallbackConf,
				UpstreamMode:   proxy.UpstreamModeFastestAddr,
			}

			testQueryStats(
				t,
				conf,
				tc.wantErr,
				tc.wantMainCount,
				tc.wantMainErr,
				tc.wantFallbackCount,
				tc.wantFallbackErr,
			)
		})
	}
}

// testQueryStats ensures that proxy with given configuration returns correct
// query statistics.
//
// TODO(f.setrakov): Consider moving arguments into a struct.
func testQueryStats(
	tb testing.TB,
	conf *proxy.Config,
	wantErr assert.ErrorAssertionFunc,
	wantMainCount int,
	wantMainErr assert.BoolAssertionFunc,
	wantFallbackCount int,
	wantFallbackErr assert.BoolAssertionFunc,
) {
	p, err := proxy.New(conf)
	require.NoError(tb, err)

	d := &proxy.DNSContext{Req: proxytest.NewTestRequest()}

	err = p.Resolve(testutil.ContextWithTimeout(tb, defaultTimeout), d)
	wantErr(tb, err)

	stats := d.QueryStatistics()

	main := stats.Main()
	assert.Lenf(tb, main, wantMainCount, "main stats count")

	fallback := stats.Fallback()
	assert.Lenf(tb, fallback, wantFallbackCount, "fallback stats count")

	wantMainErr(tb, isErrorInStats(main), "main err")
	wantFallbackErr(tb, isErrorInStats(fallback), "fallback err")
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
