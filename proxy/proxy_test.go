package proxy_test

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCustomUpstreamConfig is a helper function that returns an initialized
// [*proxy.CustomUpstreamConfig].
func newCustomUpstreamConfig(ups upstream.Upstream, enabled bool) (c *proxy.CustomUpstreamConfig) {
	return proxy.NewCustomUpstreamConfig(
		&proxy.UpstreamConfig{Upstreams: []upstream.Upstream{ups}},
		enabled,
		0,
		false,
	)
}

// isCachedWithCustomConfig is a helper function that returns the caching
// results of a constructed request using the provided custom upstream
// configuration and FQDN.
func isCachedWithCustomConfig(
	tb testing.TB,
	p *proxy.Proxy,
	conf *proxy.CustomUpstreamConfig,
	fqdn string,
) (isCached bool) {
	tb.Helper()

	d := &proxy.DNSContext{
		CustomUpstreamConfig: conf,
		Req:                  (&dns.Msg{}).SetQuestion(fqdn, dns.TypeA),
	}

	err := p.Resolve(d)
	require.NoError(tb, err)

	qs := d.QueryStatistics()
	require.NotNil(tb, qs)

	s := qs.Main()
	require.Len(tb, s, 1)

	return s[0].IsCached
}

func TestProxy_Resolve_cache(t *testing.T) {
	const host = "example.test."

	ups := &dnsproxytest.Upstream{
		OnAddress: func() (addr string) { return "stub" },
		OnClose:   func() (err error) { return nil },
	}
	ups.OnExchange = func(req *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.IP{192, 0, 2, 0},
		})

		return resp, nil
	}

	upsConf := &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{ups},
	}

	testCases := []struct {
		customUpstreamConf *proxy.CustomUpstreamConfig
		wantCachedWithConf assert.BoolAssertionFunc
		wantCachedGlobal   assert.BoolAssertionFunc
		name               string
		prxCacheEnabled    bool
	}{{
		customUpstreamConf: nil,
		wantCachedWithConf: assert.True,
		wantCachedGlobal:   assert.True,
		name:               "global_cache",
		prxCacheEnabled:    true,
	}, {
		customUpstreamConf: newCustomUpstreamConfig(ups, true),
		wantCachedWithConf: assert.True,
		wantCachedGlobal:   assert.False,
		name:               "custom_cache",
		prxCacheEnabled:    false,
	}, {
		customUpstreamConf: newCustomUpstreamConfig(ups, false),
		wantCachedWithConf: assert.False,
		wantCachedGlobal:   assert.False,
		name:               "custom_cache_only_upstreams",
		prxCacheEnabled:    false,
	}, {
		customUpstreamConf: newCustomUpstreamConfig(ups, true),
		wantCachedWithConf: assert.True,
		wantCachedGlobal:   assert.False,
		name:               "two_caches_enabled",
		prxCacheEnabled:    true,
	}, {
		customUpstreamConf: nil,
		wantCachedWithConf: assert.False,
		wantCachedGlobal:   assert.False,
		name:               "two_caches_disabled",
		prxCacheEnabled:    false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := proxy.New(&proxy.Config{
				UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
				UpstreamConfig: upsConf,
				CacheEnabled:   tc.prxCacheEnabled,
			})
			require.NoError(t, err)
			require.NotNil(t, p)

			servicetest.RequireRun(t, p, testTimeout)

			res := isCachedWithCustomConfig(t, p, tc.customUpstreamConf, host)
			assert.False(t, res)

			res = isCachedWithCustomConfig(t, p, tc.customUpstreamConf, host)
			tc.wantCachedWithConf(t, res)

			res = isCachedWithCustomConfig(t, p, nil, host)
			tc.wantCachedGlobal(t, res)
		})
	}
}

func TestProxy_Start_closeOnFail(t *testing.T) {
	t.Parallel()

	l, err := net.ListenTCP(bootstrap.NetworkTCP, net.TCPAddrFromAddrPort(localhostAnyPort))
	require.NoError(t, err)

	tcpAddr := testutil.RequireTypeAssert[*net.TCPAddr](t, l.Addr())

	ups := &dnsproxytest.Upstream{
		OnExchange: func(m *dns.Msg) (_ *dns.Msg, _ error) { panic(testutil.UnexpectedCall(m)) },
		OnAddress:  func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:    func() (_ error) { panic(testutil.UnexpectedCall()) },
	}

	p, err := proxy.New(&proxy.Config{
		// Add a free address.
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		// Add a bound address.
		TCPListenAddr:  []*net.TCPAddr{tcpAddr},
		UpstreamConfig: &proxy.UpstreamConfig{Upstreams: []upstream.Upstream{ups}},
	})
	require.NoError(t, err)

	require.True(t, t.Run("start_fail", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, testTimeout)
		err = p.Start(ctx)

		var netErr net.Error
		require.ErrorAs(t, err, &netErr)
	}))

	// Don't panic anymore.
	ups.OnClose = func() (err error) { return nil }

	require.True(t, t.Run("restart_success", func(t *testing.T) {
		require.NoError(t, l.Close())

		servicetest.RequireRun(t, p, testTimeout)
	}))
}
		p.HTTPListenAddr = []*net.TCPAddr{{IP: ip, Port: 0}}
