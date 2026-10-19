package proxy

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_performDNS64_noWrapperReuse(t *testing.T) {
	nat64Pref := netip.MustParsePrefix("64:ff9b::/96")
	wantAAAA := "64:ff9b::c000:201"

	upstreams := []upstream.Upstream{
		newNamedUpstream(t, "upstream1"),
		newNamedUpstream(t, "upstream2"),
	}

	p := mustNew(t, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr:  []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{Upstreams: upstreams},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		UseDNS64:       true,
		DNS64Prefs:     []netip.Prefix{nat64Pref},
		UpstreamMode:   UpstreamModeParallel,
	})

	origReq := (&dns.Msg{}).SetQuestion(dnsproxytest.FQDN, dns.TypeAAAA)
	origResp := (&dns.Msg{}).SetReply(origReq)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	u, wrappedDNS64 := p.performDNS64(ctx, origReq, origResp, upstreams)
	require.NotNil(t, u)
	require.Len(t, wrappedDNS64, len(upstreams))
	require.Contains(t, wrappedDNS64, u)

	for i := range upstreams {
		w := testutil.RequireTypeAssert[*upstreamWithStats](t, wrappedDNS64[i])

		assert.NotSame(t, upstreams[i], wrappedDNS64[i], "wrapper at index %d is not fresh", i)
		assert.Samef(
			t,
			upstreams[i],
			w.upstream,
			"the wrapper at index %d must wrap the original upstream", i,
		)
	}

	// The response must have been synthesized from the DNS64 exchange.
	require.Len(t, origResp.Answer, 1)

	res := testutil.RequireTypeAssert[*dns.AAAA](t, origResp.Answer[0])

	assert.Equal(t, wantAAAA, res.AAAA.String())
}

// newNamedUpstream creates a new test upstream with the given name.  It
// implements the Exchange method by returning a synthesized A record for A
// queries.
func newNamedUpstream(tb testing.TB, name string) (ups *testUpstream) {
	tb.Helper()

	onExchange := func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(req)

		if req.Question[0].Qtype != dns.TypeA {
			return resp, nil
		}

		resp.Answer = []dns.RR{&dns.A{
			A: dnsproxytest.IPv4,
			Hdr: dns.RR_Header{
				Name:   dnsproxytest.FQDN,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
		}}

		return resp, nil
	}

	return &testUpstream{
		OnExchange: onExchange,
		OnAddress:  func() (addr string) { return name },
		OnClose:    func() (err error) { panic(testutil.UnexpectedCall()) },
	}
}
