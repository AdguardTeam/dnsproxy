package proxy

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testIPv4 is a test IPv4 address used for tests.
var testIPv4 = netutil.IPv4Localhost()

// testDomain is a test FQDN used for tests.
const testDomain = "dns64.example.com."

func TestProxy_performDNS64_noWrapperReuse(t *testing.T) {
	nat64Pref := "64:ff9b::/96"
	wantAAAA := "64:ff9b::7f00:1"

	upstreams := []upstream.Upstream{
		newNamedUpstream(t, "upstream1"),
		newNamedUpstream(t, "upstream2"),
	}

	p := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		TCPListenAddr: []*net.TCPAddr{dnsproxytest.LocalhostAnyPortTCP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: upstreams,
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		UseDNS64:       true,
		DNS64Prefs:     []netip.Prefix{netip.MustParsePrefix(nat64Pref)},
		UpstreamMode:   UpstreamModeParallel,
	})

	origReq := (&dns.Msg{}).SetQuestion(testDomain, dns.TypeAAAA)
	origResp := (&dns.Msg{}).SetReply(origReq)

	// Mimic replyFromUpstream: the first exchange uses its own wrappers,
	// while performDNS64 must wrap the original upstreams itself.
	wrappedFirst := upstreamsWithStats(upstreams)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	u, wrappedDNS64 := p.performDNS64(ctx, origReq, origResp, upstreams)
	require.NotNil(t, u)
	require.Len(t, wrappedDNS64, len(upstreams))
	require.Contains(t, wrappedDNS64, u)

	for i := range upstreams {
		w, ok := wrappedDNS64[i].(*upstreamWithStats)
		require.Truef(t, ok, "unexpected wrapper type %T at index %d", wrappedDNS64[i], i)

		assert.NotSamef(t, wrappedFirst[i], wrappedDNS64[i], "wrapper at index %d is reused", i)
		assert.Samef(t, upstreams[i], w.upstream, "the wrapper at index %d must wrap the original upstream", i)
	}

	// The response must have been synthesized from the DNS64 exchange.
	require.Len(t, origResp.Answer, 1)
	require.IsType(t, &dns.AAAA{}, origResp.Answer[0])

	assert.Equal(t, wantAAAA, origResp.Answer[0].(*dns.AAAA).AAAA.String())
}

// newNamedUpstream creates a new test upstream with the given name.
func newNamedUpstream(tb testing.TB, name string) (ups *testUpstream) {
	tb.Helper()

	onExchange := func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(req)

		if req.Question[0].Qtype != dns.TypeA {
			return resp, nil
		}

		resp.Answer = []dns.RR{&dns.A{
			A: testIPv4.AsSlice(),
			Hdr: dns.RR_Header{
				Name:   testDomain,
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
