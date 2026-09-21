package fastip_test

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/AdguardTeam/dnsproxy/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/fastip"
	"github.com/AdguardTeam/dnsproxy/internal/nettest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testReplacer is used to replace "/" and "_" with "-" in test domain names.
var testReplacer = strings.NewReplacer("/", "-", "_", "-")

func TestFastestAddr_ExchangeFastest(t *testing.T) {
	t.Parallel()

	l := slogutil.NewDiscardLogger()

	require.True(t, t.Run("error", func(t *testing.T) {
		t.Parallel()

		u := &dnsproxytest.Upstream{
			OnAddress:  func() (addr string) { return "bad_upstream" },
			OnExchange: func(_ *dns.Msg) (resp *dns.Msg, err error) { return nil, assert.AnError },
			OnClose:    func() (err error) { return nil },
		}
		f := fastip.New(&fastip.Config{
			Logger:          l,
			PingWaitTimeout: fastip.DefaultPingWaitTimeout,
		})

		resp, up, err := f.ExchangeFastest(newTestReq(t), []upstream.Upstream{u})
		require.Error(t, err)

		assert.ErrorIs(t, err, assert.AnError)
		assert.Nil(t, resp)
		assert.Nil(t, up)
	}))

	require.True(t, t.Run("one_dead", func(t *testing.T) {
		t.Parallel()

		port := listen(t)

		f := fastip.New(&fastip.Config{
			Logger:          l,
			PingWaitTimeout: fastip.DefaultPingWaitTimeout,
		})

		f.SetPingPorts([]uint{port})

		// The alive IP is the just created local listener's address.  The dead
		// one is known as TEST-NET-1 which shouldn't be routed at all.  See
		// RFC-5737 (https://datatracker.ietf.org/doc/html/rfc5737).
		aliveAddr := netip.MustParseAddr("127.0.0.1")

		alive := newTestAUpstream(t, []*dns.A{newTestRec(t, aliveAddr)})
		dead := newTestAUpstream(t, []*dns.A{newTestRec(t, netip.MustParseAddr("192.0.2.1"))})

		rep, ups, err := f.ExchangeFastest(newTestReq(t), []upstream.Upstream{dead, alive})
		require.NoError(t, err)

		assert.Equal(t, ups, alive)

		require.NotNil(t, rep)
		require.NotEmpty(t, rep.Answer)

		ip := testutil.RequireTypeAssert[*dns.A](t, rep.Answer[0]).A
		assert.Equal(t, aliveAddr.AsSlice(), []byte(ip))
	}))

	require.True(t, t.Run("all_dead", func(t *testing.T) {
		t.Parallel()

		f := fastip.New(&fastip.Config{
			Logger:          l,
			PingWaitTimeout: fastip.DefaultPingWaitTimeout,
		})

		f.SetPingPorts([]uint{nettest.NewFreePort(t)})

		firstIP := netip.MustParseAddr("127.0.0.1")
		ups := newTestAUpstream(t, []*dns.A{
			newTestRec(t, firstIP),
			newTestRec(t, netip.MustParseAddr("127.0.0.2")),
			newTestRec(t, netip.MustParseAddr("127.0.0.3")),
		})

		resp, _, err := f.ExchangeFastest(newTestReq(t), []upstream.Upstream{ups})
		require.NoError(t, err)

		require.NotNil(t, resp)
		require.NotEmpty(t, resp.Answer)

		ip := testutil.RequireTypeAssert[*dns.A](t, resp.Answer[0]).A
		assert.Equal(t, firstIP.AsSlice(), []byte(ip))
	}))
}

// newTestAUpstream returns a new test upstream, which responds with the
// provided A records.
func newTestAUpstream(tb testing.TB, recs []*dns.A) (ups *dnsproxytest.Upstream) {
	tb.Helper()

	onExchange := func(m *dns.Msg) (resp *dns.Msg, err error) {
		resp = &dns.Msg{}
		resp.SetReply(m)

		for _, a := range recs {
			resp.Answer = append(resp.Answer, a)
		}

		return resp, nil
	}

	return &dnsproxytest.Upstream{
		OnAddress:  func() (addr string) { return "" },
		OnClose:    func() (err error) { return nil },
		OnExchange: onExchange,
	}
}

// newTestRec returns a new test A record.
func newTestRec(tb testing.TB, addr netip.Addr) (rr *dns.A) {
	tb.Helper()

	domain := testReplacer.Replace(tb.Name())

	return &dns.A{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeA,
			Name:   dns.Fqdn(domain),
			Ttl:    60,
		},
		A: addr.AsSlice(),
	}
}

// newTestReq returns a new test A request.
func newTestReq(tb testing.TB) (req *dns.Msg) {
	tb.Helper()

	domain := testReplacer.Replace(tb.Name())

	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(domain),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}

// listen is a helper function that creates a new listener on localhost with an
// arbitrary port.
func listen(tb testing.TB) (port uint) {
	tb.Helper()

	host := netip.AddrPortFrom(netutil.IPv4Localhost(), 0).String()
	l, err := net.Listen("tcp", host)
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, l.Close)

	return uint(l.Addr().(*net.TCPAddr).Port)
}
