package fastip

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is a common timeout value for tests.
const testTimeout = 1 * time.Second

func TestFastestAddr_ExchangeFastest(t *testing.T) {
	l := slogutil.NewDiscardLogger()

	t.Run("error", func(t *testing.T) {
		const errDesired errors.Error = "this is expected"

		u := &errUpstream{
			err: errDesired,
		}
		f := New(&Config{
			Logger:          l,
			PingWaitTimeout: DefaultPingWaitTimeout,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		resp, up, err := f.ExchangeFastest(ctx, newTestReq(t), []upstream.Upstream{u})
		require.Error(t, err)

		assert.ErrorIs(t, err, errDesired)
		assert.Nil(t, resp)
		assert.Nil(t, up)
	})

	t.Run("one_dead", func(t *testing.T) {
		port := listen(t, netip.IPv4Unspecified())

		f := New(&Config{
			Logger:          l,
			PingWaitTimeout: DefaultPingWaitTimeout,
		})
		f.pingPorts = []uint{port}

		// The alive IP is the just created local listener's address.  The dead
		// one is known as TEST-NET-1 which shouldn't be routed at all.  See
		// RFC-5737 (https://datatracker.ietf.org/doc/html/rfc5737).
		aliveAddr := netip.MustParseAddr("127.0.0.1")

		alive := &testAUpstream{
			recs: []*dns.A{newTestRec(t, aliveAddr)},
		}
		dead := &testAUpstream{
			recs: []*dns.A{newTestRec(t, netip.MustParseAddr("192.0.2.1"))},
		}

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		rep, ups, err := f.ExchangeFastest(ctx, newTestReq(t), []upstream.Upstream{dead, alive})
		require.NoError(t, err)

		assert.Equal(t, ups, alive)

		require.NotNil(t, rep)
		require.NotEmpty(t, rep.Answer)

		ip := testutil.RequireTypeAssert[*dns.A](t, rep.Answer[0]).A
		assert.Equal(t, aliveAddr.AsSlice(), []byte(ip))
	})

	t.Run("all_dead", func(t *testing.T) {
		f := New(&Config{
			Logger:          l,
			PingWaitTimeout: DefaultPingWaitTimeout,
		})
		f.pingPorts = []uint{dnsproxytest.NewFreePort(t)}

		firstIP := netip.MustParseAddr("127.0.0.1")
		ups := &testAUpstream{
			recs: []*dns.A{
				newTestRec(t, firstIP),
				newTestRec(t, netip.MustParseAddr("127.0.0.2")),
				newTestRec(t, netip.MustParseAddr("127.0.0.3")),
			},
		}

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		resp, _, err := f.ExchangeFastest(ctx, newTestReq(t), []upstream.Upstream{ups})
		require.NoError(t, err)

		require.NotNil(t, resp)
		require.NotEmpty(t, resp.Answer)

		ip := testutil.RequireTypeAssert[*dns.A](t, resp.Answer[0]).A
		assert.Equal(t, firstIP.AsSlice(), []byte(ip))
	})
}

// testAUpstream is a mock err upstream structure for tests.
type errUpstream struct {
	err      error
	closeErr error
}

// Address implements the [upstream.Upstream] interface for *errUpstream.
func (u *errUpstream) Address() string {
	return "bad_upstream"
}

// Exchange implements the [upstream.Upstream] interface for *errUpstream.
func (u *errUpstream) Exchange(_ context.Context, _ *dns.Msg) (*dns.Msg, error) {
	return nil, u.err
}

// Close implements the [upstream.Upstream] interface for *errUpstream.
func (u *errUpstream) Close() error {
	return u.closeErr
}

// testAUpstream is a mock A upstream structure for tests.
type testAUpstream struct {
	recs []*dns.A
}

// type check
var _ upstream.Upstream = (*testAUpstream)(nil)

// Exchange implements the [upstream.Upstream] interface for *testAUpstream.
func (u *testAUpstream) Exchange(_ context.Context, m *dns.Msg) (resp *dns.Msg, err error) {
	resp = &dns.Msg{}
	resp.SetReply(m)

	for _, a := range u.recs {
		resp.Answer = append(resp.Answer, a)
	}

	return resp, nil
}

// Address implements the [upstream.Upstream] interface for *testAUpstream.
func (u *testAUpstream) Address() (addr string) {
	return ""
}

// Close implements the [upstream.Upstream] interface for *testAUpstream.
func (u *testAUpstream) Close() (err error) {
	return nil
}

// newTestRec returns a new test A record.
func newTestRec(t *testing.T, addr netip.Addr) (rr *dns.A) {
	return &dns.A{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeA,
			Name:   dns.Fqdn(t.Name()),
			Ttl:    60,
		},
		A: addr.AsSlice(),
	}
}

// newTestReq returns a new test A request.
func newTestReq(t *testing.T) (req *dns.Msg) {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(t.Name()),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}
