package fastip

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFastestAddr_ExchangeFastest(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		const errDesired errors.Error = "this is expected"

		u := &errUpstream{
			err: errDesired,
		}
		f := NewFastestAddr()

		resp, up, err := f.ExchangeFastest(testARequest(t), []upstream.Upstream{u})
		require.Error(t, err)

		assert.ErrorIs(t, err, errDesired)
		assert.Nil(t, resp)
		assert.Nil(t, up)
	})

	t.Run("one_dead", func(t *testing.T) {
		port := listen(t, nil)

		f := NewFastestAddr()
		f.pingPorts = []uint{port}

		// The alive IP is the just created local listener's address.  The dead
		// one is known as TEST-NET-1 which shouldn't be routed at all.  See
		// RFC-5737 (https://datatracker.ietf.org/doc/html/rfc5737).
		aliveIP, deadIP := net.IP{127, 0, 0, 1}, net.IP{192, 0, 2, 1}
		alive := new(testAUpstream).add(t.Name(), aliveIP)
		dead := new(testAUpstream).add(t.Name(), deadIP)

		rep, up, err := f.ExchangeFastest(testARequest(t), []upstream.Upstream{dead, alive})
		require.NoError(t, err)

		assert.Equal(t, up, alive)

		require.NotNil(t, rep)
		require.NotEmpty(t, rep.Answer)
		require.IsType(t, new(dns.A), rep.Answer[0])

		ip := rep.Answer[0].(*dns.A).A
		assert.True(t, aliveIP.Equal(ip))
	})

	t.Run("all_dead", func(t *testing.T) {
		f := NewFastestAddr()
		f.pingPorts = []uint{getFreePort(t)}

		firstIP := net.IP{127, 0, 0, 1}
		up1 := new(testAUpstream).
			add(t.Name(), firstIP).
			add(t.Name(), net.IP{127, 0, 0, 2}).
			add(t.Name(), net.IP{127, 0, 0, 3})

		resp, _, err := f.ExchangeFastest(testARequest(t), []upstream.Upstream{up1})
		require.NoError(t, err)

		require.NotNil(t, resp)
		require.NotEmpty(t, resp.Answer)
		require.IsType(t, new(dns.A), resp.Answer[0])

		ip := resp.Answer[0].(*dns.A).A
		assert.True(t, firstIP.Equal(ip))
	})
}

type errUpstream struct {
	upstream.Upstream
	err error
}

func (u errUpstream) Exchange(m *dns.Msg) (*dns.Msg, error) {
	return nil, u.err
}

type testAUpstream struct {
	recs []*dns.A
}

func (u *testAUpstream) Exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	resp = &dns.Msg{}
	resp.SetReply(m)

	for _, a := range u.recs {
		resp.Answer = append(resp.Answer, a)
	}

	return resp, nil
}

func (u *testAUpstream) Address() string {
	return ""
}

func (u *testAUpstream) add(host string, ip net.IP) (chain *testAUpstream) {
	u.recs = append(u.recs, &dns.A{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeA,
			Name:   dns.Fqdn(host),
			Ttl:    60,
		},
		A: ip,
	})

	return u
}

func testARequest(t *testing.T) (req *dns.Msg) {
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
