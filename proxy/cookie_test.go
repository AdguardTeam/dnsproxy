package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// newMsgWithCookie returns a DNS message with a single question and a COOKIE
// option containing cc and sc concatenated.
func newMsgWithCookie(q dns.Question, cc, sc []byte, udpSize uint16, do bool) (m *dns.Msg) {
	m = &dns.Msg{Question: []dns.Question{q}}
	m.SetEdns0(udpSize, do)

	opt := m.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: hex.EncodeToString(append(cc, sc...)),
	})

	return m
}

func TestParseCookie(t *testing.T) {
	q := dns.Question{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	cc := []byte("12345678")
	sc := []byte("server_cookie")

	m := newMsgWithCookie(q, cc, sc, 1232, false)

	gotCC, gotSC := parseCookie(m)
	assert.Equal(t, cc, gotCC)
	assert.Equal(t, sc, gotSC)

	t.Run("invalid_hex", func(t *testing.T) {
		m := &dns.Msg{Question: []dns.Question{q}}
		m.SetEdns0(defaultUDPBufSize, false)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "zzzz"})

		cc, sc := parseCookie(m)
		assert.Nil(t, cc)
		assert.Nil(t, sc)
	})

	t.Run("too_short", func(t *testing.T) {
		m := newMsgWithCookie(q, []byte("short"), nil, defaultUDPBufSize, false)
		cc, sc := parseCookie(m)
		assert.Nil(t, cc)
		assert.Nil(t, sc)
	})
}

func TestStripCookie(t *testing.T) {
	q := dns.Question{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	cc := []byte("12345678")

	m := newMsgWithCookie(q, cc, nil, defaultUDPBufSize, false)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1}})

	stripCookie(m)

	opt = m.IsEdns0()
	assert.Len(t, opt.Option, 1)
	_, hasCookie := opt.Option[0].(*dns.EDNS0_COOKIE)
	assert.False(t, hasCookie)
}

func TestServerCookieDeterministic(t *testing.T) {
	p := &Proxy{
		Config: Config{
			DisableDNSCookies: false,
			DNSCookieSecret:   "000102030405060708090a0b0c0d0e0f",
		},
		cookieMu: sync.RWMutex{},
	}
	err := p.initCookieSecret()
	assert.NoError(t, err)

	client := []byte("12345678")
	ip1 := netip.MustParseAddr("192.0.2.1")
	ip2 := netip.MustParseAddr("192.0.2.2")

	c1 := p.serverCookie(ip1, client)
	c2 := p.serverCookie(ip1, client)
	assert.Equal(t, c1, c2, "same IP and client cookie must be stable")

	c3 := p.serverCookie(ip2, client)
	assert.NotEqual(t, c1, c3, "different IP must yield different cookie")

	expected := hmac.New(sha256.New, p.cookieSecret)
	_, _ = expected.Write(client)
	_, _ = expected.Write(ip1.AsSlice())
	assert.Equal(t, expected.Sum(nil)[:serverCookieLen], c1)
}

func TestHandleCookiesEnabled(t *testing.T) {
	secretHex := "000102030405060708090a0b0c0d0e0f"
	p := &Proxy{
		Config: Config{
			DisableDNSCookies: false,
			DNSCookieSecret:   secretHex,
		},
		cookieMu: sync.RWMutex{},
	}
	assert.NoError(t, p.initCookieSecret())

	q := dns.Question{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	cc := []byte("12345678")

	req := newMsgWithCookie(q, cc, nil, 1232, true)
	dctx := &DNSContext{
		Req:     req,
		Res:     &dns.Msg{Question: []dns.Question{q}},
		Addr:    netip.MustParseAddrPort("192.0.2.5:53"),
		doBit:   true,
		udpSize: 1500,
	}

	// Incoming request: parse and strip.
	p.handleRequestCookies(dctx)
	assert.Equal(t, cc, dctx.ReqClientCookie)
	assert.Empty(t, dctx.Req.IsEdns0().Option, "cookie must be stripped before upstream")

	// Prepare response with a bogus upstream cookie that must be removed.
	respOpt := dctx.Res.IsEdns0()
	if respOpt == nil {
		dctx.Res.SetEdns0(1200, false)
		respOpt = dctx.Res.IsEdns0()
	}
	respOpt.Option = append(respOpt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: hex.EncodeToString([]byte("badcookie"))})

	p.handleResponseCookies(dctx)

	opt := dctx.Res.IsEdns0()
	if assert.NotNil(t, opt) && assert.Len(t, opt.Option, 1) {
		cook, ok := opt.Option[0].(*dns.EDNS0_COOKIE)
		if assert.True(t, ok) {
			raw, err := hex.DecodeString(cook.Cookie)
			assert.NoError(t, err)
			assert.Equal(t, append(cc, p.serverCookie(dctx.Addr.Addr(), cc)...), raw)
		}
	}
	assert.Equal(t, uint16(1500), opt.UDPSize())
	assert.True(t, opt.Do())
}

func TestHandleCookiesDisabled(t *testing.T) {
	p := &Proxy{Config: Config{DisableDNSCookies: true}}
	q := dns.Question{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	cc := []byte("12345678")

	req := newMsgWithCookie(q, cc, nil, 1232, false)
	res := newMsgWithCookie(q, cc, []byte("servercookie"), 1232, false)

	dctx := &DNSContext{
		Req: req,
		Res: res,
	}

	p.handleRequestCookies(dctx)
	assert.Nil(t, dctx.ReqClientCookie)
	assert.Empty(t, req.IsEdns0().Option)

	p.handleResponseCookies(dctx)
	assert.Empty(t, res.IsEdns0().Option)
}
