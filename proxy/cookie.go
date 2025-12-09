package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/miekg/dns"
)

const (
	// clientCookieLen is the length of the client cookie in bytes.
	clientCookieLen = 8

	// serverCookieLen is the length of the server cookie in bytes.
	serverCookieLen = 16

	// cookieSecretLen is the size of the secret used to generate server
	// cookies.
	cookieSecretLen = 16

	// doBitMask is the mask of the DO bit in the TTL field of an OPT record.
	doBitMask = uint32(1 << 15)
)

// parseCookie returns the client and server cookies from m if present.  The
// client cookie is required to be at least eight bytes long.
func parseCookie(m *dns.Msg) (client, server []byte) {
	if m == nil {
		return nil, nil
	}

	opt := m.IsEdns0()
	if opt == nil {
		return nil, nil
	}

	for _, o := range opt.Option {
		c, ok := o.(*dns.EDNS0_COOKIE)
		if !ok {
			continue
		}

		raw, err := hex.DecodeString(c.Cookie)
		if err != nil || len(raw) < clientCookieLen {
			continue
		}

		client = raw[:clientCookieLen]
		if len(raw) > clientCookieLen {
			server = raw[clientCookieLen:]
		}

		return client, server
	}

	return nil, nil
}

// stripCookie removes any EDNS cookie options from m.
func stripCookie(m *dns.Msg) {
	if m == nil {
		return
	}

	opt := m.IsEdns0()
	if opt == nil {
		return
	}

	opts := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() == dns.EDNS0COOKIE {
			continue
		}

		opts = append(opts, o)
	}

	opt.Option = opts
}

// handleRequestCookies parses client cookies and strips cookie options before
// forwarding requests upstream.
func (p *Proxy) handleRequestCookies(dctx *DNSContext) {
	if dctx == nil || dctx.Req == nil {
		return
	}

	if !p.DisableDNSCookies {
		if client, _ := parseCookie(dctx.Req); len(client) > 0 {
			dctx.reqClientCookie = client
		}
	}

	stripCookie(dctx.Req)
}

// handleResponseCookies sets the response cookie if needed or strips cookie
// options when cookies are disabled.
func (p *Proxy) handleResponseCookies(dctx *DNSContext) {
	if dctx == nil || dctx.Res == nil {
		return
	}

	if p.DisableDNSCookies {
		stripCookie(dctx.Res)

		return
	}

	if len(dctx.reqClientCookie) == 0 {
		stripCookie(dctx.Res)

		return
	}

	udpSize := dctx.udpSize
	if udpSize == 0 {
		udpSize = defaultUDPBufSize
	}

	stripCookie(dctx.Res)

	server := p.serverCookie(dctx.Addr.Addr(), dctx.reqClientCookie)
	if len(server) == 0 {
		return
	}

	setCookie(dctx.Res, dctx.reqClientCookie, server, udpSize, dctx.doBit)
}

// serverCookie returns the server cookie for the provided address and client
// cookie using an HMAC-SHA256.
func (p *Proxy) serverCookie(ip netip.Addr, client []byte) (server []byte) {
	if len(client) < clientCookieLen || !ip.IsValid() {
		return nil
	}

	p.cookieMu.Lock()
	secret := p.cookieSecret
	p.cookieMu.Unlock()

	if len(secret) != cookieSecretLen {
		return nil
	}

	h := hmac.New(sha256.New, secret)
	_, _ = h.Write(client)
	_, _ = h.Write(ip.AsSlice())

	// Truncate to sixteen bytes.
	return h.Sum(nil)[:serverCookieLen]
}

// setCookie ensures msg has the OPT record and sets the cookie option to
// client+server.  udpSize is the UDP buffer size advertised to the client.
func setCookie(msg *dns.Msg, client, server []byte, udpSize uint16, do bool) {
	if msg == nil || len(client) == 0 || len(server) == 0 {
		return
	}

	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(udpSize, do)
		opt = msg.IsEdns0()
	} else {
		opt.SetUDPSize(udpSize)
		if do {
			opt.SetDo()
		} else {
			opt.Hdr.Ttl &^= doBitMask
		}
	}

	stripCookie(msg)

	cookie := make([]byte, 0, len(client)+len(server))
	cookie = append(cookie, client...)
	cookie = append(cookie, server...)

	opt = msg.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: hex.EncodeToString(cookie),
	})
}

// decodeCookieSecret decodes hexSecret and validates its length.
func decodeCookieSecret(hexSecret string) (secret []byte, err error) {
	secret, err = hex.DecodeString(hexSecret)
	if err != nil {
		return nil, fmt.Errorf("decoding dns cookie secret: %w", err)
	}

	if len(secret) != cookieSecretLen {
		return nil, fmt.Errorf(
			"decoding dns cookie secret: invalid length %d, want %d",
			len(secret),
			cookieSecretLen,
		)
	}

	return secret, nil
}

// generateCookieSecret returns a new random secret suitable for cookie
// generation.
func generateCookieSecret() (secret []byte, err error) {
	secret = make([]byte, cookieSecretLen)
	_, err = rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("reading random secret: %w", err)
	}

	return secret, nil
}

// initCookieSecret prepares the cookie secret depending on the configuration.
func (p *Proxy) initCookieSecret() (err error) {
	if p.DisableDNSCookies {
		return nil
	}

	var secret []byte
	if p.DNSCookieSecret != "" {
		secret, err = decodeCookieSecret(p.DNSCookieSecret)
	} else {
		secret, err = generateCookieSecret()
	}
	if err != nil {
		return fmt.Errorf("creating dns cookie secret: %w", err)
	}

	p.cookieMu.Lock()
	p.cookieSecret = secret
	p.cookieMu.Unlock()

	return nil
}
