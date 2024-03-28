package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// startListeners configures and starts listener loops
func (p *Proxy) startListeners(ctx context.Context) error {
	err := p.createUDPListeners(ctx)
	if err != nil {
		return err
	}

	err = p.createTCPListeners(ctx)
	if err != nil {
		return err
	}

	err = p.createTLSListeners()
	if err != nil {
		return err
	}

	err = p.createHTTPSListeners()
	if err != nil {
		return err
	}

	err = p.createQUICListeners()
	if err != nil {
		return err
	}

	err = p.createDNSCryptListeners()
	if err != nil {
		return err
	}

	for _, l := range p.udpListen {
		go p.udpPacketLoop(l, p.requestsSema)
	}

	for _, l := range p.tcpListen {
		go p.tcpPacketLoop(l, ProtoTCP, p.requestsSema)
	}

	for _, l := range p.tlsListen {
		go p.tcpPacketLoop(l, ProtoTLS, p.requestsSema)
	}

	for _, l := range p.httpsListen {
		go func(l net.Listener) { _ = p.httpsServer.Serve(l) }(l)
	}

	for _, l := range p.h3Listen {
		go func(l *quic.EarlyListener) { _ = p.h3Server.ServeListener(l) }(l)
	}

	for _, l := range p.quicListen {
		go p.quicPacketLoop(l, p.requestsSema)
	}

	for _, l := range p.dnsCryptUDPListen {
		go func(l *net.UDPConn) { _ = p.dnsCryptServer.ServeUDP(l) }(l)
	}

	for _, l := range p.dnsCryptTCPListen {
		go func(l net.Listener) { _ = p.dnsCryptServer.ServeTCP(l) }(l)
	}

	return nil
}

// handleBefore calls the [BeforeRequestHandler] if it's set and returns true if
// the request should be processed further.
func (p *Proxy) handleBefore(d *DNSContext) (cont bool) {
	if p.BeforeRequestHandler == nil {
		return true
	}

	ok, err := p.BeforeRequestHandler(p, d)
	if err != nil {
		log.Error("dnsproxy: handling before request: %s", err)

		d.Res = p.messages.NewMsgSERVFAIL(d.Req)
		p.respond(d)

		return false
	}

	return ok
}

// handleDNSRequest processes the incoming packet bytes and returns with an optional response packet.
func (p *Proxy) handleDNSRequest(d *DNSContext) error {
	p.logDNSMessage(d.Req)

	if d.Req.Response {
		log.Debug("dnsproxy: dropping incoming response packet from %s", d.Addr)

		return nil
	}

	if !p.handleBefore(d) {
		return nil
	}

	// ratelimit based on IP only, protects CPU cycles and outbound connections
	//
	// TODO(e.burkov):  Investigate if written above true and move to UDP server
	// implementation?
	if d.Proto == ProtoUDP && p.isRatelimited(d.Addr.Addr()) {
		log.Debug("dnsproxy: ratelimiting %s based on IP only", d.Addr)

		return nil // do nothing, don't reply, we got ratelimited
	}

	d.Res = p.validateRequest(d)

	var err error

	if d.Res == nil {
		if len(p.UpstreamConfig.Upstreams) == 0 {
			panic("SHOULD NOT HAPPEN: no default upstreams specified")
		}

		defer func() { err = errors.Annotate(err, "handling request: %w") }()

		// execute the DNS request
		// if there is a custom middleware configured, use it
		if p.RequestHandler != nil {
			err = p.RequestHandler(p, d)
		} else {
			err = p.Resolve(d)
		}
	}

	p.logDNSMessage(d.Res)
	p.respond(d)

	return err
}

// validateRequest returns a response for invalid request or nil if the request
// is ok.
func (p *Proxy) validateRequest(d *DNSContext) (resp *dns.Msg) {
	switch {
	case len(d.Req.Question) != 1:
		log.Debug("dnsproxy: got invalid number of questions: %d", len(d.Req.Question))

		// TODO(e.burkov):  Probably, FORMERR would be a better choice here.
		// Check out RFC.
		return p.messages.NewMsgSERVFAIL(d.Req)
	case p.RefuseAny && d.Req.Question[0].Qtype == dns.TypeANY:
		// Refuse requests of type ANY (anti-DDOS measure).
		log.Debug("dnsproxy: refusing type=ANY request")

		return p.messages.NewMsgNOTIMPLEMENTED(d.Req)
	case p.recDetector.check(d.Req):
		log.Debug("dnsproxy: recursion detected resolving %q", d.Req.Question[0].Name)

		return p.messages.NewMsgNXDOMAIN(d.Req)
	default:
		return nil
	}
}

// respond writes the specified response to the client (or does nothing if d.Res is empty)
func (p *Proxy) respond(d *DNSContext) {
	// d.Conn can be nil in the case of a DoH request.
	if d.Conn != nil {
		_ = d.Conn.SetWriteDeadline(time.Now().Add(defaultTimeout))
	}

	var err error

	switch d.Proto {
	case ProtoUDP:
		err = p.respondUDP(d)
	case ProtoTCP:
		err = p.respondTCP(d)
	case ProtoTLS:
		err = p.respondTCP(d)
	case ProtoHTTPS:
		err = p.respondHTTPS(d)
	case ProtoQUIC:
		err = p.respondQUIC(d)
	case ProtoDNSCrypt:
		err = p.respondDNSCrypt(d)
	default:
		err = fmt.Errorf("SHOULD NOT HAPPEN - unknown protocol: %s", d.Proto)
	}

	if err != nil {
		logWithNonCrit(err, fmt.Sprintf("responding %s request", d.Proto))
	}
}

// Set TTL value of all records according to our settings
func (p *Proxy) setMinMaxTTL(r *dns.Msg) {
	for _, rr := range r.Answer {
		originalTTL := rr.Header().Ttl
		newTTL := respectTTLOverrides(originalTTL, p.CacheMinTTL, p.CacheMaxTTL)

		if originalTTL != newTTL {
			log.Debug("Override TTL from %d to %d", originalTTL, newTTL)
			rr.Header().Ttl = newTTL
		}
	}
}

func (p *Proxy) logDNSMessage(m *dns.Msg) {
	if m == nil {
		return
	}

	if m.Response {
		log.Tracef("OUT: %s", m)
	} else {
		log.Tracef("IN: %s", m)
	}
}
