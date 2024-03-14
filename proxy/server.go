package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
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

// handleDNSRequest processes the incoming packet bytes and returns with an optional response packet.
func (p *Proxy) handleDNSRequest(d *DNSContext) (err error) {
	p.logDNSMessage(d.Req)

	if d.Req.Response {
		log.Debug("proxy: dropping incoming reply packet from %s", d.Addr.String())

		return nil
	}

	if p.BeforeRequestHandler != nil {
		var ok bool

		ok, err = p.BeforeRequestHandler(p, d)
		if err != nil {
			log.Error("Error in the BeforeRequestHandler: %s", err)
			d.Res = p.msgConstructor.NewMsgSERVFAIL(d.Req)
			p.respond(d)

			return nil
		}

		if !ok {
			// Do nothing, don't reply
			return nil
		}
	}

	// ratelimit based on IP only, protects CPU cycles and outbound connections
	//
	// TODO(e.burkov):  Investigate if written above true and move to UDP server
	// implementation?
	if d.Proto == ProtoUDP && p.isRatelimited(d.Addr.Addr()) {
		log.Debug("proxy: ratelimiting %v based on IP only", d.Addr)

		// Do nothing, don't reply, we got ratelimited.
		return nil
	}

	d.Res = p.validateRequest(d)
	if d.Res == nil {
		if len(p.UpstreamConfig.Upstreams) == 0 {
			// TODO(e.burkov):  Investigate if we can remove this.
			panic("SHOULD NOT HAPPEN: no default upstreams specified")
		}

		defer func() { err = errors.Annotate(err, "handling request: %w") }()

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
		log.Debug("proxy: got invalid number of questions: %v", len(d.Req.Question))

		return p.msgConstructor.NewMsgSERVFAIL(d.Req)
	case p.RefuseAny && d.Req.Question[0].Qtype == dns.TypeANY:
		// Refuse requests of type ANY (anti-DDOS measure).
		log.Debug("proxy: refusing type=ANY request")

		return p.msgConstructor.NewMsgNOTIMPLEMENTED(d.Req)
	case p.recDetector.check(*d.Req):
		log.Debug("proxy: recursion detected resolving %q", d.Req.Question[0].Name)

		return p.msgConstructor.NewMsgNXDOMAIN(d.Req)
	default:
		q := d.Req.Question[0]
		if q.Qtype != dns.TypePTR {
			return nil
		}

		requestedPref, err := proxynetutil.ExtractARPASubnet(q.Name)
		if err != nil {
			log.Debug("proxy: parsing reversed subnet: %v", err)

			return nil
		}

		if p.PrivateSubnets.Contains(requestedPref.Addr()) {
			if !d.IsLocalClient {
				log.Debug("proxy: %s requests a private arpa domain %q", d.Addr, q.Name)

				return p.msgConstructor.NewMsgNXDOMAIN(d.Req)
			}

			d.PrivateARPA = requestedPref
		}

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
