package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// startListeners configures listeners and starts listening each configured
// address.  If it returns an error, all listeners should be closed manually.
func (p *Proxy) startListeners(ctx context.Context) (err error) {
	err = p.initUDPListeners(ctx)
	if err != nil {
		return err
	}

	err = p.initTCPListeners(ctx)
	if err != nil {
		return err
	}

	err = p.initTLSListeners(ctx)
	if err != nil {
		return err
	}

	err = p.initHTTPSListeners(ctx)
	if err != nil {
		return err
	}

	err = p.initQUICListeners(ctx)
	if err != nil {
		return err
	}

	err = p.initDNSCryptListeners(ctx)
	if err != nil {
		return err
	}

	return nil
}

// serveListeners starts serving the configured listeners.
func (p *Proxy) serveListeners() {
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
}

// handleDNSRequest processes the context.  The only error it returns is the one
// from the [RequestHandler], or [Resolve] if the [RequestHandler] is not set.
// d is left without a response as the documentation to [BeforeRequestHandler]
// says, and if it's ratelimited.
func (p *Proxy) handleDNSRequest(d *DNSContext) (err error) {
	p.logDNSMessage(d.Req)

	if d.Req.Response {
		p.logger.Debug("dropping incoming response packet", "addr", d.Addr)

		return nil
	}

	ip := d.Addr.Addr()
	d.IsPrivateClient = p.privateNets.Contains(ip)

	if !p.handleBefore(d) {
		return nil
	}

	// ratelimit based on IP only, protects CPU cycles and outbound connections
	//
	// TODO(e.burkov):  Investigate if written above true and move to UDP server
	// implementation?
	if d.Proto == ProtoUDP && p.isRatelimited(ip) {
		p.logger.Debug("ratelimited based on ip only", "addr", d.Addr)

		// Don't reply to ratelimited clients.
		return nil
	}

	d.Res = p.validateRequest(d)
	if d.Res == nil {
		if p.RequestHandler != nil {
			err = errors.Annotate(p.RequestHandler(p, d), "using request handler: %w")
		} else {
			err = errors.Annotate(p.Resolve(d), "using default request handler: %w")
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
		p.logger.Debug("invalid number of questions", "req_questions_len", len(d.Req.Question))

		// TODO(e.burkov):  Probably, FORMERR would be a better choice here.
		// Check out RFC.
		return p.messages.NewMsgSERVFAIL(d.Req)
	case p.RefuseAny && d.Req.Question[0].Qtype == dns.TypeANY:
		// Refuse requests of type ANY (anti-DDOS measure).
		p.logger.Debug("refusing dns type any request")

		return p.messages.NewMsgNOTIMPLEMENTED(d.Req)
	case p.recDetector.check(d.Req):
		p.logger.Debug("recursion detected", "req_question", d.Req.Question[0].Name)

		return p.messages.NewMsgNXDOMAIN(d.Req)
	case d.isForbiddenARPA(p.privateNets, p.logger):
		p.logger.Debug(
			"private arpa domain is requested",
			"addr", d.Addr,
			"arpa", d.Req.Question[0].Name,
		)

		return p.messages.NewMsgNXDOMAIN(d.Req)
	default:
		return nil
	}
}

// isForbiddenARPA returns true if dctx contains a PTR, SOA, or NS request for
// some private address and client's address is not within the private network.
// Otherwise, it sets [DNSContext.RequestedPrivateRDNS] for future use.
func (dctx *DNSContext) isForbiddenARPA(privateNets netutil.SubnetSet, l *slog.Logger) (ok bool) {
	q := dctx.Req.Question[0]
	switch q.Qtype {
	case dns.TypePTR, dns.TypeSOA, dns.TypeNS:
		// Go on.
		//
		// TODO(e.burkov):  Reconsider the list of types involved to private
		// address space.  Perhaps, use the logic for any type.  See
		// https://www.rfc-editor.org/rfc/rfc6761.html#section-6.1.
	default:
		return false
	}

	requestedPref, err := netutil.ExtractReversedAddr(q.Name)
	if err != nil {
		l.Debug("parsing reversed subnet", slogutil.KeyError, err)

		return false
	}

	if privateNets.Contains(requestedPref.Addr()) {
		dctx.RequestedPrivateRDNS = requestedPref

		return !dctx.IsPrivateClient
	}

	return false
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
		logWithNonCrit(err, "responding request", d.Proto, p.logger)
	}
}

// Set TTL value of all records according to our settings
func (p *Proxy) setMinMaxTTL(r *dns.Msg) {
	for _, rr := range r.Answer {
		originalTTL := rr.Header().Ttl
		newTTL := respectTTLOverrides(originalTTL, p.CacheMinTTL, p.CacheMaxTTL)

		if originalTTL != newTTL {
			p.logger.Debug("ttl overwritten", "old", originalTTL, "new", newTTL)
			rr.Header().Ttl = newTTL
		}
	}
}

// logDNSMessage logs the given DNS message.
func (p *Proxy) logDNSMessage(m *dns.Msg) {
	if m == nil {
		return
	}

	var msg string
	if m.Response {
		msg = "out"
	} else {
		msg = "in"
	}

	slogutil.PrintLines(context.TODO(), p.logger, slog.LevelDebug, msg, m.String())
}

// logWithNonCrit logs the error on the appropriate level depending on whether
// err is a critical error or not.
func logWithNonCrit(err error, msg string, proto Proto, l *slog.Logger) {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isEPIPE(err) {
		l.Debug(
			"connection is closed",
			"proto", proto,
			"details", msg,
			slogutil.KeyError, err,
		)
	} else if netErr := net.Error(nil); errors.As(err, &netErr) && netErr.Timeout() {
		l.Debug(
			"connection timed out",
			"proto", proto,
			"details", msg,
			slogutil.KeyError, err,
		)
	} else {
		l.Error(msg, "proto", proto, slogutil.KeyError, err)
	}
}
