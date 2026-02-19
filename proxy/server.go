package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/optslog"
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
// from the [Handler], or [Resolve] if the [Handler] is not set.
func (p *Proxy) handleDNSRequest(d *DNSContext) (err error) {
	p.logDNSMessage(d.Req)

	if d.Req.Response {
		p.logger.Debug("dropping incoming response packet", "addr", d.Addr)

		return nil
	}

	ip := d.Addr.Addr()
	d.IsPrivateClient = p.privateNets.Contains(ip)

	// TODO(d.kolyshev):  Consider moving validation to a new middleware.
	d.Res = p.validateRequest(d)
	if d.Res == nil {
		err = p.requestHandler.ServeDNS(p, d)
		if errors.Is(err, ErrDrop) {
			// Don't reply to dropped clients.
			return nil
		}
	}

	p.logDNSMessage(d.Res)
	p.respond(d)

	return err
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

// setMinMaxTTL sets the TTL values of all records according to the proxy
// settings.  r must not be nil.
func (p *Proxy) setMinMaxTTL(ctx context.Context, r *dns.Msg) {
	rrSets := container.KeyValues[string, []dns.RR]{{
		Key:   "answer",
		Value: r.Answer,
	}, {
		Key:   "extra",
		Value: r.Extra,
	}, {
		Key:   "ns",
		Value: r.Ns,
	}}

	for _, rrSet := range rrSets {
		for _, rr := range rrSet.Value {
			original := rr.Header().Ttl
			overridden := respectTTLOverrides(original, p.CacheMinTTL, p.CacheMaxTTL)

			if original == overridden {
				continue
			}

			optslog.Trace3(
				ctx,
				p.logger,
				"ttl overwritten",
				"section", rrSet.Key,
				"old", original,
				"new", overridden,
			)
			rr.Header().Ttl = overridden
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
