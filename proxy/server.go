package proxy

import (
	"fmt"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

// startListeners configures and starts listener loops
func (p *Proxy) startListeners() error {
	err := p.createUDPListeners()
	if err != nil {
		return err
	}

	err = p.createTCPListeners()
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

	for _, l := range p.udpListen {
		go p.udpPacketLoop(l)
	}

	for _, l := range p.tcpListen {
		go p.tcpPacketLoop(l, ProtoTCP)
	}

	for _, l := range p.tlsListen {
		go p.tcpPacketLoop(l, ProtoTLS)
	}

	for i := range p.httpsServer {
		go p.listenHTTPS(p.httpsServer[i], p.httpsListen[i])
	}

	for _, l := range p.quicListen {
		go p.quicPacketLoop(l)
	}

	return nil
}

// guardMaxGoroutines makes sure that there are no more than p.MaxGoroutines parallel goroutines
func (p *Proxy) guardMaxGoroutines() {
	if p.maxGoroutines != nil {
		p.maxGoroutines <- true
	}
}

// freeMaxGoroutines allows other goroutines to do the job
func (p *Proxy) freeMaxGoroutines() {
	if p.maxGoroutines != nil {
		<-p.maxGoroutines
	}
}

// handleDNSRequest processes the incoming packet bytes and returns with an optional response packet.
func (p *Proxy) handleDNSRequest(d *DNSContext) error {
	d.StartTime = time.Now()
	p.logDNSMessage(d.Req)

	if d.Req.Response {
		log.Debug("Dropping incoming Reply packet from %s", d.Addr.String())
		return nil
	}

	if p.BeforeRequestHandler != nil {
		ok, err := p.BeforeRequestHandler(p, d)
		if err != nil {
			log.Error("Error in the BeforeRequestHandler: %s", err)
			d.Res = p.genServerFailure(d.Req)
			p.respond(d)
			return nil
		}
		if !ok {
			return nil // do nothing, don't reply
		}
	}

	// ratelimit based on IP only, protects CPU cycles and outbound connections
	if d.Proto == ProtoUDP && p.isRatelimited(d.Addr) {
		log.Tracef("Ratelimiting %v based on IP only", d.Addr)
		return nil // do nothing, don't reply, we got ratelimited
	}

	if len(d.Req.Question) != 1 {
		log.Debug("got invalid number of questions: %v", len(d.Req.Question))
		d.Res = p.genServerFailure(d.Req)
	}

	// refuse ANY requests (anti-DDOS measure)
	if p.RefuseAny && len(d.Req.Question) > 0 && d.Req.Question[0].Qtype == dns.TypeANY {
		log.Tracef("Refusing type=ANY request")
		d.Res = p.genNotImpl(d.Req)
	}

	var err error

	if d.Res == nil {
		if len(p.UpstreamConfig.Upstreams) == 0 {
			panic("SHOULD NOT HAPPEN: no default upstreams specified")
		}

		// execute the DNS request
		// if there is a custom middleware configured, use it
		if p.RequestHandler != nil {
			err = p.RequestHandler(p, d)
		} else {
			err = p.Resolve(d)
		}

		if err != nil {
			err = errorx.Decorate(err, "talking to dnsUpstream failed")
		}
	}

	p.logDNSMessage(d.Res)
	p.respond(d)
	return err
}

// respond writes the specified response to the client (or does nothing if d.Res is empty)
func (p *Proxy) respond(d *DNSContext) {
	if d.Res == nil {
		return
	}

	// d.Conn can be nil in the case of a DOH request
	if d.Conn != nil {
		d.Conn.SetWriteDeadline(time.Now().Add(defaultTimeout)) //nolint
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
	default:
		err = fmt.Errorf("SHOULD NOT HAPPEN - unknown protocol: %s", d.Proto)
	}

	if err != nil {
		if strings.HasSuffix(err.Error(), "use of closed network connection") {
			// This case may happen while we're restarting DNS server
			log.Debug("error while responding to a DNS request: %s", err)
		} else {
			log.Printf("error while responding to a DNS request: %s", err)
		}
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

func (p *Proxy) genServerFailure(request *dns.Msg) *dns.Msg {
	resp := dns.Msg{}
	resp.SetRcode(request, dns.RcodeServerFailure)
	resp.RecursionAvailable = true
	return &resp
}

func (p *Proxy) genNotImpl(request *dns.Msg) *dns.Msg {
	resp := dns.Msg{}
	resp.SetRcode(request, dns.RcodeNotImplemented)
	resp.RecursionAvailable = true
	resp.SetEdns0(1452, false) // NOTIMPL without EDNS is treated as 'we don't support EDNS', so explicitly set it
	return &resp
}

func (p *Proxy) genNXDomain(req *dns.Msg) *dns.Msg {
	resp := dns.Msg{}
	resp.SetRcode(req, dns.RcodeNameError)
	resp.RecursionAvailable = true
	return &resp
}

func (p *Proxy) logDNSMessage(m *dns.Msg) {
	if m.Response {
		log.Tracef("OUT: %s", m)
	} else {
		log.Tracef("IN: %s", m)
	}
}
