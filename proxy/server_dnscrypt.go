package proxy

import (
	"net"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

func (p *Proxy) createDNSCryptListeners() error {
	for _, a := range p.DNSCryptUDPListenAddr {
		log.Info("Creating a DNSCrypt UDP listener")
		udpListen, err := net.ListenUDP("udp", a)
		if err != nil {
			return err
		}
		p.dnsCryptUDPListen = append(p.dnsCryptUDPListen, udpListen)
		log.Info("Listening for DNSCrypt messages on udp://%s", udpListen.LocalAddr())
	}

	for _, a := range p.DNSCryptTCPListenAddr {
		log.Info("Creating a DNSCrypt TCP listener")
		tcpListen, err := net.ListenTCP("tcp", a)
		if err != nil {
			return errorx.Decorate(err, "couldn't listen to TCP socket")
		}
		p.dnsCryptTCPListen = append(p.dnsCryptTCPListen, tcpListen)
		log.Info("Listening for DNSCrypt messages on tcp://%s", tcpListen.Addr())
	}

	return nil
}

// dnsCryptHandler - dnscrypt.Handler implementation
type dnsCryptHandler struct {
	proxy *Proxy

	requestGoroutinesSema semaphore
}

// compile-time type check
var _ dnscrypt.Handler = &dnsCryptHandler{}

// ServeDNS - processes the DNS query
func (h *dnsCryptHandler) ServeDNS(rw dnscrypt.ResponseWriter, req *dns.Msg) error {
	d := h.proxy.newDNSContext(ProtoDNSCrypt, req)
	d.Addr = rw.RemoteAddr()
	d.DNSCryptResponseWriter = rw

	h.requestGoroutinesSema.acquire()
	defer h.requestGoroutinesSema.release()

	return h.proxy.handleDNSRequest(d)
}

// Writes a response to the UDP client
func (p *Proxy) respondDNSCrypt(d *DNSContext) error {
	if d.Res == nil {
		// If no response has been written, do nothing and let it drop
		return nil
	}

	return d.DNSCryptResponseWriter.WriteMsg(d.Res)
}
