package proxy

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

func (p *Proxy) createDNSCryptListeners() (err error) {
	if len(p.DNSCryptUDPListenAddr) == 0 && len(p.DNSCryptTCPListenAddr) == 0 {
		// Do nothing if DNSCrypt listen addresses are not specified.
		return nil
	}

	if p.DNSCryptResolverCert == nil || p.DNSCryptProviderName == "" {
		return errors.Error("invalid DNSCrypt configuration: no certificate or provider name")
	}

	log.Info("Initializing DNSCrypt: %s", p.DNSCryptProviderName)
	p.dnsCryptServer = &dnscrypt.Server{
		ProviderName: p.DNSCryptProviderName,
		ResolverCert: p.DNSCryptResolverCert,
		Handler: &dnsCryptHandler{
			proxy: p,

			requestGoroutinesSema: p.requestGoroutinesSema,
		},
	}

	for _, a := range p.DNSCryptUDPListenAddr {
		log.Info("Creating a DNSCrypt UDP listener")
		udpListen, lErr := net.ListenUDP("udp", a)
		if lErr != nil {
			return fmt.Errorf("listening to dnscrypt udp socket: %w", lErr)
		}

		p.dnsCryptUDPListen = append(p.dnsCryptUDPListen, udpListen)
		log.Info("Listening for DNSCrypt messages on udp://%s", udpListen.LocalAddr())
	}

	for _, a := range p.DNSCryptTCPListenAddr {
		log.Info("Creating a DNSCrypt TCP listener")
		tcpListen, lErr := net.ListenTCP("tcp", a)
		if lErr != nil {
			return fmt.Errorf("listening to dnscrypt tcp socket: %w", lErr)
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
	d.Addr = netutil.NetAddrToAddrPort(rw.RemoteAddr())
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
