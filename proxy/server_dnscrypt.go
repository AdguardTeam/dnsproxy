package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

func (p *Proxy) createDNSCryptListeners() (err error) {
	if len(p.DNSCryptUDPListenAddr) == 0 && len(p.DNSCryptTCPListenAddr) == 0 {
		// Do nothing if DNSCrypt listen addresses are not specified.
		return nil
	}

	if p.DNSCryptResolverCert == nil || p.DNSCryptProviderName == "" {
		return errors.Error("invalid dnscrypt configuration: no certificate or provider name")
	}

	p.logger.Info("initializing dnscrypt", "provider", p.DNSCryptProviderName)
	p.dnsCryptServer = &dnscrypt.Server{
		ProviderName: p.DNSCryptProviderName,
		ResolverCert: p.DNSCryptResolverCert,
		Handler: &dnsCryptHandler{
			proxy: p,

			reqSema: p.requestsSema,
		},
	}

	for _, a := range p.DNSCryptUDPListenAddr {
		p.logger.Info("creating dnscrypt udp listener")
		udpListen, lErr := net.ListenUDP(bootstrap.NetworkUDP, a)
		if lErr != nil {
			return fmt.Errorf("listening to dnscrypt udp socket: %w", lErr)
		}

		p.dnsCryptUDPListen = append(p.dnsCryptUDPListen, udpListen)
		p.logger.Info("listening for dnscrypt messages on udp", "addr", udpListen.LocalAddr())
	}

	for _, a := range p.DNSCryptTCPListenAddr {
		p.logger.Info("creating a dnscrypt tcp listener")
		tcpListen, lErr := net.ListenTCP(bootstrap.NetworkTCP, a)
		if lErr != nil {
			return fmt.Errorf("listening to dnscrypt tcp socket: %w", lErr)
		}

		p.dnsCryptTCPListen = append(p.dnsCryptTCPListen, tcpListen)
		p.logger.Info("listening for dnscrypt messages on tcp", "addr", tcpListen.Addr())
	}

	return nil
}

// dnsCryptHandler - dnscrypt.Handler implementation
type dnsCryptHandler struct {
	proxy *Proxy

	reqSema syncutil.Semaphore
}

// compile-time type check
var _ dnscrypt.Handler = &dnsCryptHandler{}

// ServeDNS - processes the DNS query
func (h *dnsCryptHandler) ServeDNS(rw dnscrypt.ResponseWriter, req *dns.Msg) (err error) {
	d := h.proxy.newDNSContext(ProtoDNSCrypt, req, netutil.NetAddrToAddrPort(rw.RemoteAddr()))
	d.DNSCryptResponseWriter = rw

	// TODO(d.kolyshev): Pass and use context from above.
	err = h.reqSema.Acquire(context.Background())
	if err != nil {
		return fmt.Errorf("dnsproxy: dnscrypt: acquiring semaphore: %w", err)
	}
	defer h.reqSema.Release()

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
