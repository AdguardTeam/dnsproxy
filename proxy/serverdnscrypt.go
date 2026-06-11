package proxy

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// initDNSCryptListeners initializes the DNSCrypt listeners.
func (p *Proxy) initDNSCryptListeners(ctx context.Context) (err error) {
	if len(p.DNSCryptUDPListenAddr) == 0 && len(p.DNSCryptTCPListenAddr) == 0 {
		// Do nothing if DNSCrypt listen addresses are not specified.
		return nil
	}

	if p.DNSCryptResolverCert == nil || p.DNSCryptProviderName == "" {
		return errors.Error("invalid dnscrypt configuration: no certificate or provider name")
	}

	p.logger.InfoContext(ctx, "initializing dnscrypt", "provider", p.DNSCryptProviderName)

	for _, addr := range p.DNSCryptUDPListenAddr {
		p.logger.InfoContext(ctx, "creating dnscrypt udp server", "addr", addr)

		s, sErr := p.newDNSCryptServer(netutil.NetAddrToAddrPort(addr), dnscrypt.ProtoUDP)
		if sErr != nil {
			return fmt.Errorf("listening to dnscrypt udp on addr %s: %w", addr, sErr)
		}

		p.dnsCryptServers = append(p.dnsCryptServers, s)
	}

	for _, addr := range p.DNSCryptTCPListenAddr {
		p.logger.InfoContext(ctx, "creating dnscrypt tcp server", "addr", addr)

		s, sErr := p.newDNSCryptServer(netutil.NetAddrToAddrPort(addr), dnscrypt.ProtoTCP)
		if sErr != nil {
			return fmt.Errorf("listening to dnscrypt tcp on addr %s: %w", addr, sErr)
		}

		p.dnsCryptServers = append(p.dnsCryptServers, s)
	}

	return nil
}

// newDNSCryptServer returns a new DNSCrypt server for the given address and
// protocol.
func (p *Proxy) newDNSCryptServer(
	addr netip.AddrPort,
	proto dnscrypt.Proto,
) (s *dnscrypt.Server, err error) {
	return dnscrypt.NewServer(&dnscrypt.ServerConfig{
		Handler: &dnsCryptHandler{
			proxy:   p,
			reqSema: p.requestsSema,
		},
		ResolverCert: p.DNSCryptResolverCert,
		Logger:       p.logger,
		ProviderName: p.DNSCryptProviderName,
		Addr:         addr,
		Proto:        proto,
	})
}

// dnsCryptHandler is the [dnscrypt.Handler] implementation that handles
// requests in the Proxy.
type dnsCryptHandler struct {
	proxy   *Proxy
	reqSema syncutil.Semaphore
}

// type check
var _ dnscrypt.Handler = &dnsCryptHandler{}

// ServeDNS implements the [dnscrypt.Handler] interface for *dnsCryptHandler.
func (h *dnsCryptHandler) ServeDNS(
	ctx context.Context,
	rw dnscrypt.ResponseWriter,
	req *dns.Msg,
) (err error) {
	addr := netutil.NetAddrToAddrPort(rw.RemoteAddr())
	d := h.proxy.newDNSContext(ProtoDNSCrypt, req, addr)
	d.DNSCryptResponseWriter = rw

	ctx, cancel := h.proxy.reqCtx.New(ctx)
	defer cancel()

	err = h.reqSema.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("dnsproxy: dnscrypt: acquiring semaphore: %w", err)
	}
	defer h.reqSema.Release()

	return h.proxy.handleDNSRequest(ctx, d)
}

// Writes a response to the UDP client.  d must not be nil.
func (p *Proxy) respondDNSCrypt(ctx context.Context, d *DNSContext) error {
	if d.Res == nil {
		// If no response has been written, do nothing and let it drop.
		return nil
	}

	return d.DNSCryptResponseWriter.WriteMsg(ctx, d.Res)
}
