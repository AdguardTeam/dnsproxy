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

// initDNSCryptServers initializes the DNSCrypt servers.
func (p *Proxy) initDNSCryptServers(ctx context.Context) (err error) {
	if len(p.DNSCryptUDPListenAddr) == 0 && len(p.DNSCryptTCPListenAddr) == 0 {
		// Do nothing if DNSCrypt listen addresses are not specified.
		return nil
	}

	if p.DNSCryptResolverCert == nil || p.DNSCryptProviderName == "" {
		return errors.Error("invalid dnscrypt configuration: no certificate or provider name")
	}

	p.logger.InfoContext(ctx, "initializing dnscrypt", "provider", p.DNSCryptProviderName)

	for _, addr := range p.DNSCryptUDPListenAddr {
		s, sErr := p.newDNSCryptServer(ctx, netutil.NetAddrToAddrPort(addr), dnscrypt.ProtoUDP)
		if sErr != nil {
			return fmt.Errorf("listening to dnscrypt udp on addr %s: %w", addr, sErr)
		}

		p.dnsCryptServers = append(p.dnsCryptServers, s)
	}

	for _, addr := range p.DNSCryptTCPListenAddr {
		s, sErr := p.newDNSCryptServer(ctx, netutil.NetAddrToAddrPort(addr), dnscrypt.ProtoTCP)
		if sErr != nil {
			return fmt.Errorf("listening to dnscrypt tcp on addr %s: %w", addr, sErr)
		}

		p.dnsCryptServers = append(p.dnsCryptServers, s)
	}

	return nil
}

// startDNSCryptServers starts the DNSCrypt servers.
func (p *Proxy) startDNSCryptServers(ctx context.Context) (err error) {
	var started []*dnscrypt.Server

	for i, s := range p.dnsCryptServers {
		err = s.Start(ctx)
		if err != nil {
			closeErr := shutdownDNSCryptServers(ctx, started)

			return fmt.Errorf(
				"starting dnscrypt server at index %d: %w",
				i,
				errors.WithDeferred(err, closeErr),
			)
		}

		started = append(started, s)
	}

	return nil
}

// shutdownDNSCryptServers shuts down the DNSCrypt servers.  If it returns an
// error, some servers may be still running.
func shutdownDNSCryptServers(ctx context.Context, srvs []*dnscrypt.Server) (err error) {
	var errs []error

	for i, s := range srvs {
		err = s.Shutdown(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("shutting down dnscrypt server at index %d: %w", i, err))
		}
	}

	return errors.Join(errs...)
}

// newDNSCryptServer returns a new DNSCrypt server for the given address and
// protocol.
func (p *Proxy) newDNSCryptServer(
	ctx context.Context,
	addr netip.AddrPort,
	proto dnscrypt.Proto,
) (s *dnscrypt.Server, err error) {
	p.logger.InfoContext(ctx, "creating dnscrypt server", "addr", addr, "proto", proto)

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

// respondDNSCrypt writes a response to the client using the DNSCrypt response
// writer.  d must not be nil.
func (p *Proxy) respondDNSCrypt(ctx context.Context, d *DNSContext) error {
	if d.Res == nil {
		// If no response has been written, do nothing and let it drop.
		return nil
	}

	return d.DNSCryptResponseWriter.WriteMsg(ctx, d.Res)
}
