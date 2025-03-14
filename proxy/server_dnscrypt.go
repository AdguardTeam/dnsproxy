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

func (p *Proxy) initDNSCryptListeners(ctx context.Context) (err error) {
	if len(p.DNSCryptUDPListenAddr) == 0 && len(p.DNSCryptTCPListenAddr) == 0 {
		// Do nothing if DNSCrypt listen addresses are not specified.
		return nil
	}

	if p.DNSCryptResolverCert == nil || p.DNSCryptProviderName == "" {
		return errors.Error("invalid dnscrypt configuration: no certificate or provider name")
	}

	p.logger.InfoContext(ctx, "initializing dnscrypt", "provider", p.DNSCryptProviderName)
	p.dnsCryptServer = &dnscrypt.Server{
		ProviderName: p.DNSCryptProviderName,
		ResolverCert: p.DNSCryptResolverCert,
		Handler: &dnsCryptHandler{
			proxy:   p,
			reqSema: p.requestsSema,
		},
	}

	for _, addr := range p.DNSCryptUDPListenAddr {
		udp, lErr := p.listenDNSCryptUDP(ctx, addr)
		if lErr != nil {
			return fmt.Errorf("listening to dnscrypt udp on addr %s: %w", addr, lErr)
		}

		p.dnsCryptUDPListen = append(p.dnsCryptUDPListen, udp)
	}

	for _, addr := range p.DNSCryptTCPListenAddr {
		tcp, lErr := p.listenDNSCryptTCP(ctx, addr)
		if lErr != nil {
			return fmt.Errorf("listening to dnscrypt tcp on addr %s: %w", addr, lErr)
		}

		p.dnsCryptTCPListen = append(p.dnsCryptTCPListen, tcp)
	}

	return nil
}

// listenDNSCryptUDP returns a new UDP connection for DNSCrypt listening on
// addr.
func (p *Proxy) listenDNSCryptUDP(
	ctx context.Context,
	addr *net.UDPAddr,
) (conn *net.UDPConn, err error) {
	addrStr := addr.String()
	p.logger.InfoContext(ctx, "creating dnscrypt udp server socket", "addr", addrStr)

	err = p.bindWithRetry(ctx, func() (listenErr error) {
		conn, listenErr = net.ListenUDP(bootstrap.NetworkUDP, addr)

		return listenErr
	})
	if err != nil {
		return nil, fmt.Errorf("listening to udp socket: %w", err)
	}

	p.logger.InfoContext(ctx, "listening for dnscrypt messages on udp", "addr", conn.LocalAddr())

	return conn, nil
}

// listenDNSCryptTCP returns a new TCP listener for DNSCrypt listening on addr.
func (p *Proxy) listenDNSCryptTCP(
	ctx context.Context,
	addr *net.TCPAddr,
) (conn *net.TCPListener, err error) {
	addrStr := addr.String()
	p.logger.InfoContext(ctx, "creating dnscrypt tcp server socket", "addr", addrStr)

	err = p.bindWithRetry(ctx, func() (listenErr error) {
		conn, listenErr = net.ListenTCP(bootstrap.NetworkTCP, addr)

		return listenErr
	})
	if err != nil {
		return nil, fmt.Errorf("listening to tcp socket: %w", err)
	}

	p.logger.InfoContext(ctx, "listening for dnscrypt messages on tcp", "addr", conn.Addr())

	return conn, nil
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
