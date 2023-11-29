package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// listenHTTP creates instances of TLS listeners that will be used to run an
// H1/H2 server.  Returns the address the listener actually listens to (useful
// in the case if port 0 is specified).
func (p *Proxy) listenHTTP(addr *net.TCPAddr) (laddr *net.TCPAddr, err error) {
	tcpListen, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp listener: %w", err)
	}
	log.Info("Listening to https://%s", tcpListen.Addr())

	tlsConfig := p.TLSConfig.Clone()
	tlsConfig.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

	tlsListen := tls.NewListener(tcpListen, tlsConfig)
	p.httpsListen = append(p.httpsListen, tlsListen)

	return tcpListen.Addr().(*net.TCPAddr), nil
}

// listenH3 creates instances of QUIC listeners that will be used for running
// an HTTP/3 server.
func (p *Proxy) listenH3(addr *net.UDPAddr) (err error) {
	tlsConfig := p.TLSConfig.Clone()
	tlsConfig.NextProtos = []string{"h3"}
	quicListen, err := quic.ListenAddrEarly(addr.String(), tlsConfig, newServerQUICConfig())
	if err != nil {
		return fmt.Errorf("quic listener: %w", err)
	}
	log.Info("Listening to h3://%s", quicListen.Addr())

	p.h3Listen = append(p.h3Listen, quicListen)

	return nil
}

// createHTTPSListeners creates TCP/UDP listeners and HTTP/H3 servers.
func (p *Proxy) createHTTPSListeners() (err error) {
	p.httpsServer = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: defaultTimeout,
		WriteTimeout:      defaultTimeout,
	}

	if p.HTTP3 {
		p.h3Server = &http3.Server{
			Handler: p,
		}
	}

	for _, addr := range p.HTTPSListenAddr {
		log.Info("Creating an HTTPS server")

		tcpAddr, lErr := p.listenHTTP(addr)
		if lErr != nil {
			return fmt.Errorf("failed to start HTTPS server on %s: %w", addr, lErr)
		}

		if p.HTTP3 {
			// HTTP/3 server listens to the same pair IP:port as the one HTTP/2
			// server listens to.
			udpAddr := &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port}
			err = p.listenH3(udpAddr)
			if err != nil {
				return fmt.Errorf("failed to start HTTP/3 server on %s: %w", udpAddr, err)
			}
		}
	}

	return nil
}

// ServeHTTP is the http.Handler implementation that handles DoH queries.
// Here is what it returns:
//
//   - http.StatusBadRequest if there is no DNS request data;
//   - http.StatusUnsupportedMediaType if request content type is not
//     "application/dns-message";
//   - http.StatusMethodNotAllowed if request method is not GET or POST.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Debug("dnsproxy: incoming https request on %s", r.URL)

	raddr, prx, err := remoteAddr(r)
	if err != nil {
		log.Debug("dnsproxy: warning: getting real ip: %s", err)
	}

	if !p.checkBasicAuth(w, r, raddr) {
		return
	}

	var buf []byte

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if len(buf) == 0 || err != nil {
			log.Debug("dnsproxy: parsing dns request from get param %q: %v", dnsParam, err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

			return
		}
	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			log.Debug("dnsproxy: unsupported media type %q", contentType)
			http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)

			return
		}

		buf, err = io.ReadAll(r.Body)
		if err != nil {
			log.Debug("dnsproxy: reading http request body: %s", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

			return
		}

		defer log.OnCloserError(r.Body, log.DEBUG)
	default:
		log.Debug("dnsproxy: bad http method %q", r.Method)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}

	req := &dns.Msg{}
	if err = req.Unpack(buf); err != nil {
		log.Debug("dnsproxy: unpacking http msg: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	d := p.newDNSContext(ProtoHTTPS, req)
	d.Addr = raddr
	d.HTTPRequest = r
	d.HTTPResponseWriter = w

	if prx.IsValid() {
		log.Debug("dnsproxy: request came from proxy server %s", prx)

		// TODO(s.chzhen):  Consider using []netip.Prefix.
		if !p.proxyVerifier.Contains(prx.Addr().AsSlice()) {
			log.Debug("dnsproxy: proxy %s is not trusted, using original remote addr", prx)
			d.Addr = prx
		}
	}

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Debug("dnsproxy: handling dns (%s) request: %s", d.Proto, err)
	}
}

// checkBasicAuth checks the basic authorization data, if necessary, and if the
// data isn't valid, it writes an error.  shouldHandle is false if the request
// has been denied.
func (p *Proxy) checkBasicAuth(
	w http.ResponseWriter,
	r *http.Request,
	raddr netip.AddrPort,
) (shouldHandle bool) {
	ui := p.Config.Userinfo
	if ui == nil {
		return true
	}

	user, pass, _ := r.BasicAuth()
	if matchesUserinfo(ui, user, pass) {
		return true
	}

	log.Error("dnsproxy: basic auth failed for user %q from raddr %s", user, raddr)

	h := w.Header()
	// TODO(a.garipov): Add to httphdr.
	h.Set("Www-Authenticate", `Basic realm="DNS", charset="UTF-8"`)
	http.Error(w, "Authorization required", http.StatusUnauthorized)

	return false
}

// matchesUserinfo returns false if user and pass don't match userinfo.
// userinfo must not be nil.
func matchesUserinfo(userinfo *url.Userinfo, user, pass string) (ok bool) {
	requiredPassword, _ := userinfo.Password()

	return user == userinfo.Username() && pass == requiredPassword
}

// Writes a response to the DoH client.
func (p *Proxy) respondHTTPS(d *DNSContext) (err error) {
	resp := d.Res
	w := d.HTTPResponseWriter

	if resp == nil {
		// Indicate the response's absence via a http.StatusInternalServerError.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return nil
	}

	bytes, err := resp.Pack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return fmt.Errorf("packing message: %w", err)
	}

	if srvName := p.Config.HTTPSServerName; srvName != "" {
		w.Header().Set(httphdr.Server, srvName)
	}

	w.Header().Set(httphdr.ContentType, "application/dns-message")
	_, err = w.Write(bytes)

	return err
}

// realIPFromHdrs extracts the actual client's IP address from the first
// suitable r's header.  It returns an error if r doesn't contain any
// information about real client's IP address.  Current headers priority is:
//
//  1. [httphdr.CFConnectingIP]
//  2. [httphdr.TrueClientIP]
//  3. [httphdr.XRealIP]
//  4. [httphdr.XForwardedFor]
func realIPFromHdrs(r *http.Request) (realIP netip.Addr, err error) {
	for _, h := range []string{
		httphdr.CFConnectingIP,
		httphdr.TrueClientIP,
		httphdr.XRealIP,
	} {
		realIP, err = netip.ParseAddr(strings.TrimSpace(r.Header.Get(h)))
		if err == nil {
			return realIP, nil
		}
	}

	xff := r.Header.Get(httphdr.XForwardedFor)
	firstComma := strings.IndexByte(xff, ',')
	if firstComma > 0 {
		xff = xff[:firstComma]
	}

	return netip.ParseAddr(strings.TrimSpace(xff))
}

// remoteAddr returns the real client's address and the IP address of the latest
// proxy server if any.
func remoteAddr(r *http.Request) (addr, prx netip.AddrPort, err error) {
	host, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}

	realIP, err := realIPFromHdrs(r)
	if err != nil {
		log.Debug("dnsproxy: getting ip address from http request: %s", err)

		return host, netip.AddrPort{}, nil
	}

	log.Debug("dnsproxy: using ip address from http request: %s", realIP)

	// TODO(a.garipov): Add port if we can get it from headers like X-Real-Port,
	// X-Forwarded-Port, etc.
	addr = netip.AddrPortFrom(realIP, 0)

	return addr, host, nil
}
