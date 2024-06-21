package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// listenHTTP creates instances of TLS listeners that will be used to run an
// H1/H2 server.  Returns the address the listener actually listens to (useful
// in the case if port 0 is specified).
func (p *Proxy) listenHTTP(addr *net.TCPAddr) (laddr *net.TCPAddr, err error) {
	tcpListen, err := net.ListenTCP(bootstrap.NetworkTCP, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp listener: %w", err)
	}

	p.logger.Info("listening to https", "addr", tcpListen.Addr())

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

	p.logger.Info("listening to h3", "addr", quicListen.Addr())

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
		p.logger.Info("creating an https server")

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

// newDoHReq returns new DNS request parsed from the given HTTP request.  In
// case of invalid request returns nil and the suitable status code for an HTTP
// error response.  l must not be nil.
func newDoHReq(r *http.Request, l *slog.Logger) (req *dns.Msg, statusCode int) {
	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if len(buf) == 0 || err != nil {
			l.Debug(
				"parsing dns request from http get param",
				"param_name", dnsParam,
				slogutil.KeyError, err,
			)

			return nil, http.StatusBadRequest
		}
	case http.MethodPost:
		contentType := r.Header.Get(httphdr.ContentType)
		if contentType != "application/dns-message" {
			l.Debug("unsupported media type", "content_type", contentType)

			return nil, http.StatusUnsupportedMediaType
		}

		// TODO(d.kolyshev): Limit reader.
		buf, err = io.ReadAll(r.Body)
		if err != nil {
			l.Debug("reading http request body", slogutil.KeyError, err)

			return nil, http.StatusBadRequest
		}

		defer slogutil.CloseAndLog(context.TODO(), l, r.Body, slog.LevelDebug)
	default:
		l.Debug("bad http method", "method", r.Method)

		return nil, http.StatusMethodNotAllowed
	}

	req = &dns.Msg{}
	if err = req.Unpack(buf); err != nil {
		l.Debug("unpacking http msg", slogutil.KeyError, err)

		return nil, http.StatusBadRequest
	}

	return req, http.StatusOK
}

// ServeHTTP is the http.Handler implementation that handles DoH queries.
//
// Here is what it returns:
//
//   - http.StatusBadRequest if there is no DNS request data,
//   - http.StatusUnsupportedMediaType if request content type is not
//     "application/dns-message",
//   - http.StatusMethodNotAllowed if request method is not GET or POST.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.logger.Debug("incoming https request", "url", r.URL)

	raddr, prx, err := remoteAddr(r, p.logger)
	if err != nil {
		p.logger.Debug("getting real ip", slogutil.KeyError, err)
	}

	if !p.checkBasicAuth(w, r, raddr) {
		return
	}

	req, statusCode := newDoHReq(r, p.logger)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)

		return
	}

	if prx.IsValid() {
		p.logger.Debug("request came from proxy server", "addr", prx)

		if !p.TrustedProxies.Contains(prx.Addr()) {
			p.logger.Debug("proxy is not trusted, using original remote addr", "addr", prx)

			// So the address of the proxy itself is used, as the remote address
			// parsed from headers cannot be trusted.
			//
			// TODO(e.burkov): Do not parse headers in this case.
			raddr = prx
		}
	}

	d := p.newDNSContext(ProtoHTTPS, req, raddr)
	d.HTTPRequest = r
	d.HTTPResponseWriter = w

	err = p.handleDNSRequest(d)
	if err != nil {
		p.logger.Debug("handling dns request", "proto", d.Proto, slogutil.KeyError, err)
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

	p.logger.Error("basic auth failed", "user", user, "raddr", raddr)

	h := w.Header()
	h.Set(httphdr.WWWAuthenticate, `Basic realm="DNS", charset="UTF-8"`)
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
func remoteAddr(r *http.Request, l *slog.Logger) (addr, prx netip.AddrPort, err error) {
	host, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}

	realIP, err := realIPFromHdrs(r)
	if err != nil {
		l.Debug("getting ip address from http request", slogutil.KeyError, err)

		return host, netip.AddrPort{}, nil
	}

	l.Debug("using ip address from http request", "addr", realIP)

	// TODO(a.garipov): Add port if we can get it from headers like X-Real-Port,
	// X-Forwarded-Port, etc.
	addr = netip.AddrPortFrom(realIP, 0)

	return addr, host, nil
}
