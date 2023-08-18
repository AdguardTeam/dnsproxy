package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
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
	log.Tracef("Incoming HTTPS request on %s", r.URL)

	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if len(buf) == 0 || err != nil {
			log.Tracef("Cannot parse DNS request from %s", dnsParam)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			log.Tracef("Unsupported media type: %s", contentType)
			http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
			return
		}

		buf, err = io.ReadAll(r.Body)
		if err != nil {
			log.Tracef("Cannot read the request body: %s", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		defer log.OnCloserError(r.Body, log.DEBUG)
	default:
		log.Tracef("Wrong HTTP method: %s", r.Method)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	req := &dns.Msg{}
	if err = req.Unpack(buf); err != nil {
		log.Tracef("msg.Unpack: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	addr, prx, err := remoteAddr(r)
	if err != nil {
		log.Debug("warning: getting real ip: %s", err)
	}

	d := p.newDNSContext(ProtoHTTPS, req)
	d.Addr = addr
	d.HTTPRequest = r
	d.HTTPResponseWriter = w

	if prx != nil {
		ip, _ := netutil.IPAndPortFromAddr(prx)
		log.Debug("request came from proxy server %s", prx)
		if !p.proxyVerifier.Contains(ip) {
			log.Debug("proxy %s is not trusted, using original remote addr", ip)
			d.Addr = prx
		}
	}

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
	}
}

// Writes a response to the DoH client.
func (p *Proxy) respondHTTPS(d *DNSContext) error {
	resp := d.Res
	w := d.HTTPResponseWriter

	if resp == nil {
		// If no response has been written, indicate it via a 500 error
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
// suitable r's header.  It returns nil if r doesn't contain any information
// about real client's IP address.  Current headers priority is:
//
//  1. CF-Connecting-IP
//  2. True-Client-IP
//  3. X-Real-IP
//  4. X-Forwarded-For
func realIPFromHdrs(r *http.Request) (realIP net.IP) {
	for _, h := range []string{
		// Headers set by CloudFlare proxy servers.
		"CF-Connecting-IP",
		"True-Client-IP",
		// Other proxying headers.
		"X-Real-IP",
	} {
		realIP = net.ParseIP(strings.TrimSpace(r.Header.Get(h)))
		if realIP != nil {
			return realIP
		}
	}

	xff := r.Header.Get("X-Forwarded-For")
	firstComma := strings.IndexByte(xff, ',')
	if firstComma == -1 {
		return net.ParseIP(strings.TrimSpace(xff))
	}

	return net.ParseIP(strings.TrimSpace(xff[:firstComma]))
}

// remoteAddr returns the real client's address and the IP address of the latest
// proxy server if any.
func remoteAddr(r *http.Request) (addr, prx net.Addr, err error) {
	var hostStr, portStr string
	if hostStr, portStr, err = net.SplitHostPort(r.RemoteAddr); err != nil {
		return nil, nil, err
	}

	var port int
	if port, err = strconv.Atoi(portStr); err != nil {
		return nil, nil, err
	}

	host := net.ParseIP(hostStr)
	if host == nil {
		return nil, nil, fmt.Errorf("invalid ip: %s", hostStr)
	}

	h3 := r.Context().Value(http3.ServerContextKey) != nil

	if realIP := realIPFromHdrs(r); realIP != nil {
		log.Tracef("Using IP address from HTTP request: %s", realIP)

		// TODO(a.garipov): Add port if we can get it from headers like
		// X-Real-Port, X-Forwarded-Port, etc.
		if h3 {
			addr = &net.UDPAddr{IP: realIP, Port: 0}
			prx = &net.UDPAddr{IP: host, Port: port}
		} else {
			addr = &net.TCPAddr{IP: realIP, Port: 0}
			prx = &net.TCPAddr{IP: host, Port: port}
		}

		return addr, prx, nil
	}

	if h3 {
		return &net.UDPAddr{IP: host, Port: port}, nil, nil
	}

	return &net.TCPAddr{IP: host, Port: port}, nil, nil
}
