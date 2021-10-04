package proxy

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

func (p *Proxy) createHTTPSListeners() error {
	for _, a := range p.HTTPSListenAddr {
		log.Info("Creating an HTTPS server")
		tcpListen, err := net.ListenTCP("tcp", a)
		if err != nil {
			return errorx.Decorate(err, "could not start HTTPS listener")
		}
		p.httpsListen = append(p.httpsListen, tcpListen)
		log.Info("Listening to https://%s", tcpListen.Addr())

		tlsConfig := p.TLSConfig.Clone()
		tlsConfig.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

		srv := &http.Server{
			TLSConfig:         tlsConfig,
			Handler:           p,
			ReadHeaderTimeout: defaultTimeout,
			WriteTimeout:      defaultTimeout,
		}

		p.httpsServer = append(p.httpsServer, srv)
	}

	return nil
}

// serveHttps starts the HTTPS server
func (p *Proxy) listenHTTPS(srv *http.Server, l net.Listener) {
	log.Info("Listening to DNS-over-HTTPS on %s", l.Addr())
	err := srv.ServeTLS(l, "", "")

	if err != http.ErrServerClosed {
		log.Info("HTTPS server was closed unexpectedly: %s", err)
	} else {
		log.Info("HTTPS server was closed")
	}
}

// ServeHTTP is the http.RequestHandler implementation that handles DOH queries
// Here is what it returns:
// http.StatusBadRequest - if there is no DNS request data
// http.StatusUnsupportedMediaType - if request content type is not application/dns-message
// http.StatusMethodNotAllowed - if request method is not GET or POST
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

		buf, err = ioutil.ReadAll(r.Body)
		if err != nil {
			log.Tracef("Cannot read the request body: %s", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
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
		ip := ipFromAddr(prx)
		log.Debug("request came from proxy server %s", prx)
		if !p.proxyVerifier.detect(ip) {
			log.Debug("proxy %s is not trusted, using original remote addr", ip)
			d.Addr = prx
		}
	}

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
	}
}

// ipFromAddr returns an IP address from addr.  If addr is neither
// a *net.TCPAddr nor a *net.UDPAddr, it returns nil.
//
// TODO(a.garipov): Create package netutil in the golibs module and move it
// there.
func ipFromAddr(addr net.Addr) (ip net.IP) {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return addr.IP
	case *net.UDPAddr:
		return addr.IP
	}

	return nil
}

// Writes a response to the DOH client
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
		return errorx.Decorate(err, "couldn't convert message into wire format: %s", resp.String())
	}

	w.Header().Set("Server", "AdGuard DNS")
	w.Header().Set("Content-Type", "application/dns-message")
	_, err = w.Write(bytes)
	return err
}

// realIPFromHdrs extracts the actual client's IP address from the first
// suitable r's header.  It returns nil if r doesn't contain any information
// about real client's IP address.  Current headers priority is:
//
//   1. CF-Connecting-IP
//   2. True-Client-IP
//   3. X-Real-IP
//   4. X-Forwarded-For
//
func realIPFromHdrs(r *http.Request) (realIP net.IP) {
	for _, h := range [...]string{
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

	if realIP := realIPFromHdrs(r); realIP != nil {
		log.Tracef("Using IP address from HTTP request: %s", realIP)

		// TODO(a.garipov): Use net.UDPAddr here and below when
		// necessary when we start supporting HTTP/3.
		//
		// TODO(a.garipov): Add port if we can get it from headers like
		// X-Real-Port, X-Forwarded-Port, etc.
		addr = &net.TCPAddr{IP: realIP, Port: 0}
		prx = &net.TCPAddr{IP: host, Port: port}

		return addr, prx, nil
	}

	return &net.TCPAddr{IP: host, Port: port}, nil, nil
}
