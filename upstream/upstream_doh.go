package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Values to configure HTTP and HTTP/2 transport.
const (
	// transportDefaultReadIdleTimeout is the default timeout for pinging
	// idle connections in HTTP/2 transport.
	transportDefaultReadIdleTimeout = 30 * time.Second

	// transportDefaultIdleConnTimeout is the default timeout for idle
	// connections in HTTP transport.
	transportDefaultIdleConnTimeout = 5 * time.Minute

	// dohMaxConnsPerHost controls the maximum number of connections for
	// each host.
	dohMaxConnsPerHost = 1

	// dohMaxIdleConns controls the maximum number of connections being idle
	// at the same time.
	dohMaxIdleConns = 1
)

// dnsOverHTTPS is a struct that implements the Upstream interface for the
// DNS-over-HTTPS protocol.
type dnsOverHTTPS struct {
	boot *bootstrapper

	// The Client's Transport typically has internal state (cached TCP
	// connections), so Clients should be reused instead of created as
	// needed. Clients are safe for concurrent use by multiple goroutines.
	client      *http.Client
	clientGuard sync.Mutex

	// quicConfig is the QUIC configuration that is used if HTTP/3 is enabled
	// for this upstream.
	quicConfig *quic.Config
}

// type check
var _ Upstream = &dnsOverHTTPS{}

// newDoH returns the DNS-over-HTTPS Upstream.
func newDoH(uu *url.URL, opts *Options) (u Upstream, err error) {
	addPort(uu, defaultPortDoH)

	var b *bootstrapper
	b, err = urlToBoot(uu, opts)
	if err != nil {
		return nil, fmt.Errorf("creating https bootstrapper: %w", err)
	}

	return &dnsOverHTTPS{
		boot: b,

		quicConfig: &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
		},
	}, nil
}

// Address implements the Upstream interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Address() string { return p.boot.URL.String() }

// Exchange implements the Upstream interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	// Quote from https://www.rfc-editor.org/rfc/rfc8484.html:
	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	id := m.Id
	m.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies.
		m.Id = id
		if resp != nil {
			resp.Id = id
		}
	}()

	// Check if there was already an active client before sending the request.
	// We'll only attempt to re-connect if there was one.
	hasClient := p.hasClient()

	// Make the first attempt to send the DNS query.
	resp, err = p.exchangeHTTPS(m)

	// Make up to 2 attempts to re-create the HTTP client and send the request
	// again.  There are several cases (mostly, with QUIC) where this workaround
	// is necessary to make HTTP client usable.  We need to make 2 attempts in
	// the case when the connection was closed (due to inactivity for example)
	// AND the server refuses to open a 0-RTT connection.
	for i := 0; hasClient && p.shouldRetry(err) && i < 2; i++ {
		log.Debug("re-creating the HTTP client and retrying due to %v", err)

		p.clientGuard.Lock()
		p.client = nil
		// Re-create the token store to make sure we're not trying to use invalid
		// tokens for 0-RTT.
		p.quicConfig.TokenStore = newQUICTokenStore()
		p.clientGuard.Unlock()

		resp, err = p.exchangeHTTPS(m)
	}

	if err != nil {
		// If the request failed anyway, make sure we don't use this client.
		p.clientGuard.Lock()
		p.client = nil
		p.clientGuard.Unlock()
	}

	return resp, err
}

// exchangeHTTPS creates an HTTP client and sends the DNS query using it.
func (p *dnsOverHTTPS) exchangeHTTPS(m *dns.Msg) (resp *dns.Msg, err error) {
	client, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("initializing http client: %w", err)
	}

	logBegin(p.Address(), m)
	resp, err = p.exchangeHTTPSClient(m, client)
	logFinish(p.Address(), err)

	return resp, err
}

// exchangeHTTPSClient sends the DNS query to a DoH resolver using the specified
// http.Client instance.
func (p *dnsOverHTTPS) exchangeHTTPSClient(m *dns.Msg, client *http.Client) (*dns.Msg, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	method := http.MethodGet
	if _, ok := p.client.Transport.(*http3.RoundTripper); ok {
		// If we're using HTTP/3, use http3.MethodGet0RTT to force using 0-RTT.
		method = http3.MethodGet0RTT
	}

	u := url.URL{
		Scheme:   p.boot.URL.Scheme,
		Host:     p.boot.URL.Host,
		Path:     p.boot.URL.Path,
		RawQuery: fmt.Sprintf("dns=%s", base64.RawURLEncoding.EncodeToString(buf)),
	}

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", p.boot.URL, err)
	}

	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "")

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", p.boot.URL, err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p.boot.URL, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got status code %d from %s", resp.StatusCode, p.boot.URL)
	}

	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf("unpacking response from %s: body is %s: %w", p.boot.URL, string(body), err)
	}

	if response.Id != m.Id {
		err = dns.ErrId
	}

	return &response, err
}

// hasClient returns true if this connection already has an active HTTP client.
func (p *dnsOverHTTPS) hasClient() (ok bool) {
	p.clientGuard.Lock()
	defer p.clientGuard.Unlock()

	return p.client != nil
}

// shouldRetry checks what error we have received and returns true if we should
// re-create the HTTP client and retry the request.
func (p *dnsOverHTTPS) shouldRetry(err error) (ok bool) {
	if err == nil {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// If this is a timeout error, trying to forcibly re-create the HTTP
		// client instance.  This is an attempt to fix an issue with DoH client
		// stalling after a network change.
		//
		// See https://github.com/AdguardTeam/AdGuardHome/issues/3217.
		return true
	}

	if isQUICRetryError(err) {
		return true
	}

	return false
}

// getClient gets or lazily initializes an HTTP client (and transport) that will
// be used for this DoH resolver.
func (p *dnsOverHTTPS) getClient() (c *http.Client, err error) {
	startTime := time.Now()

	p.clientGuard.Lock()
	defer p.clientGuard.Unlock()
	if p.client != nil {
		return p.client, nil
	}

	// Timeout can be exceeded while waiting for the lock. This happens quite
	// often on mobile devices.
	elapsed := time.Since(startTime)
	if p.boot.options.Timeout > 0 && elapsed > p.boot.options.Timeout {
		return nil, fmt.Errorf("timeout exceeded: %s", elapsed)
	}

	p.client, err = p.createClient()

	return p.client, err
}

// createClient creates a new *http.Client instance.  The HTTP protocol version
// will depend on whether HTTP3 is allowed and provided by this upstream.  Note,
// that we'll attempt to establish a QUIC connection when creating the client in
// order to check whether HTTP3 is supported.
func (p *dnsOverHTTPS) createClient() (*http.Client, error) {
	transport, err := p.createTransport()
	if err != nil {
		return nil, fmt.Errorf("initializing http transport: %w", err)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   p.boot.options.Timeout,
		Jar:       nil,
	}

	p.client = client

	return p.client, nil
}

// createTransport initializes an HTTP transport that will be used specifically
// for this DoH resolver.  This HTTP transport ensures that the HTTP requests
// will be sent exactly to the IP address got from the bootstrap resolver. Note,
// that this function will first attempt to establish a QUIC connection (if
// HTTP3 is enabled in the upstream options).  If this attempt is successful,
// it returns an HTTP3 transport, otherwise it returns the H1/H2 transport.
func (p *dnsOverHTTPS) createTransport() (t http.RoundTripper, err error) {
	tlsConfig, dialContext, err := p.boot.get()
	if err != nil {
		return nil, fmt.Errorf("bootstrapping %s: %w", p.boot.URL, err)
	}

	// First, we attempt to create an HTTP3 transport.  If the probe QUIC
	// connection is established successfully, we'll be using HTTP3 for this
	// upstream.
	transportH3, err := p.createTransportH3(tlsConfig, dialContext)
	if err == nil {
		log.Debug("using HTTP/3 for this upstream: QUIC was faster")
		return transportH3, nil
	}

	log.Debug("using HTTP/2 for this upstream: %v", err)

	if !p.supportsHTTP() {
		return nil, errors.Error("HTTP1/1 and HTTP2 are not supported by this upstream")
	}

	transport := &http.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		DialContext:        dialContext,
		IdleConnTimeout:    transportDefaultIdleConnTimeout,
		MaxConnsPerHost:    dohMaxConnsPerHost,
		MaxIdleConns:       dohMaxIdleConns,
		// Since we have a custom DialContext, we need to use this field to
		// make golang http.Client attempt to use HTTP/2. Otherwise, it would
		// only be used when negotiated on the TLS level.
		ForceAttemptHTTP2: true,
	}

	// Explicitly configure transport to use HTTP/2.
	//
	// See https://github.com/AdguardTeam/dnsproxy/issues/11.
	var transportH2 *http2.Transport
	transportH2, err = http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	// Enable HTTP/2 pings on idle connections.
	transportH2.ReadIdleTimeout = transportDefaultReadIdleTimeout

	return transport, nil
}

// createTransportH3 tries to create an HTTP/3 transport for this upstream.
// We should be able to fall back to H1/H2 in case if HTTP/3 is unavailable or
// if it is too slow.  In order to do that, this method will run two probes
// in parallel (one for TLS, the other one for QUIC) and if QUIC is faster it
// will create the *http3.RoundTripper instance.
func (p *dnsOverHTTPS) createTransportH3(
	tlsConfig *tls.Config,
	dialContext dialHandler,
) (roundTripper http.RoundTripper, err error) {
	if !p.supportsH3() {
		return nil, errors.Error("HTTP3 support is not enabled")
	}

	addr, err := p.probeH3(tlsConfig, dialContext)
	if err != nil {
		return nil, err
	}

	rt := &http3.RoundTripper{
		Dial: func(
			ctx context.Context,

			// Ignore the address and always connect to the one that we got
			// from the bootstrapper.
			_ string,
			tlsCfg *tls.Config,
			cfg *quic.Config,
		) (c quic.EarlyConnection, err error) {
			c, err = quic.DialAddrEarlyContext(ctx, addr, tlsCfg, cfg)
			return c, err
		},
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		QuicConfig:         p.quicConfig,
	}

	return rt, nil
}

// probeH3 runs a test to check whether QUIC is faster than TLS for this
// upstream.  If the test is successful it will return the address that we
// should use to establish the QUIC connections.
func (p *dnsOverHTTPS) probeH3(
	tlsConfig *tls.Config,
	dialContext dialHandler,
) (addr string, err error) {
	// We're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there are v4/v6 addresses).
	rawConn, err := dialContext(context.Background(), "udp", "")
	if err != nil {
		return "", fmt.Errorf("failed to dial: %w", err)
	}
	// It's never actually used.
	_ = rawConn.Close()

	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		return "", fmt.Errorf("not a UDP connection to %s", p.Address())
	}

	addr = udpConn.RemoteAddr().String()

	// Avoid spending time on probing if this upstream only supports HTTP/3.
	if p.supportsH3() && !p.supportsHTTP() {
		return addr, nil
	}

	// Use a new *tls.Config with empty session cache for probe connections.
	// Surprisingly, this is really important since otherwise it invalidates
	// the existing cache.
	// TODO(ameshkov): figure out why the sessions cache invalidates here.
	probeTLSCfg := tlsConfig.Clone()
	probeTLSCfg.ClientSessionCache = nil

	// Do not expose probe connections to the callbacks that are passed to
	// the bootstrap options to avoid side-effects.
	// TODO(ameshkov): consider exposing, somehow mark that this is a probe.
	probeTLSCfg.VerifyPeerCertificate = nil
	probeTLSCfg.VerifyConnection = nil

	// Run probeQUIC and probeTLS in parallel and see which one is faster.
	chQuic := make(chan error, 1)
	chTLS := make(chan error, 1)
	go p.probeQUIC(addr, probeTLSCfg, chQuic)
	go p.probeTLS(dialContext, probeTLSCfg, chTLS)

	select {
	case quicErr := <-chQuic:
		if quicErr != nil {
			// QUIC failed, return error since HTTP3 was not preferred.
			return "", quicErr
		}

		// Return immediately, QUIC was faster.
		return addr, quicErr
	case tlsErr := <-chTLS:
		if tlsErr != nil {
			// Return immediately, TLS failed.
			log.Debug("probing TLS: %v", tlsErr)
			return addr, nil
		}

		return "", errors.Error("TLS was faster than QUIC, prefer it")
	}
}

// probeQUIC attempts to establish a QUIC connection to the specified address.
// We run probeQUIC and probeTLS in parallel and see which one is faster.
func (p *dnsOverHTTPS) probeQUIC(addr string, tlsConfig *tls.Config, ch chan error) {
	startTime := time.Now()

	timeout := p.boot.options.Timeout
	if timeout == 0 {
		timeout = dialTimeout
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(timeout))
	defer cancel()

	conn, err := quic.DialAddrEarlyContext(ctx, addr, tlsConfig, p.quicConfig)
	if err != nil {
		ch <- fmt.Errorf("opening QUIC connection to %s: %w", p.Address(), err)
		return
	}

	// Ignore the error since there's no way we can use it for anything useful.
	_ = conn.CloseWithError(QUICCodeNoError, "")

	ch <- nil

	elapsed := time.Now().Sub(startTime)
	log.Debug("elapsed on establishing a QUIC connection: %s", elapsed)
}

// probeTLS attempts to establish a TLS connection to the specified address. We
// run probeQUIC and probeTLS in parallel and see which one is faster.
func (p *dnsOverHTTPS) probeTLS(dialContext dialHandler, tlsConfig *tls.Config, ch chan error) {
	startTime := time.Now()

	conn, err := tlsDial(dialContext, "tcp", tlsConfig)
	if err != nil {
		ch <- fmt.Errorf("opening TLS connection: %w", err)
		return
	}

	// Ignore the error since there's no way we can use it for anything useful.
	_ = conn.Close()

	ch <- nil

	elapsed := time.Now().Sub(startTime)
	log.Debug("elapsed on establishing a TLS connection: %s", elapsed)
}

// supportsH3 returns true if HTTP/3 is supported by this upstream.
func (p *dnsOverHTTPS) supportsH3() (ok bool) {
	for _, v := range p.supportedHTTPVersions() {
		if v == HTTPVersion3 {
			return true
		}
	}

	return false
}

// supportsHTTP returns true if HTTP/1.1 or HTTP2 is supported by this upstream.
func (p *dnsOverHTTPS) supportsHTTP() (ok bool) {
	for _, v := range p.supportedHTTPVersions() {
		if v == HTTPVersion11 || v == HTTPVersion2 {
			return true
		}
	}

	return false
}

// supportedHTTPVersions returns the list of supported HTTP versions.
func (p *dnsOverHTTPS) supportedHTTPVersions() (v []HTTPVersion) {
	v = p.boot.options.HTTPVersions
	if v == nil {
		v = DefaultHTTPVersions
	}

	return v
}
