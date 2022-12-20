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
	"runtime"
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
	// each host.  Note, that setting it to 1 may cause issues with Go's http
	// implementation, see https://github.com/AdguardTeam/dnsproxy/issues/278.
	dohMaxConnsPerHost = 2

	// dohMaxIdleConns controls the maximum number of connections being idle
	// at the same time.
	dohMaxIdleConns = 2
)

// dnsOverHTTPS is a struct that implements the Upstream interface for the
// DNS-over-HTTPS protocol.
type dnsOverHTTPS struct {
	boot *bootstrapper

	// The Client's Transport typically has internal state (cached TCP
	// connections), so Clients should be reused instead of created as
	// needed. Clients are safe for concurrent use by multiple goroutines.
	client   *http.Client
	clientMu sync.Mutex

	// quicConfig is the QUIC configuration that is used if HTTP/3 is enabled
	// for this upstream.
	quicConfig      *quic.Config
	quicConfigGuard sync.Mutex
}

// type check
var _ Upstream = (*dnsOverHTTPS)(nil)

// newDoH returns the DNS-over-HTTPS Upstream.
func newDoH(uu *url.URL, opts *Options) (u Upstream, err error) {
	addPort(uu, defaultPortDoH)

	var b *bootstrapper
	b, err = urlToBoot(uu, opts)
	if err != nil {
		return nil, fmt.Errorf("creating https bootstrapper: %w", err)
	}

	u = &dnsOverHTTPS{
		boot: b,

		quicConfig: &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
			Tracer:          opts.QUICTracer,
		},
	}

	runtime.SetFinalizer(u, (*dnsOverHTTPS).Close)

	return u, nil
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
	client, isCached, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("failed to init http client: %w", err)
	}

	// Make the first attempt to send the DNS query.
	resp, err = p.exchangeHTTPS(client, m)

	// Make up to 2 attempts to re-create the HTTP client and send the request
	// again.  There are several cases (mostly, with QUIC) where this workaround
	// is necessary to make HTTP client usable.  We need to make 2 attempts in
	// the case when the connection was closed (due to inactivity for example)
	// AND the server refuses to open a 0-RTT connection.
	for i := 0; isCached && p.shouldRetry(err) && i < 2; i++ {
		client, err = p.resetClient(err)
		if err != nil {
			return nil, fmt.Errorf("failed to reset http client: %w", err)
		}

		resp, err = p.exchangeHTTPS(client, m)
	}

	if err != nil {
		// If the request failed anyway, make sure we don't use this client.
		_, resErr := p.resetClient(err)

		return nil, errors.WithDeferred(err, resErr)
	}

	return resp, err
}

// Close implements the Upstream interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Close() (err error) {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()

	runtime.SetFinalizer(p, nil)

	if p.client == nil {
		return nil
	}

	return p.closeClient(p.client)
}

// closeClient cleans up resources used by client if necessary.  Note, that at
// this point it should only be done for HTTP/3 as it may leak due to keep-alive
// connections.
func (p *dnsOverHTTPS) closeClient(client *http.Client) (err error) {
	if isHTTP3(client) {
		return client.Transport.(io.Closer).Close()
	}

	return nil
}

// exchangeHTTPS logs the request and its result and calls exchangeHTTPSClient.
func (p *dnsOverHTTPS) exchangeHTTPS(client *http.Client, req *dns.Msg) (resp *dns.Msg, err error) {
	logBegin(p.Address(), req)
	resp, err = p.exchangeHTTPSClient(client, req)
	logFinish(p.Address(), err)

	return resp, err
}

// exchangeHTTPSClient sends the DNS query to a DoH resolver using the specified
// http.Client instance.
func (p *dnsOverHTTPS) exchangeHTTPSClient(
	client *http.Client,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	method := http.MethodGet
	if isHTTP3(client) {
		// If we're using HTTP/3, use http3.MethodGet0RTT to force using 0-RTT.
		method = http3.MethodGet0RTT
	}

	u := url.URL{
		Scheme:   p.boot.URL.Scheme,
		Host:     p.boot.URL.Host,
		Path:     p.boot.URL.Path,
		RawQuery: fmt.Sprintf("dns=%s", base64.RawURLEncoding.EncodeToString(buf)),
	}

	httpReq, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", p.boot.URL, err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", p.boot.URL, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p.boot.URL, err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil,
			fmt.Errorf(
				"expected status %d, got %d from %s",
				http.StatusOK,
				httpResp.StatusCode,
				p.boot.URL,
			)
	}

	resp = &dns.Msg{}
	err = resp.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf(
			"unpacking response from %s: body is %s: %w",
			p.boot.URL,
			body,
			err,
		)
	}

	if resp.Id != req.Id {
		err = dns.ErrId
	}

	return resp, err
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

// resetClient triggers re-creation of the *http.Client that is used by this
// upstream.  This method accepts the error that caused resetting client as
// depending on the error we may also reset the QUIC config.
func (p *dnsOverHTTPS) resetClient(resetErr error) (client *http.Client, err error) {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()

	if errors.Is(resetErr, quic.Err0RTTRejected) {
		// Reset the TokenStore only if 0-RTT was rejected.
		p.resetQUICConfig()
	}

	oldClient := p.client
	if oldClient != nil {
		closeErr := p.closeClient(oldClient)
		if closeErr != nil {
			log.Info("warning: failed to close the old http client: %v", closeErr)
		}
	}

	log.Debug("re-creating the http client due to %v", resetErr)
	p.client, err = p.createClient()

	return p.client, err
}

// getQUICConfig returns the QUIC config in a thread-safe manner.  Note, that
// this method returns a pointer, it is forbidden to change its properties.
func (p *dnsOverHTTPS) getQUICConfig() (c *quic.Config) {
	p.quicConfigGuard.Lock()
	defer p.quicConfigGuard.Unlock()

	return p.quicConfig
}

// resetQUICConfig Re-create the token store to make sure we're not trying to
// use invalid for 0-RTT.
func (p *dnsOverHTTPS) resetQUICConfig() {
	p.quicConfigGuard.Lock()
	defer p.quicConfigGuard.Unlock()

	p.quicConfig = p.quicConfig.Clone()
	p.quicConfig.TokenStore = newQUICTokenStore()
}

// getClient gets or lazily initializes an HTTP client (and transport) that will
// be used for this DoH resolver.
func (p *dnsOverHTTPS) getClient() (c *http.Client, isCached bool, err error) {
	startTime := time.Now()

	p.clientMu.Lock()
	defer p.clientMu.Unlock()
	if p.client != nil {
		return p.client, true, nil
	}

	// Timeout can be exceeded while waiting for the lock. This happens quite
	// often on mobile devices.
	elapsed := time.Since(startTime)
	if p.boot.options.Timeout > 0 && elapsed > p.boot.options.Timeout {
		return nil, false, fmt.Errorf("timeout exceeded: %s", elapsed)
	}

	log.Debug("creating a new http client")
	p.client, err = p.createClient()

	return p.client, false, err
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

// http3Transport is a wrapper over *http3.RoundTripper that tries to optimize
// its behavior.  The main thing that it does is trying to force use a single
// connection to a host instead of creating a new one all the time.  It also
// helps mitigate race issues with quic-go.
type http3Transport struct {
	baseTransport *http3.RoundTripper

	closed bool
	mu     sync.RWMutex
}

// type check
var _ http.RoundTripper = (*http3Transport)(nil)

// RoundTrip implements the http.RoundTripper interface for *http3Transport.
func (h *http3Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return nil, net.ErrClosed
	}

	// Try to use cached connection to the target host if it's available.
	resp, err = h.baseTransport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: true})

	if errors.Is(err, http3.ErrNoCachedConn) {
		// If there are no cached connection, trigger creating a new one.
		resp, err = h.baseTransport.RoundTrip(req)
	}

	return resp, err
}

// type check
var _ io.Closer = (*http3Transport)(nil)

// Close implements the io.Closer interface for *http3Transport.
func (h *http3Transport) Close() (err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed = true

	return h.baseTransport.Close()
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
		QuicConfig:         p.getQUICConfig(),
	}

	return &http3Transport{baseTransport: rt}, nil
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

	conn, err := quic.DialAddrEarlyContext(ctx, addr, tlsConfig, p.getQUICConfig())
	if err != nil {
		ch <- fmt.Errorf("opening QUIC connection to %s: %w", p.Address(), err)
		return
	}

	// Ignore the error since there's no way we can use it for anything useful.
	_ = conn.CloseWithError(QUICCodeNoError, "")

	ch <- nil

	elapsed := time.Since(startTime)
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

	elapsed := time.Since(startTime)
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

// isHTTP3 checks if the *http.Client is an HTTP/3 client.
func isHTTP3(client *http.Client) (ok bool) {
	_, ok = client.Transport.(*http3Transport)

	return ok
}
