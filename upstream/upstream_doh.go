package upstream

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

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

// dnsOverHTTPS represents DNS-over-HTTPS upstream.
type dnsOverHTTPS struct {
	boot *bootstrapper

	// The Client's Transport typically has internal state (cached TCP
	// connections), so Clients should be reused instead of created as
	// needed. Clients are safe for concurrent use by multiple goroutines.
	client      *http.Client
	clientGuard sync.Mutex
}

// type check
var _ Upstream = &dnsOverHTTPS{}

func (p *dnsOverHTTPS) Address() string { return p.boot.URL.String() }

func (p *dnsOverHTTPS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	client, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("initializing http client: %w", err)
	}

	logBegin(p.Address(), m)
	r, err := p.exchangeHTTPSClient(m, client)
	logFinish(p.Address(), err)

	return r, err
}

// exchangeHTTPSClient sends the DNS query to a DOH resolver using the specified
// http.Client instance.
func (p *dnsOverHTTPS) exchangeHTTPSClient(m *dns.Msg, client *http.Client) (*dns.Msg, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	requestURL := p.Address() + "?dns=" + base64.RawURLEncoding.EncodeToString(buf)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", p.boot.URL, err)
	}

	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// TODO: consider using errors.As
		if os.IsTimeout(err) {
			// If this is a timeout error, trying to forcibly re-create the HTTP client instance
			// See https://github.com/AdguardTeam/AdGuardHome/issues/3217 for more details on this
			p.clientGuard.Lock()
			p.client = nil
			p.clientGuard.Unlock()
		}

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

// getClient gets or lazily initializes an HTTP client (and transport) that will
// be used for this DOH resolver.
func (p *dnsOverHTTPS) getClient() (c *http.Client, err error) {
	startTime := time.Now()

	p.clientGuard.Lock()
	defer p.clientGuard.Unlock()
	if p.client != nil {
		return p.client, nil
	}

	// Timeout can be exceeded while waiting for the lock
	// This happens quite often on mobile devices
	elapsed := time.Since(startTime)
	if p.boot.options.Timeout > 0 && elapsed > p.boot.options.Timeout {
		return nil, fmt.Errorf("timeout exceeded: %s", elapsed)
	}

	p.client, err = p.createClient()

	return p.client, err
}

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
// for this DOH resolver. This HTTP transport ensures that the HTTP requests
// will be sent exactly to the IP address got from the bootstrap resolver.
func (p *dnsOverHTTPS) createTransport() (*http.Transport, error) {
	tlsConfig, dialContext, err := p.boot.get()
	if err != nil {
		return nil, fmt.Errorf("bootstrapping %s: %w", p.boot.URL, err)
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
