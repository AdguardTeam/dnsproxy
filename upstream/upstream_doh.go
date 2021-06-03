package upstream

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// dnsOverHTTPS represents DNS-over-HTTPS upstream.
type dnsOverHTTPS struct {
	boot *bootstrapper

	// mu exists for lazy initialization purposes and protects client from
	// data race during lazy initialization.  It provides the exchange with
	// invalid upstream possibility, which is needed for now. Should be
	// refactored further.
	mu sync.Mutex

	// The Client's Transport typically has internal state (cached TCP
	// connections), so Clients should be reused instead of created as
	// needed. Clients are safe for concurrent use by multiple goroutines.
	client *http.Client
}

// type check
var _ Upstream = &dnsOverHTTPS{}

func (p *dnsOverHTTPS) Address() string { return p.boot.URL.String() }

func (p *dnsOverHTTPS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	client, err := p.getClient()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't initialize HTTP client or transport")
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
		return nil, errorx.Decorate(err, "couldn't pack request msg")
	}

	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	requestURL := p.Address() + "?dns=" + base64.RawURLEncoding.EncodeToString(buf)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't create a HTTP request to %s", p.boot.URL)
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't do a GET request to '%s'", p.boot.URL)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't read body contents for '%s'", p.boot.URL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got an unexpected HTTP status code %d from '%s'", resp.StatusCode, p.boot.URL)
	}
	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't unpack DNS response from '%s': body is %s", p.boot.URL, string(body))
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

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client != nil {
		return p.client, nil
	}

	// Timeout can be exceeded while waiting for the lock
	// This happens quite often on mobile devices
	elapsed := time.Since(startTime)
	if p.boot.options.Timeout > 0 && elapsed > p.boot.options.Timeout {
		return nil, fmt.Errorf("timeout exceeded: %d ms", int(elapsed/time.Millisecond))
	}

	p.client, err = p.createClient()

	return p.client, err
}

func (p *dnsOverHTTPS) createClient() (*http.Client, error) {
	transport, err := p.createTransport()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't initialize HTTP transport")
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
		return nil, errorx.Decorate(err, "couldn't bootstrap %s", p.boot.URL)
	}

	transport := &http.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		DialContext:        dialContext,
	}
	// It appears that this is important to explicitly configure transport to use HTTP2
	// Relevant issue: https://github.com/AdguardTeam/dnsproxy/issues/11
	_, err = http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	return transport, nil
}
