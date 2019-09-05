package upstream

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// DohMaxConnsPerHost controls the maximum number of connections per host
// nolint
var DohMaxConnsPerHost = 0

//
// DNS-over-https
//
type dnsOverHTTPS struct {
	boot *bootstrapper

	// The Client's Transport typically has internal state (cached TCP
	// connections), so Clients should be reused instead of created as
	// needed. Clients are safe for concurrent use by multiple goroutines.
	client *http.Client

	sync.RWMutex // protects transport
}

func (p *dnsOverHTTPS) Address() string { return p.boot.address }

func (p *dnsOverHTTPS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	client, err := p.getClient()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't initialize HTTP client or transport")
	}

	return p.exchangeHTTPSClient(m, client)
}

// exchangeHTTPSClient sends the DNS query to a DOH resolver using the specified http.Client instance
func (p *dnsOverHTTPS) exchangeHTTPSClient(m *dns.Msg, client *http.Client) (*dns.Msg, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't pack request msg")
	}

	// It appears, that GET requests are more memory-efficient with Golang implementation of HTTP/2.
	requestURL := p.boot.address + "?dns=" + base64.RawURLEncoding.EncodeToString(buf)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't create a HTTP request to %s", p.boot.address)
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't do a POST request to '%s'", p.boot.address)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't read body contents for '%s'", p.boot.address)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got an unexpected HTTP status code %d from '%s'", resp.StatusCode, p.boot.address)
	}
	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't unpack DNS response from '%s': body is %s", p.boot.address, string(body))
	}
	if err == nil && response.Id != m.Id {
		err = dns.ErrId
	}
	return &response, err
}

// getClient gets or lazily initializes an HTTP client (and transport) that will be used for this DOH resolver.
func (p *dnsOverHTTPS) getClient() (*http.Client, error) {
	p.Lock()
	defer p.Unlock()
	if p.client != nil {
		return p.client, nil
	}

	transport, err := p.createTransport()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't initialize HTTP transport")
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   p.boot.timeout,
		Jar:       nil,
	}

	// Warming up the HTTP client.
	// This is actually important -- if there is no warmup, there's a race condition on the very first DNS query:
	// http.Client will create numerous connections. During this warmup it'll create a new connection that will be used
	// for processing further DNS queries.
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{{Name: "ipv4only.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	_, err = p.exchangeHTTPSClient(&req, client)
	if err != nil {
		return nil, err
	}

	p.client = client
	return p.client, nil
}

// createTransport initializes an HTTP transport that will be used specifically for this DOH resolver
// This HTTP transport ensures that the HTTP requests will be sent exactly to the IP address got from the bootstrap resolver
func (p *dnsOverHTTPS) createTransport() (*http.Transport, error) {
	tlsConfig, dialContext, err := p.boot.get()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't bootstrap %s", p.boot.address)
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		DialContext:        dialContext,
		MaxConnsPerHost:    DohMaxConnsPerHost,
		MaxIdleConns:       1,
	}
	// It appears that this is important to explicitly configure transport to use HTTP2
	// Relevant issue: https://github.com/AdguardTeam/dnsproxy/issues/11
	http2.ConfigureTransport(transport) // nolint

	return transport, nil
}
