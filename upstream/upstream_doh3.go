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
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
)

// dnsOverHTTP3 represents DNS-over-HTTP/3 upstream.
type dnsOverHTTP3 struct {
	boot *bootstrapper

	client      *http.Client
	clientGuard sync.Mutex
}

// type check
var _ Upstream = &dnsOverHTTP3{}

// newDoH3 returns the DNS-over-HTTP3 Upstream.
func newDoH3(uu *url.URL, opts *Options) (u Upstream, err error) {
	addPort(uu, defaultPortDoH)

	var b *bootstrapper
	b, err = urlToBoot(uu, opts)
	if err != nil {
		return nil, fmt.Errorf("creating https bootstrapper: %w", err)
	}

	return &dnsOverHTTP3{boot: b}, nil
}

func (p *dnsOverHTTP3) Address() string { return p.boot.URL.String() }

func (p *dnsOverHTTP3) Exchange(m *dns.Msg) (*dns.Msg, error) {
	client, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("initializing http client: %w", err)
	}

	logBegin(p.Address(), m)
	r, err := p.exchangeHTTP3Client(m, client)
	logFinish(p.Address(), err)

	return r, err
}

// exchangeHTTP3Client sends the DNS query to a DOH3 resolver using the specified
// http.Client instance.
func (p *dnsOverHTTP3) exchangeHTTP3Client(m *dns.Msg, client *http.Client) (*dns.Msg, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	requestURL := p.Address() + "?dns=" + base64.RawURLEncoding.EncodeToString(buf)
	u, err := url.Parse(requestURL)
	if err != nil {
		return nil, fmt.Errorf("parse request URL: %w", err)
	}

	u.Scheme = "https"
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", p.boot.URL, err)
	}

	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// If this is a timeout error, trying to forcibly re-create the HTTP
			// client instance.
			//
			// See https://github.com/AdguardTeam/AdGuardHome/issues/3217.
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
func (p *dnsOverHTTP3) getClient() (c *http.Client, err error) {
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

func (p *dnsOverHTTP3) createClient() (*http.Client, error) {
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
// for this DOH3 resolver. This HTTP transport ensures that the HTTP requests
// will be sent exactly to the IP address got from the bootstrap resolver.
func (p *dnsOverHTTP3) createTransport() (http.RoundTripper, error) {
	tlsConfig, dialContext, err := p.boot.get()
	if err != nil {
		return nil, fmt.Errorf("bootstrapping %s: %w", p.boot.URL, err)
	}

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
	}

	transport := &http3.RoundTripper{
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		QuicConfig:         quicConfig,
		Dial: func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
			// we're using bootstrapped address instead of what's passed to the function
			// it does not create an actual connection, but it helps us determine
			// what IP is actually reachable (when there're v4/v6 addresses)
			rawConn, e := dialContext(context.Background(), "udp", "")
			if e != nil {
				return nil, e
			}
			// It's never actually used
			_ = rawConn.Close()

			udpConn, ok := rawConn.(*net.UDPConn)
			if !ok {
				return nil, fmt.Errorf("failed to open connection to %s", p.Address())
			}

			return quic.DialAddrEarly(udpConn.RemoteAddr().String(), tlsCfg, cfg)
		},
	}

	return transport, nil
}
