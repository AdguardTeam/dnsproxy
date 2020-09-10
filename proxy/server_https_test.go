package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"testing"

	"github.com/miekg/dns"
)

func TestHttpsProxy(t *testing.T) {
	// Prepare the proxy server
	serverConfig, caPem := createServerTLSConfig(t)
	dnsProxy := createTestProxy(t, serverConfig)

	// Start listening
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{ServerName: tlsServerName, RootCAs: roots}

	// Send a DNS-over-HTTPS request
	httpsAddr := dnsProxy.Addr(ProtoHTTPS)

	dialer := &net.Dialer{
		Timeout: defaultTimeout,
	}
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Route request to the DOH server address
		return dialer.DialContext(ctx, network, httpsAddr.String())
	}
	transport := &http.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		DialContext:        dialContext,
	}

	msg := createTestMessage()
	buf, err := msg.Pack()
	if err != nil {
		t.Fatalf("couldn't pack DNS request: %s", err)
	}

	bb := bytes.NewBuffer(buf)
	req, err := http.NewRequest("POST", "https://test.com", bb)
	if err != nil {
		t.Fatalf("couldn't create a new HTTP request: %s", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// IP "1.2.3.4" will be used as a client address in DNSContext
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 127.0.0.1")

	client := http.Client{
		Transport: transport,
		Timeout:   defaultTimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("couldn't exec the HTTP request: %s", err)
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("coulnd't read the response body: %s", err)
	}
	reply := &dns.Msg{}
	err = reply.Unpack(body)
	if err != nil {
		t.Fatalf("invalid DNS response: %s", err)
	}

	assertResponse(t, reply)

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}
