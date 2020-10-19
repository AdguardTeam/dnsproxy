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
	"github.com/stretchr/testify/assert"
)

func TestHttpsProxy(t *testing.T) {
	// Prepare the proxy server
	serverConfig, caPem := createServerTLSConfig(t)
	dnsProxy := createTestProxy(t, serverConfig)

	// Start listening
	err := dnsProxy.Start()
	assert.Nil(t, err)
	defer func() {
		assert.Nil(t, dnsProxy.Stop())
	}()

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
	assert.Nil(t, err)

	bb := bytes.NewBuffer(buf)
	req, err := http.NewRequest("POST", "https://test.com", bb)
	assert.Nil(t, err)

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// IP "1.2.3.4" will be used as a client address in DNSContext
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 127.0.0.1")

	client := http.Client{
		Transport: transport,
		Timeout:   defaultTimeout,
	}
	resp, err := client.Do(req)
	assert.Nil(t, err)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	reply := &dns.Msg{}
	err = reply.Unpack(body)
	assert.Nil(t, err)

	assertResponse(t, reply)
}
