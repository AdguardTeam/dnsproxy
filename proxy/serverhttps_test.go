package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	proxytest "github.com/AdguardTeam/dnsproxy/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestProxy_HandleDNSRequest_https(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		http3 bool
	}{{
		name:  "https_proxy",
		http3: false,
	}, {
		name:  "h3_proxy",
		http3: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tlsConf, caPem := dnsproxytest.NewTLSConfig(t)

			httpConf := &proxy.HTTPConfig{
				ListenAddresses: []netip.AddrPort{dnsproxytest.LocalhostAnyPort},
				HTTP3Enabled:    tc.http3,
			}
			dnsProxy, err := proxy.New(&proxy.Config{
				Logger:         testLogger,
				TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
				QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
				TLSConfig:      tlsConf,
				UpstreamConfig: newTestUpstreamConfig(t),
				TrustedProxies: dnsproxytest.DefaultTrustedProxies,
				HTTPConfig:     httpConf,
			})
			require.NoError(t, err)

			servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

			// Create the HTTP client that we'll be using for this test.
			client := createTestHTTPClient(dnsProxy, caPem, tc.http3)

			// Prepare a test message to be sent to the server.
			msg := dnsproxytest.NewTestRequest()

			// Send the test message and check if the response is what we
			// expected.
			resp := sendTestDoHMessage(t, client, msg, nil)
			dnsproxytest.RequireResponse(t, msg, resp)
		})
	}
}

func TestProxy_HandleDNSRequest_trustedProxies(t *testing.T) {
	t.Parallel()

	var (
		clientAddr = netip.MustParseAddr("192.0.2.1")
		proxyAddr  = netip.MustParseAddr("127.0.0.1")
	)

	doRequest := func(t *testing.T, addr, expectedClientIP netip.Addr) {
		var gotAddr netip.Addr
		reqHandler := &proxytest.Handler{
			OnHandle: func(ctx context.Context, p *proxy.Proxy, d *proxy.DNSContext) (err error) {
				gotAddr = d.Addr.Addr()

				return p.Resolve(ctx, d)
			},
		}

		// Prepare the proxy server.
		tlsConf, caPem := dnsproxytest.NewTLSConfig(t)
		httpConf := &proxy.HTTPConfig{
			ListenAddresses: []netip.AddrPort{dnsproxytest.LocalhostAnyPort},
		}
		dnsProxy, err := proxy.New(&proxy.Config{
			Logger:         testLogger,
			UpstreamConfig: newTestUpstreamConfig(t),
			TrustedProxies: netip.PrefixFrom(addr, addr.BitLen()),
			RequestHandler: reqHandler,
			TLSConfig:      tlsConf,
			TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
			QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
			HTTPConfig:     httpConf,
		})
		require.NoError(t, err)

		client := createTestHTTPClient(dnsProxy, caPem, false)

		msg := dnsproxytest.NewTestRequest()

		servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

		hdrs := map[string]string{
			"X-Forwarded-For": strings.Join([]string{clientAddr.String(), proxyAddr.String()}, ","),
		}

		resp := sendTestDoHMessage(t, client, msg, hdrs)
		dnsproxytest.RequireResponse(t, msg, resp)

		require.Equal(t, expectedClientIP, gotAddr)
	}

	t.Run("success", func(t *testing.T) {
		doRequest(t, proxyAddr, clientAddr)
	})

	t.Run("not_in_trusted", func(t *testing.T) {
		doRequest(t, netip.MustParseAddr("127.0.0.2"), proxyAddr)
	})
}

// createTestHTTPClient creates an *http.Client that will be used to send
// requests to the specified dnsProxy.
func createTestHTTPClient(
	dnsProxy *proxy.Proxy,
	caPem []byte,
	http3Enabled bool,
) (client *http.Client) {
	// prepare roots list so that the server cert was successfully validated.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsClientConfig := &tls.Config{
		ServerName: dnsproxytest.TLSServerName,
		RootCAs:    roots,
	}

	var transport http.RoundTripper

	if http3Enabled {
		tlsClientConfig.NextProtos = []string{"h3"}

		transport = &http3.Transport{
			Dial: func(
				ctx context.Context,
				_ string,
				tlsCfg *tls.Config,
				cfg *quic.Config,
			) (*quic.Conn, error) {
				addr := dnsProxy.Addr(proxy.ProtoHTTPS).String()
				return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
			},
			TLSClientConfig:    tlsClientConfig,
			QUICConfig:         &quic.Config{},
			DisableCompression: true,
		}
	} else {
		dialer := &net.Dialer{
			Timeout: defaultTimeout,
		}
		dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Route request to the DNS-over-HTTPS server address.
			return dialer.DialContext(ctx, network, dnsProxy.Addr(proxy.ProtoHTTPS).String())
		}

		tlsClientConfig.NextProtos = []string{"h2", "http/1.1"}
		transport = &http.Transport{
			TLSClientConfig:    tlsClientConfig,
			DisableCompression: true,
			DialContext:        dialContext,
			ForceAttemptHTTP2:  true,
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   defaultTimeout,
	}
}

// sendTestDoHMessage sends the specified DNS message using client and returns
// the DNS response.
func sendTestDoHMessage(
	t *testing.T,
	client *http.Client,
	m *dns.Msg,
	hdrs map[string]string,
) (resp *dns.Msg) {
	packed, err := m.Pack()
	require.NoError(t, err)

	u := url.URL{
		Scheme:   "https",
		Host:     dnsproxytest.TLSServerName,
		Path:     "/dns-query",
		RawQuery: fmt.Sprintf("dns=%s", base64.RawURLEncoding.EncodeToString(packed)),
	}

	method := http.MethodGet
	if _, ok := client.Transport.(*http3.Transport); ok {
		// If we're using HTTP/3, use http3.MethodGet0RTT to force using 0-RTT.
		method = http3.MethodGet0RTT
	}

	req, err := http.NewRequest(method, u.String(), nil)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	for k, v := range hdrs {
		req.Header.Set(k, v)
	}

	httpResp, err := client.Do(req) // nolint:bodyclose
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, httpResp.Body.Close)

	require.True(
		t,
		httpResp.ProtoAtLeast(2, 0),
		"the proto is too old: %s",
		httpResp.Proto,
	)

	body, err := io.ReadAll(httpResp.Body)
	require.NoError(t, err)

	resp = &dns.Msg{}
	err = resp.Unpack(body)
	require.NoError(t, err)

	return resp
}
