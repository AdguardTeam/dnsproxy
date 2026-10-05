package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	proxytest "github.com/AdguardTeam/dnsproxy/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

// Common address strings for tests.
const (
	testClientAddrStr1        = "192.0.2.1"
	testClientAddrStr2        = "192.0.2.2"
	testProxyAddrStr          = "127.0.0.1"
	testUntrustedProxyAddrStr = "127.0.0.2"
)

// Common addresses for tests.
var (
	testClientAddr1        = netip.MustParseAddr(testClientAddrStr1)
	testClientAddr2        = netip.MustParseAddr(testClientAddrStr2)
	testProxyAddr          = netip.MustParseAddr(testProxyAddrStr)
	testUntrustedProxyAddr = netip.MustParseAddr(testUntrustedProxyAddrStr)
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

			tlsListenAddr := dnsproxytest.TCPLocalhostAnyPort
			quicListenAddr := dnsproxytest.UDPLocalhostAnyPort
			dnsProxy, err := proxy.New(&proxy.Config{
				Logger:         testLogger,
				TLSListenAddr:  []*net.TCPAddr{tlsListenAddr},
				QUICListenAddr: []*net.UDPAddr{quicListenAddr},
				TLSConfig:      tlsConf,
				UpstreamConfig: &proxy.UpstreamConfig{
					Upstreams: []upstream.Upstream{newTestUpstream(t)},
				},
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

	testCases := []struct {
		trustedProxy netip.Addr
		wantClientIP netip.Addr
		name         string
	}{{
		name:         "success",
		trustedProxy: testProxyAddr,
		wantClientIP: testClientAddr1,
	}, {
		name:         "not_in_trusted",
		trustedProxy: testUntrustedProxyAddr,
		wantClientIP: testProxyAddr,
	}}

	hdr := http.Header{
		httphdr.XForwardedFor: []string{testClientAddrStr1 + "," + testProxyAddrStr},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testProxyRealIPDetection(t, tc.trustedProxy, hdr, tc.wantClientIP)
		})
	}
}

// testProxyRealIPDetection starts a proxy and checks the client IP detected
// from hdr.  trustedProxy and wantClientIP must be valid.
func testProxyRealIPDetection(
	tb testing.TB,
	trustedProxy netip.Addr,
	hdr http.Header,
	wantClientIP netip.Addr,
) {
	var gotAddr netip.Addr
	reqHandler := &proxytest.Handler{
		OnHandle: func(ctx context.Context, p *proxy.Proxy, d *proxy.DNSContext) (err error) {
			gotAddr = d.Addr.Addr()

			return p.Resolve(ctx, d)
		},
	}

	tlsConf, caPem := dnsproxytest.NewTLSConfig(tb)
	httpConf := &proxy.HTTPConfig{
		ListenAddresses: []netip.AddrPort{dnsproxytest.LocalhostAnyPort},
	}
	trustedProxies := netip.PrefixFrom(trustedProxy, trustedProxy.BitLen())
	dnsProxy, err := proxy.New(&proxy.Config{
		Logger: testLogger,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(tb)},
		},
		TrustedProxies: trustedProxies,
		RequestHandler: reqHandler,
		TLSConfig:      tlsConf,
		TLSListenAddr:  []*net.TCPAddr{dnsproxytest.TCPLocalhostAnyPort},
		QUICListenAddr: []*net.UDPAddr{dnsproxytest.UDPLocalhostAnyPort},
		HTTPConfig:     httpConf,
	})
	require.NoError(tb, err)

	client := createTestHTTPClient(dnsProxy, caPem, false)
	msg := dnsproxytest.NewTestRequest()

	servicetest.RequireRun(tb, dnsProxy, dnsproxytest.Timeout)

	resp := sendTestDoHMessage(tb, client, msg, hdr)
	dnsproxytest.RequireResponse(tb, msg, resp)

	require.Equal(tb, wantClientIP, gotAddr)
}

func TestProxy_HandleDNSRequest_realIPFromHeader(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantClientIP netip.Addr
		hdr          http.Header
		name         string
	}{{
		name: "cf-connecting-ip",
		hdr: http.Header{
			httphdr.CFConnectingIP: []string{testClientAddrStr1},
		},
		wantClientIP: testClientAddr1,
	}, {
		name: "true-client-ip",
		hdr: http.Header{
			httphdr.TrueClientIP: []string{testClientAddrStr1},
		},
		wantClientIP: testClientAddr1,
	}, {
		name: "x-real-ip",
		hdr: http.Header{
			httphdr.XRealIP: []string{testClientAddrStr1},
		},
		wantClientIP: testClientAddr1,
	}, {
		name: "cf-connecting-ip_redundant_spaces",
		hdr: http.Header{
			httphdr.CFConnectingIP: []string{"  " + testClientAddrStr1 + "\t"},
		},
		wantClientIP: testClientAddr1,
	}, {
		name: "no_any",
		hdr: http.Header{
			httphdr.CFConnectingIP: []string{"invalid"},
			httphdr.TrueClientIP:   []string{"invalid"},
			httphdr.XRealIP:        []string{"invalid"},
		},
		wantClientIP: testProxyAddr,
	}, {
		name: "priority",
		hdr: http.Header{
			httphdr.XForwardedFor:  []string{testClientAddrStr2 + "," + testClientAddrStr1},
			httphdr.TrueClientIP:   []string{testClientAddrStr2},
			httphdr.XRealIP:        []string{testClientAddrStr2},
			httphdr.CFConnectingIP: []string{testClientAddrStr1},
		},
		wantClientIP: testClientAddr1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testProxyRealIPDetection(t, testProxyAddr, tc.hdr, tc.wantClientIP)
		})
	}
}

func TestProxy_HandleDNSRequest_realIPFromHeaderXFF(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantClientIP netip.Addr
		hdr          http.Header
		name         string
	}{{
		name: "x-forwarded-for_simple",
		hdr: http.Header{
			httphdr.XForwardedFor: []string{testClientAddrStr2 + "," + testClientAddrStr1},
		},
		wantClientIP: testClientAddr2,
	}, {
		name: "x-forwarded-for_single",
		hdr: http.Header{
			httphdr.XForwardedFor: []string{testClientAddrStr1},
		},
		wantClientIP: testClientAddr1,
	}, {
		name: "x-forwarded-for_invalid_proxy",
		hdr: http.Header{
			httphdr.XForwardedFor: []string{testClientAddrStr1 + ",invalid"},
		},
		wantClientIP: testClientAddr1,
	}, {
		name: "x-forwarded-for_empty",
		hdr: http.Header{
			httphdr.XForwardedFor: []string{""},
		},
		wantClientIP: testProxyAddr,
	}, {
		name: "x-forwarded-for_redundant_spaces",
		hdr: http.Header{
			httphdr.XForwardedFor: []string{
				"  " + testClientAddrStr1 + "   ,\t" + testClientAddrStr2,
			},
		},
		wantClientIP: testClientAddr1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testProxyRealIPDetection(t, testProxyAddr, tc.hdr, tc.wantClientIP)
		})
	}
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
	tb testing.TB,
	client *http.Client,
	m *dns.Msg,
	hdr http.Header,
) (resp *dns.Msg) {
	tb.Helper()

	packed, err := m.Pack()
	require.NoError(tb, err)

	u := url.URL{
		Scheme:   urlutil.SchemeHTTPS,
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
	require.NoError(tb, err)

	maps.Copy(req.Header, hdr)

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	httpResp, err := client.Do(req)
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, httpResp.Body.Close)

	require.True(tb, httpResp.ProtoAtLeast(2, 0))

	body, err := io.ReadAll(httpResp.Body)
	require.NoError(tb, err)

	resp = &dns.Msg{}
	err = resp.Unpack(body)
	require.NoError(tb, err)

	return resp
}
