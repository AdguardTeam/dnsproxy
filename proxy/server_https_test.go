package proxy

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

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHttpsProxy(t *testing.T) {
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
			// Prepare dnsProxy with its configuration.
			tlsConf, caPem := createServerTLSConfig(t)
			dnsProxy := createTestProxy(t, tlsConf)
			dnsProxy.HTTP3 = tc.http3

			// Run the proxy.
			err := dnsProxy.Start()
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

			// Create the HTTP client that we'll be using for this test.
			client := createTestHTTPClient(dnsProxy, caPem, tc.http3)

			// Prepare a test message to be sent to the server.
			msg := createTestMessage()

			// Send the test message and check if the response is what we
			// expected.
			resp := sendTestDoHMessage(t, client, msg, nil)
			requireResponse(t, msg, resp)
		})
	}
}

func TestProxy_trustedProxies(t *testing.T) {
	var (
		clientAddr = netip.MustParseAddr("1.2.3.4")
		proxyAddr  = netip.MustParseAddr("127.0.0.1")
	)

	doRequest := func(t *testing.T, addr string, expectedClientIP netip.Addr) {
		// Prepare the proxy server.
		tlsConf, caPem := createServerTLSConfig(t)
		dnsProxy := createTestProxy(t, tlsConf)

		var gotAddr netip.Addr
		dnsProxy.RequestHandler = func(_ *Proxy, d *DNSContext) (err error) {
			gotAddr = d.Addr.Addr()

			return dnsProxy.Resolve(d)
		}

		client := createTestHTTPClient(dnsProxy, caPem, false)

		msg := createTestMessage()

		dnsProxy.TrustedProxies = []string{addr}

		// Start listening.
		serr := dnsProxy.Start()
		require.NoError(t, serr)
		testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

		hdrs := map[string]string{
			"X-Forwarded-For": strings.Join([]string{clientAddr.String(), proxyAddr.String()}, ","),
		}

		resp := sendTestDoHMessage(t, client, msg, hdrs)
		requireResponse(t, msg, resp)

		require.Equal(t, expectedClientIP, gotAddr)
	}

	t.Run("success", func(t *testing.T) {
		doRequest(t, proxyAddr.String(), clientAddr)
	})

	t.Run("not_in_trusted", func(t *testing.T) {
		doRequest(t, "127.0.0.2", proxyAddr)
	})
}

func TestAddrsFromRequest(t *testing.T) {
	var (
		theIP     = netip.AddrFrom4([4]byte{1, 2, 3, 4})
		anotherIP = netip.AddrFrom4([4]byte{1, 2, 3, 5})

		theIPStr     = theIP.String()
		anotherIPStr = anotherIP.String()
	)

	testCases := []struct {
		name    string
		hdrs    map[string]string
		wantIP  netip.Addr
		wantErr string
	}{{
		name: "cf-connecting-ip",
		hdrs: map[string]string{
			"CF-Connecting-IP": theIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "true-client-ip",
		hdrs: map[string]string{
			"True-Client-IP": theIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "x-real-ip",
		hdrs: map[string]string{
			"X-Real-IP": theIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "no_any",
		hdrs: map[string]string{
			"CF-Connecting-IP": "invalid",
			"True-Client-IP":   "invalid",
			"X-Real-IP":        "invalid",
		},
		wantIP:  netip.Addr{},
		wantErr: `ParseAddr(""): unable to parse IP`,
	}, {
		name: "priority",
		hdrs: map[string]string{
			"X-Forwarded-For":  strings.Join([]string{anotherIPStr, theIPStr}, ","),
			"True-Client-IP":   anotherIPStr,
			"X-Real-IP":        anotherIPStr,
			"CF-Connecting-IP": theIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "x-forwarded-for_simple",
		hdrs: map[string]string{
			"X-Forwarded-For": strings.Join([]string{anotherIPStr, theIPStr}, ","),
		},
		wantIP:  anotherIP,
		wantErr: "",
	}, {
		name: "x-forwarded-for_single",
		hdrs: map[string]string{
			"X-Forwarded-For": theIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "x-forwarded-for_invalid_proxy",
		hdrs: map[string]string{
			"X-Forwarded-For": strings.Join([]string{theIPStr, "invalid"}, ","),
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "x-forwarded-for_empty",
		hdrs: map[string]string{
			"X-Forwarded-For": "",
		},
		wantIP:  netip.Addr{},
		wantErr: `ParseAddr(""): unable to parse IP`,
	}, {
		name: "x-forwarded-for_redundant_spaces",
		hdrs: map[string]string{
			"X-Forwarded-For": "  " + theIPStr + "   ,\t" + anotherIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "cf-connecting-ip_redundant_spaces",
		hdrs: map[string]string{
			"CF-Connecting-IP": "  " + theIPStr + "\t",
		},
		wantIP:  theIP,
		wantErr: "",
	}}

	for _, tc := range testCases {
		r, err := http.NewRequest(http.MethodGet, "localhost", nil)
		require.NoError(t, err)

		for h, v := range tc.hdrs {
			r.Header.Set(h, v)
		}

		t.Run(tc.name, func(t *testing.T) {
			var ip netip.Addr
			ip, err = realIPFromHdrs(r)
			testutil.AssertErrorMsg(t, tc.wantErr, err)

			assert.Equal(t, tc.wantIP, ip)
		})
	}
}

func TestRemoteAddr(t *testing.T) {
	const thePort = 4321

	var (
		theIP     = netip.AddrFrom4([4]byte{1, 2, 3, 4})
		anotherIP = netip.AddrFrom4([4]byte{1, 2, 3, 5})
		thirdIP   = netip.AddrFrom4([4]byte{1, 2, 3, 6})

		theIPStr     = theIP.String()
		anotherIPStr = anotherIP.String()
		thirdIPStr   = thirdIP.String()
	)

	rAddr := netip.AddrPortFrom(theIP, thePort)

	testCases := []struct {
		name       string
		remoteAddr string
		hdrs       map[string]string
		wantErr    string
		wantIP     netip.AddrPort
		wantProxy  netip.AddrPort
	}{{
		name:       "no_proxy",
		remoteAddr: rAddr.String(),
		hdrs:       nil,
		wantErr:    "",
		wantIP:     netip.AddrPortFrom(theIP, thePort),
		wantProxy:  netip.AddrPort{},
	}, {
		name:       "proxied_with_cloudflare",
		remoteAddr: rAddr.String(),
		hdrs: map[string]string{
			"CF-Connecting-IP": anotherIPStr,
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(anotherIP, 0),
		wantProxy: netip.AddrPortFrom(theIP, thePort),
	}, {
		name:       "proxied_once",
		remoteAddr: rAddr.String(),
		hdrs: map[string]string{
			"X-Forwarded-For": anotherIPStr,
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(anotherIP, 0),
		wantProxy: netip.AddrPortFrom(theIP, thePort),
	}, {
		name:       "proxied_multiple",
		remoteAddr: rAddr.String(),
		hdrs: map[string]string{
			"X-Forwarded-For": strings.Join([]string{anotherIPStr, thirdIPStr}, ","),
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(anotherIP, 0),
		wantProxy: netip.AddrPortFrom(theIP, thePort),
	}, {
		name:       "no_port",
		remoteAddr: theIPStr,
		hdrs:       nil,
		wantErr:    "not an ip:port",
		wantIP:     netip.AddrPort{},
		wantProxy:  netip.AddrPort{},
	}, {
		name:       "bad_port",
		remoteAddr: theIPStr + ":notport",
		hdrs:       nil,
		wantErr:    `invalid port "notport" parsing "1.2.3.4:notport"`,
		wantIP:     netip.AddrPort{},
		wantProxy:  netip.AddrPort{},
	}, {
		name:       "bad_host",
		remoteAddr: "host:1",
		hdrs:       nil,
		wantErr:    `ParseAddr("host"): unable to parse IP`,
		wantIP:     netip.AddrPort{},
		wantProxy:  netip.AddrPort{},
	}, {
		name:       "bad_proxied_host",
		remoteAddr: "host:1",
		hdrs: map[string]string{
			"CF-Connecting-IP": theIPStr,
		},
		wantErr:   `ParseAddr("host"): unable to parse IP`,
		wantIP:    netip.AddrPort{},
		wantProxy: netip.AddrPort{},
	}}

	for _, tc := range testCases {
		r, err := http.NewRequest(http.MethodGet, "localhost", nil)
		require.NoError(t, err)

		r.RemoteAddr = tc.remoteAddr
		for h, v := range tc.hdrs {
			r.Header.Set(h, v)
		}

		t.Run(tc.name, func(t *testing.T) {
			var addr, prx netip.AddrPort
			addr, prx, err = remoteAddr(r)
			if tc.wantErr != "" {
				testutil.AssertErrorMsg(t, tc.wantErr, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantIP, addr)
			assert.Equal(t, tc.wantProxy, prx)
		})
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
		Host:     tlsServerName,
		Path:     "/dns-query",
		RawQuery: fmt.Sprintf("dns=%s", base64.RawURLEncoding.EncodeToString(packed)),
	}

	method := http.MethodGet
	if _, ok := client.Transport.(*http3.RoundTripper); ok {
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

// createTestHTTPClient creates an *http.Client that will be used to send
// requests to the specified dnsProxy.
func createTestHTTPClient(dnsProxy *Proxy, caPem []byte, http3Enabled bool) (client *http.Client) {
	// prepare roots list so that the server cert was successfully validated.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsClientConfig := &tls.Config{
		ServerName: tlsServerName,
		RootCAs:    roots,
	}

	var transport http.RoundTripper

	if http3Enabled {
		tlsClientConfig.NextProtos = []string{"h3"}

		transport = &http3.RoundTripper{
			Dial: func(
				ctx context.Context,
				_ string,
				tlsCfg *tls.Config,
				cfg *quic.Config,
			) (quic.EarlyConnection, error) {
				addr := dnsProxy.Addr(ProtoHTTPS).String()
				return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
			},
			TLSClientConfig:    tlsClientConfig,
			QuicConfig:         &quic.Config{},
			DisableCompression: true,
		}
	} else {
		dialer := &net.Dialer{
			Timeout: defaultTimeout,
		}
		dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Route request to the DNS-over-HTTPS server address.
			return dialer.DialContext(ctx, network, dnsProxy.Addr(ProtoHTTPS).String())
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
