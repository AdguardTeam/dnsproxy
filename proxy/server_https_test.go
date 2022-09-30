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
	"net/url"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
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

func TestHttpsProxyTrustedProxies(t *testing.T) {
	// Prepare the proxy server.
	tlsConf, caPem := createServerTLSConfig(t)
	dnsProxy := createTestProxy(t, tlsConf)

	var gotAddr net.Addr
	dnsProxy.RequestHandler = func(_ *Proxy, d *DNSContext) (err error) {
		gotAddr = d.Addr

		return dnsProxy.Resolve(d)
	}

	client := createTestHTTPClient(dnsProxy, caPem, false)

	clientIP, proxyIP := net.IP{1, 2, 3, 4}, net.IP{127, 0, 0, 1}
	msg := createTestMessage()

	doRequest := func(t *testing.T, proxyAddr string) {
		dnsProxy.TrustedProxies = []string{proxyAddr}

		// Start listening.
		serr := dnsProxy.Start()
		require.NoError(t, serr)
		testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

		hdrs := map[string]string{
			"X-Forwarded-For": strings.Join([]string{clientIP.String(), proxyIP.String()}, ","),
		}

		resp := sendTestDoHMessage(t, client, msg, hdrs)
		requireResponse(t, msg, resp)
	}

	t.Run("success", func(t *testing.T) {
		doRequest(t, proxyIP.String())

		ip, _ := netutil.IPAndPortFromAddr(gotAddr)
		assert.True(t, ip.Equal(clientIP))
	})

	t.Run("not_in_trusted", func(t *testing.T) {
		doRequest(t, "127.0.0.2")

		ip, _ := netutil.IPAndPortFromAddr(gotAddr)
		assert.True(t, ip.Equal(proxyIP))
	})
}

func TestAddrsFromRequest(t *testing.T) {
	theIP, anotherIP := net.IP{1, 2, 3, 4}, net.IP{1, 2, 3, 5}
	theIPStr, anotherIPStr := theIP.String(), anotherIP.String()

	testCases := []struct {
		name   string
		hdrs   map[string]string
		wantIP net.IP
	}{{
		name: "cf-connecting-ip",
		hdrs: map[string]string{
			"CF-Connecting-IP": theIPStr,
		},
		wantIP: theIP,
	}, {
		name: "true-client-ip",
		hdrs: map[string]string{
			"True-Client-IP": theIPStr,
		},
		wantIP: theIP,
	}, {
		name: "x-real-ip",
		hdrs: map[string]string{
			"X-Real-IP": theIPStr,
		},
		wantIP: theIP,
	}, {
		name: "no_any",
		hdrs: map[string]string{
			"CF-Connecting-IP": "invalid",
			"True-Client-IP":   "invalid",
			"X-Real-IP":        "invalid",
		},
		wantIP: nil,
	}, {
		name: "priority",
		hdrs: map[string]string{
			"X-Forwarded-For":  strings.Join([]string{anotherIPStr, theIPStr}, ","),
			"True-Client-IP":   anotherIPStr,
			"X-Real-IP":        anotherIPStr,
			"CF-Connecting-IP": theIPStr,
		},
		wantIP: theIP,
	}, {
		name: "x-forwarded-for_simple",
		hdrs: map[string]string{
			"X-Forwarded-For": strings.Join([]string{anotherIPStr, theIPStr}, ","),
		},
		wantIP: anotherIP,
	}, {
		name: "x-forwarded-for_single",
		hdrs: map[string]string{
			"X-Forwarded-For": theIPStr,
		},
		wantIP: theIP,
	}, {
		name: "x-forwarded-for_invalid_proxy",
		hdrs: map[string]string{
			"X-Forwarded-For": strings.Join([]string{theIPStr, "invalid"}, ","),
		},
		wantIP: theIP,
	}, {
		name: "x-forwarded-for_empty",
		hdrs: map[string]string{
			"X-Forwarded-For": "",
		},
		wantIP: nil,
	}, {
		name: "x-forwarded-for_redundant_spaces",
		hdrs: map[string]string{
			"X-Forwarded-For": "  " + theIPStr + "   ,\t" + anotherIPStr,
		},
		wantIP: theIP,
	}, {
		name: "cf-connecting-ip_redundant_spaces",
		hdrs: map[string]string{
			"CF-Connecting-IP": "  " + theIPStr + "\t",
		},
		wantIP: theIP,
	}}

	for _, tc := range testCases {
		r, err := http.NewRequest("GET", "localhost", nil)
		require.NoError(t, err)

		for h, v := range tc.hdrs {
			r.Header.Set(h, v)
		}

		t.Run(tc.name, func(t *testing.T) {
			ip := realIPFromHdrs(r)
			assert.True(t, tc.wantIP.Equal(ip))
		})
	}
}

func TestRemoteAddr(t *testing.T) {
	theIP, anotherIP, thirdIP := net.IP{1, 2, 3, 4}, net.IP{1, 2, 3, 5}, net.IP{1, 2, 3, 6}
	theIPStr, anotherIPStr, thirdIPStr := theIP.String(), anotherIP.String(), thirdIP.String()
	rAddr := &net.TCPAddr{IP: theIP, Port: 1}

	testCases := []struct {
		name       string
		remoteAddr string
		hdrs       map[string]string
		wantErr    string
		wantIP     net.IP
		wantProxy  net.IP
	}{{
		name:       "no_proxy",
		remoteAddr: rAddr.String(),
		hdrs:       nil,
		wantErr:    "",
		wantIP:     theIP,
		wantProxy:  nil,
	}, {
		name:       "proxied_with_cloudflare",
		remoteAddr: rAddr.String(),
		hdrs: map[string]string{
			"CF-Connecting-IP": anotherIPStr,
		},
		wantErr:   "",
		wantIP:    anotherIP,
		wantProxy: theIP,
	}, {
		name:       "proxied_once",
		remoteAddr: rAddr.String(),
		hdrs: map[string]string{
			"X-Forwarded-For": anotherIPStr,
		},
		wantErr:   "",
		wantIP:    anotherIP,
		wantProxy: theIP,
	}, {
		name:       "proxied_multiple",
		remoteAddr: rAddr.String(),
		hdrs: map[string]string{
			"X-Forwarded-For": strings.Join([]string{anotherIPStr, thirdIPStr}, ","),
		},
		wantErr:   "",
		wantIP:    anotherIP,
		wantProxy: theIP,
	}, {
		name:       "no_port",
		remoteAddr: theIPStr,
		hdrs:       nil,
		wantErr:    "address " + theIPStr + ": missing port in address",
		wantIP:     nil,
		wantProxy:  nil,
	}, {
		name:       "bad_port",
		remoteAddr: theIPStr + ":notport",
		hdrs:       nil,
		wantErr:    "strconv.Atoi: parsing \"notport\": invalid syntax",
		wantIP:     nil,
		wantProxy:  nil,
	}, {
		name:       "bad_host",
		remoteAddr: "host:1",
		hdrs:       nil,
		wantErr:    "invalid ip: host",
		wantIP:     nil,
		wantProxy:  nil,
	}, {
		name:       "bad_proxied_host",
		remoteAddr: "host:1",
		hdrs: map[string]string{
			"CF-Connecting-IP": theIPStr,
		},
		wantErr:   "invalid ip: host",
		wantIP:    nil,
		wantProxy: nil,
	}}

	for _, tc := range testCases {
		r, err := http.NewRequest("GET", "localhost", nil)
		require.NoError(t, err)

		r.RemoteAddr = tc.remoteAddr
		for h, v := range tc.hdrs {
			r.Header.Set(h, v)
		}

		t.Run(tc.name, func(t *testing.T) {
			addr, prx, err := remoteAddr(r)
			if tc.wantErr != "" {
				assert.Equal(t, tc.wantErr, err.Error())

				return
			}

			require.NoError(t, err)

			ip, _ := netutil.IPAndPortFromAddr(addr)
			assert.True(t, ip.Equal(tc.wantIP))

			prxIP, _ := netutil.IPAndPortFromAddr(prx)
			assert.True(t, tc.wantProxy.Equal(prxIP))
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

	httpResp, err := client.Do(req)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, httpResp.Body.Close)

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
		transport = &http3.RoundTripper{
			Dial: func(
				ctx context.Context,
				_ string,
				tlsCfg *tls.Config,
				cfg *quic.Config,
			) (quic.EarlyConnection, error) {
				addr := dnsProxy.Addr(ProtoHTTPS).String()
				return quic.DialAddrEarlyContext(ctx, addr, tlsCfg, cfg)
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

		transport = &http.Transport{
			TLSClientConfig:    tlsClientConfig,
			DisableCompression: true,
			DialContext:        dialContext,
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   defaultTimeout,
	}
}
