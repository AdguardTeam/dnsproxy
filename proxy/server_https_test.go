package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHttpsProxy(t *testing.T) {
	// Prepare the proxy server.
	tlsConf, caPem := createServerTLSConfig(t)
	dnsProxy := createTestProxy(t, tlsConf)

	var gotAddr net.Addr
	dnsProxy.RequestHandler = func(_ *Proxy, d *DNSContext) (err error) {
		gotAddr = d.Addr

		return dnsProxy.Resolve(d)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caPem)
	require.True(t, ok)

	dialer := &net.Dialer{
		Timeout: defaultTimeout,
	}
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Route request to the DNS-over-HTTPS server address.
		return dialer.DialContext(ctx, network, dnsProxy.Addr(ProtoHTTPS).String())
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: tlsServerName,
			RootCAs:    roots,
		},
		DisableCompression: true,
		DialContext:        dialContext,
	}
	client := http.Client{
		Transport: transport,
		Timeout:   defaultTimeout,
	}

	clientIP, proxyIP := net.IP{1, 2, 3, 4}, net.IP{127, 0, 0, 1}
	msg := createTestMessage()

	doRequest := func(t *testing.T, proxyAddr string) (reply *dns.Msg) {
		dnsProxy.TrustedProxies = []string{proxyAddr}

		// Start listening.
		serr := dnsProxy.Start()
		require.NoError(t, serr)
		t.Cleanup(func() {
			derr := dnsProxy.Stop()
			require.NoError(t, derr)
		})

		packed, err := msg.Pack()
		require.NoError(t, err)

		b := bytes.NewBuffer(packed)
		req, err := http.NewRequest("POST", "https://test.com", b)
		require.NoError(t, err)

		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		// IP "1.2.3.4" will be used as a client address in DNSContext.
		req.Header.Set("X-Forwarded-For", strings.Join(
			[]string{clientIP.String(), proxyIP.String()},
			",",
		))

		resp, err := client.Do(req)
		require.NoError(t, err)

		if resp != nil && resp.Body != nil {
			t.Cleanup(func() {
				resp.Body.Close()
			})
		}

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		reply = &dns.Msg{}
		err = reply.Unpack(body)
		require.NoError(t, err)

		return reply
	}

	t.Run("success", func(t *testing.T) {
		reply := doRequest(t, proxyIP.String())

		assertResponse(t, reply)
		assert.True(t, ipFromAddr(gotAddr).Equal(clientIP))
	})

	t.Run("not_in_trusted", func(t *testing.T) {
		reply := doRequest(t, "127.0.0.2")

		assertResponse(t, reply)
		assert.True(t, ipFromAddr(gotAddr).Equal(proxyIP))
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

			assert.True(t, ipFromAddr(addr).Equal(tc.wantIP))
			assert.True(t, tc.wantProxy.Equal(ipFromAddr(prx)))
		})
	}
}
