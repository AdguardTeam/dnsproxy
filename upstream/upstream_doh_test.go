package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestUpstreamDoH(t *testing.T) {
	testCases := []struct {
		name             string
		http3Enabled     bool
		httpVersions     []HTTPVersion
		delayHandshakeH3 time.Duration
		delayHandshakeH2 time.Duration
		expectedProtocol HTTPVersion
	}{{
		name:             "http1.1_h2",
		http3Enabled:     false,
		httpVersions:     []HTTPVersion{HTTPVersion11, HTTPVersion2},
		expectedProtocol: HTTPVersion2,
	}, {
		name:             "fallback_to_http2",
		http3Enabled:     false,
		httpVersions:     []HTTPVersion{HTTPVersion3, HTTPVersion2},
		expectedProtocol: HTTPVersion2,
	}, {
		name:             "http3",
		http3Enabled:     true,
		httpVersions:     []HTTPVersion{HTTPVersion3},
		expectedProtocol: HTTPVersion3,
	}, {
		name:             "race_http3_faster",
		http3Enabled:     true,
		httpVersions:     []HTTPVersion{HTTPVersion3, HTTPVersion2},
		delayHandshakeH2: time.Second,
		expectedProtocol: HTTPVersion3,
	}, {
		name:             "race_http2_faster",
		http3Enabled:     true,
		httpVersions:     []HTTPVersion{HTTPVersion3, HTTPVersion2},
		delayHandshakeH3: time.Second,
		expectedProtocol: HTTPVersion2,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startDoHServer(t, testDoHServerOptions{
				http3Enabled:     tc.http3Enabled,
				delayHandshakeH2: tc.delayHandshakeH2,
				delayHandshakeH3: tc.delayHandshakeH3,
			})
			t.Cleanup(srv.Shutdown)

			// Create a DNS-over-HTTPS upstream.
			address := fmt.Sprintf("https://%s/dns-query", srv.addr)

			var lastState tls.ConnectionState
			u, err := AddressToUpstream(
				address,
				&Options{
					InsecureSkipVerify: true,
					HTTPVersions:       tc.httpVersions,
					VerifyConnection: func(state tls.ConnectionState) (err error) {
						if state.NegotiatedProtocol != string(tc.expectedProtocol) {
							return fmt.Errorf(
								"expected %s, got %s",
								tc.expectedProtocol,
								state.NegotiatedProtocol,
							)
						}
						lastState = state
						return nil
					},
				},
			)
			require.NoError(t, err)

			// Test that it responds properly.
			for i := 0; i < 10; i++ {
				checkUpstream(t, u, address)
			}

			doh := u.(*dnsOverHTTPS)

			// Trigger re-connection.
			doh.client = nil

			// Force it to establish the connection again.
			checkUpstream(t, u, address)

			// Check that TLS session was resumed properly.
			require.True(t, lastState.DidResume)
		})
	}
}

// testDoHServerOptions allows customizing testDoHServer behavior.
type testDoHServerOptions struct {
	http3Enabled     bool
	delayHandshakeH2 time.Duration
	delayHandshakeH3 time.Duration
}

// testDoHServer is an instance of a test DNS-over-HTTPS server that we use
// for tests.
type testDoHServer struct {
	// addr is the address that this server listens to.
	addr string

	// tlsConfig is the TLS configuration that is used for this server.
	tlsConfig *tls.Config

	// server is an HTTP/1.1 and HTTP/2 server.
	server *http.Server

	// serverH3 is an HTTP/3 server.
	serverH3 *http3.Server
}

// Shutdown stops the DOH server.
func (s *testDoHServer) Shutdown() {
	if s.server != nil {
		_ = s.server.Shutdown(context.Background())
	}

	if s.serverH3 != nil {
		_ = s.serverH3.Close()
	}
}

// startDoHServer starts a new DNS-over-HTTPS server on a random port and
// returns the instance of this server.  Depending on whether http3Enabled is
// set to true or false it will or will not initialize a HTTP/3 server.
func startDoHServer(
	t *testing.T,
	opts testDoHServerOptions,
) (s *testDoHServer) {
	tlsConfig := createServerTLSConfig(t, "127.0.0.1")
	handler := createDoHHandler()

	// Step one is to create a regular HTTP server, we'll always have it
	// running.
	server := &http.Server{
		Handler: handler,
	}

	// Listen TCP first.
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tcpListen, err := net.ListenTCP("tcp", tcpAddr)
	require.NoError(t, err)

	tlsConfigH2 := tlsConfig.Clone()
	tlsConfigH2.NextProtos = []string{string(HTTPVersion2), string(HTTPVersion11)}
	tlsConfigH2.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
		if opts.delayHandshakeH2 > 0 {
			time.Sleep(opts.delayHandshakeH2)
		}
		return nil, nil
	}
	tlsListen := tls.NewListener(tcpListen, tlsConfigH2)

	// Run the H1/H2 server.
	go server.Serve(tlsListen)

	// Get the real address that the listener now listens to.
	tcpAddr = tcpListen.Addr().(*net.TCPAddr)

	var serverH3 *http3.Server

	if opts.http3Enabled {
		tlsConfigH3 := tlsConfig.Clone()
		tlsConfigH3.NextProtos = []string{string(HTTPVersion3)}
		tlsConfigH3.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			if opts.delayHandshakeH3 > 0 {
				time.Sleep(opts.delayHandshakeH3)
			}
			return nil, nil
		}

		serverH3 = &http3.Server{
			TLSConfig:  tlsConfig.Clone(),
			QuicConfig: &quic.Config{},
			Handler:    handler,
		}

		// Listen UDP for the H3 server. Reuse the same port as was used for the
		// TCP listener.
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", tcpAddr.Port))
		require.NoError(t, err)

		udpListen, err := net.ListenUDP("udp", udpAddr)
		require.NoError(t, err)

		// Run the H3 server.
		go serverH3.Serve(udpListen)
	}

	return &testDoHServer{
		tlsConfig: tlsConfig,
		server:    server,
		serverH3:  serverH3,
		// Save the address that the server listens to.
		addr: tcpAddr.String(),
	}
}

// createDoHHandler returns a very simple http.Handler that reads the incoming
// request and returns with a test message.
func createDoHHandler() (h http.Handler) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		dnsParam := r.URL.Query().Get("dns")
		buf, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("internal error: %s", err),
				http.StatusInternalServerError,
			)
			return
		}

		m := &dns.Msg{}
		err = m.Unpack(buf)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("internal error: %s", err),
				http.StatusInternalServerError,
			)
			return
		}

		resp := respondToTestMessage(m)

		buf, err = resp.Pack()
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("internal error: %s", err),
				http.StatusInternalServerError,
			)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		_, err = w.Write(buf)
	})

	return mux
}
