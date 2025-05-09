package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestUpstreamDoH(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		expectedProtocol HTTPVersion
		httpVersions     []HTTPVersion
		delayHandshakeH3 time.Duration
		delayHandshakeH2 time.Duration
		http3Enabled     bool
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
			t.Parallel()

			srv := startDoHServer(t, testDoHServerOptions{
				http3Enabled:     tc.http3Enabled,
				delayHandshakeH2: tc.delayHandshakeH2,
				delayHandshakeH3: tc.delayHandshakeH3,
			})

			// Create a DNS-over-HTTPS upstream.
			address := fmt.Sprintf("https://%s/dns-query", srv.addr)

			var lastState tls.ConnectionState
			opts := &Options{
				Logger:             slogutil.NewDiscardLogger(),
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
			}
			u, err := AddressToUpstream(address, opts)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			// Test that it responds properly.
			for range 10 {
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

func TestUpstreamDoH_raceReconnect(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		expectedProtocol HTTPVersion
		httpVersions     []HTTPVersion
		delayHandshakeH3 time.Duration
		delayHandshakeH2 time.Duration
		http3Enabled     bool
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

	// This is a different set of tests that are supposed to be run with -race.
	// The difference is that the HTTP handler here adds additional time.Sleep
	// call.  This call would trigger the HTTP client re-connection which is
	// important to test for race conditions.
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			const timeout = time.Millisecond * 100
			var requestsCount int32

			handlerFunc := createDoHHandlerFunc()
			mux := http.NewServeMux()
			mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
				newVal := atomic.AddInt32(&requestsCount, 1)
				if newVal%10 == 0 {
					time.Sleep(timeout * 2)
				}
				handlerFunc(w, r)
			})

			srv := startDoHServer(t, testDoHServerOptions{
				http3Enabled:     tc.http3Enabled,
				delayHandshakeH2: tc.delayHandshakeH2,
				delayHandshakeH3: tc.delayHandshakeH3,
				handler:          mux,
			})

			// Create a DNS-over-HTTPS upstream that will be used for the
			// race test.
			address := fmt.Sprintf("https://%s/dns-query", srv.addr)
			opts := &Options{
				Logger:             slogutil.NewDiscardLogger(),
				InsecureSkipVerify: true,
				HTTPVersions:       tc.httpVersions,
				Timeout:            timeout,
			}
			u, err := AddressToUpstream(address, opts)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			checkRaceCondition(u)
		})
	}
}

func TestUpstreamDoH_serverRestart(t *testing.T) {
	testCases := []struct {
		name         string
		httpVersions []HTTPVersion
	}{{
		name:         "http2",
		httpVersions: []HTTPVersion{HTTPVersion11, HTTPVersion2},
	}, {
		name:         "http3",
		httpVersions: []HTTPVersion{HTTPVersion3},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var addr netip.AddrPort
			var upsAddr string
			var u Upstream

			t.Run("first_try", func(t *testing.T) {
				srv := startDoHServer(t, testDoHServerOptions{
					http3Enabled: true,
				})

				addr = netip.MustParseAddrPort(srv.addr)
				upsAddr = (&url.URL{
					Scheme: "https",
					Host:   addr.String(),
					Path:   "dns-query",
				}).String()

				var err error
				u, err = AddressToUpstream(upsAddr, &Options{
					Logger:             slogutil.NewDiscardLogger(),
					InsecureSkipVerify: true,
					HTTPVersions:       tc.httpVersions,
					Timeout:            100 * time.Millisecond,
				})
				require.NoError(t, err)

				checkUpstream(t, u, upsAddr)
			})
			require.False(t, t.Failed())
			testutil.CleanupAndRequireSuccess(t, u.Close)

			t.Run("second_try", func(t *testing.T) {
				_ = startDoHServer(t, testDoHServerOptions{
					http3Enabled: true,
					port:         int(addr.Port()),
				})

				checkUpstream(t, u, upsAddr)
			})
			require.False(t, t.Failed())

			t.Run("retry", func(t *testing.T) {
				_, err := u.Exchange(createTestMessage())
				require.Error(t, err)

				_ = startDoHServer(t, testDoHServerOptions{
					http3Enabled: true,
					port:         int(addr.Port()),
				})

				checkUpstream(t, u, upsAddr)
			})
		})
	}
}

func TestUpstreamDoH_0RTT(t *testing.T) {
	t.Parallel()

	// Run the first server instance.
	srv := startDoHServer(t, testDoHServerOptions{
		http3Enabled: true,
	})

	// Create a DNS-over-HTTPS upstream.
	tracer := &quicTracer{}
	address := fmt.Sprintf("h3://%s/dns-query", srv.addr)
	u, err := AddressToUpstream(address, &Options{
		Logger:             slogutil.NewDiscardLogger(),
		InsecureSkipVerify: true,
		QUICTracer:         tracer.TracerForConnection,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	uh := u.(*dnsOverHTTPS)
	req := createTestMessage()

	// Trigger connection to a DoH3 server.
	resp, err := uh.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, resp)

	// Close the active connection to make sure we'll reconnect.
	func() {
		uh.clientMu.Lock()
		defer uh.clientMu.Unlock()

		err = uh.closeClient(uh.client)
		require.NoError(t, err)

		uh.client = nil
	}()

	// Trigger second connection.
	resp, err = uh.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, resp)

	// Check traced connections info.
	conns := tracer.getConnectionsInfo()
	require.Len(t, conns, 2)

	// Examine the first connection (no 0-RTT there).
	require.False(t, conns[0].is0RTT())

	// Examine the second connection (the one that used 0-RTT).
	require.True(t, conns[1].is0RTT())
}

// testDoHServerOptions allows customizing testDoHServer behavior.
type testDoHServerOptions struct {
	// handler is an HTTP handler that should be used by the server.  The
	// default one is used on nil.
	handler http.Handler
	// delayHandshakeH2 is a delay that should be added to the handshake of the
	// HTTP/2 server.
	delayHandshakeH2 time.Duration
	// delayHandshakeH3 is a delay that should be added to the handshake of the
	// HTTP/3 server.
	delayHandshakeH3 time.Duration
	// port is the port that the server should listen to.  If it's 0, a random
	// port is used.
	port int
	// http3Enabled is a flag that indicates whether the server should start an
	// HTTP/3 server.
	http3Enabled bool
}

// testDoHServer is an instance of a test DNS-over-HTTPS server.
type testDoHServer struct {
	// tlsConfig is the TLS configuration that is used for this server.
	tlsConfig *tls.Config

	// rootCAs is the pool with root certificates used by the test server.
	rootCAs *x509.CertPool

	// server is an HTTP/1.1 and HTTP/2 server.
	server *http.Server

	// serverH3 is an HTTP/3 server.
	serverH3 *http3.Server

	// listenerH3 that's used to serve HTTP/3.
	listenerH3 *quic.EarlyListener

	// addr is the address that this server listens to.
	addr string
}

// Shutdown stops the DoH server.
func (s *testDoHServer) Shutdown() {
	if s.server != nil {
		_ = s.server.Shutdown(context.Background())
	}

	if s.serverH3 != nil {
		_ = s.serverH3.Close()
		_ = s.listenerH3.Close()
	}
}

// startDoHServer starts a new DNS-over-HTTPS server with specified options.  It
// returns a started server instance with addr set.  Note that it adds its own
// shutdown to cleanup of t.
func startDoHServer(
	t *testing.T,
	opts testDoHServerOptions,
) (s *testDoHServer) {
	tlsConfig, rootCAs := createServerTLSConfig(t, "127.0.0.1")
	handler := opts.handler
	if handler == nil {
		handler = createDoHHandler()
	}

	// Step one is to create a regular HTTP server, we'll always have it
	// running.
	server := &http.Server{
		Handler:     handler,
		ReadTimeout: time.Second,
		ErrorLog:    slog.NewLogLogger(slog.DiscardHandler, slog.LevelDebug),
	}

	// Listen TCP first.
	listenAddr := fmt.Sprintf("127.0.0.1:%d", opts.port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
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
	go func() {
		// TODO(ameshkov): check the error here.
		_ = server.Serve(tlsListen)
	}()

	// Get the real address that the listener now listens to.
	tcpAddr = tcpListen.Addr().(*net.TCPAddr)

	var serverH3 *http3.Server
	var listenerH3 *quic.EarlyListener

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
			Handler: handler,
		}

		// Listen UDP for the H3 server. Reuse the same port as was used for the
		// TCP listener.
		var udpAddr *net.UDPAddr
		udpAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", tcpAddr.Port))
		require.NoError(t, err)

		var conn net.PacketConn
		conn, err = net.ListenUDP("udp", udpAddr)
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, conn.Close)

		transport := &quic.Transport{
			Conn:                conn,
			VerifySourceAddress: func(net.Addr) bool { return false },
		}

		// QUIC configuration with the 0-RTT support enabled by default.
		listenerH3, err = transport.ListenEarly(tlsConfigH3, &quic.Config{
			Allow0RTT: true,
		})
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, transport.Close)

		// Run the H3 server.
		go func() {
			// TODO(ameshkov): check the error here.
			_ = serverH3.ServeListener(listenerH3)
		}()
	}

	s = &testDoHServer{
		tlsConfig:  tlsConfig,
		rootCAs:    rootCAs,
		server:     server,
		serverH3:   serverH3,
		listenerH3: listenerH3,
		// Save the address that the server listens to.
		addr: tcpAddr.String(),
	}
	t.Cleanup(s.Shutdown)

	return s
}

// createDoHHandlerFunc creates a simple http.HandlerFunc that reads the
// incoming DNS message and returns the test response.
func createDoHHandlerFunc() (f http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if err != nil {
			panic(fmt.Errorf("unexpected error on writing response: %w", err))
		}
	}
}

// createDoHHandler returns a very simple http.Handler that reads the incoming
// request and returns with a test message.
func createDoHHandler() (h http.Handler) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", createDoHHandlerFunc())

	return mux
}
