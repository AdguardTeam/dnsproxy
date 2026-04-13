package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

type countingConn struct {
	net.Conn

	mu           sync.Mutex
	writeCalls   int
	bytesWritten int
}

func (c *countingConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCalls++
	c.bytesWritten += n
	return n, err
}

func (c *countingConn) stats() (calls, bytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeCalls, c.bytesWritten
}

func newTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "dnsproxy-test",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

func newTestProxy() *Proxy {
	return &Proxy{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func tlsPair(t *testing.T) (serverTLS *tls.Conn, serverRaw *countingConn, clientTLS *tls.Conn, cleanup func()) {
	t.Helper()

	srv, cli := net.Pipe()

	serverRaw = &countingConn{Conn: srv}
	serverTLS = tls.Server(serverRaw, newTestTLSConfig(t))
	clientTLS = tls.Client(cli, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})

	var wg sync.WaitGroup
	wg.Add(2)

	var serverErr, clientErr error
	go func() {
		defer wg.Done()
		serverErr = serverTLS.Handshake()
	}()
	go func() {
		defer wg.Done()
		clientErr = clientTLS.Handshake()
	}()
	wg.Wait()

	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}
	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}

	cleanup = func() {
		_ = clientTLS.Close()
		_ = serverTLS.Close()
	}

	return serverTLS, serverRaw, clientTLS, cleanup
}

func TestShutdownTCPConnGracefully_TLS_ClientInitiatedClose_SkipsTLSCloseNotify(t *testing.T) {
	p := newTestProxy()

	serverTLS, raw, clientTLS, cleanup := tlsPair(t)
	defer cleanup()

	// Close the client side gracefully first; the server-side shutdown should
	// avoid sending its own close_notify once clientInitiatedClose is known.
	_ = clientTLS.Close()

	// Reset stats after handshake and the client's close_notify.
	raw.mu.Lock()
	raw.writeCalls = 0
	raw.bytesWritten = 0
	raw.mu.Unlock()

	p.shutdownTCPConnGracefully(context.Background(), serverTLS, ProtoTLS, true)

	calls, bytes := raw.stats()
	if calls != 0 || bytes != 0 {
		t.Fatalf("expected no server TLS writes after client-initiated close, got calls=%d bytes=%d", calls, bytes)
	}
}

func TestShutdownTCPConnGracefully_TLS_DefaultPath_SendsTLSCloseNotify(t *testing.T) {
	p := newTestProxy()

	serverTLS, raw, _, cleanup := tlsPair(t)
	defer cleanup()

	// Reset stats after handshake.
	raw.mu.Lock()
	raw.writeCalls = 0
	raw.bytesWritten = 0
	raw.mu.Unlock()

	p.shutdownTCPConnGracefully(context.Background(), serverTLS, ProtoTLS, false)

	calls, bytes := raw.stats()
	if calls == 0 {
		t.Fatalf("expected server TLS close_notify write on default path, got calls=%d bytes=%d", calls, bytes)
	}
}
