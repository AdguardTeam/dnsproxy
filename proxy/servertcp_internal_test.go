package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestTcpProxy(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	// Create a DNS-over-TCP client connection
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)

	sendTestMessages(t, conn)
}

func TestTlsProxy(t *testing.T) {
	serverConfig, caPem := newTLSConfig(t)
	dnsProxy := mustNew(t, &Config{
		Logger:          testLogger,
		TLSListenAddr:   []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		HTTPSListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		QUICListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TLSConfig:       serverConfig,
		UpstreamConfig:  newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:  defaultTrustedProxies,
	})

	servicetest.RequireRun(t, dnsProxy, testTimeout)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{ServerName: tlsServerName, RootCAs: roots}

	// Create a DNS-over-TLS client connection
	addr := dnsProxy.Addr(ProtoTLS)
	conn, err := dns.DialWithTLS("tcp-tls", addr.String(), tlsConfig)
	require.NoError(t, err)

	sendTestMessages(t, conn)
}
