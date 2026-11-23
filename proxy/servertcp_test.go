package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/dnsproxytest"
	proxytest "github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_HandleDNSRequest_tcp(t *testing.T) {
	p := newTestProxy(t, nil)
	servicetest.RequireRun(t, p, testTimeout)

	addr := p.Addr(proxy.ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, conn.Close)

	subtestSendTestMessages(t, conn)
}

func TestProxy_HandleDNSRequest_tls(t *testing.T) {
	serverConfig, caPem := proxytest.NewTLSConfig(t)
	dnsProxy := newTestProxy(t, &proxy.Config{
		Logger:         testLogger,
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		TLSConfig:      serverConfig,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(t)},
		},
		TrustedProxies: proxytest.DefaultTrustedProxies,
	})
	servicetest.RequireRun(t, dnsProxy, proxytest.Timeout)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{ServerName: proxytest.TLSServerName, RootCAs: roots}

	// Create a DNS-over-TLS client connection
	addr := dnsProxy.Addr(proxy.ProtoTLS)
	conn, err := dns.DialWithTLS("tcp-tls", addr.String(), tlsConfig)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, conn.Close)

	subtestSendTestMessages(t, conn)
}

func TestProxy_HandleDNSRequest_splitTCPPrefix(t *testing.T) {
	t.Parallel()

	p := newTestProxy(t, nil)
	servicetest.RequireRun(t, p, testTimeout)

	conn := requireDial(t, p.Addr(proxy.ProtoTCP), proxytest.Timeout)

	req := proxytest.NewTestRequest()

	require.True(t, t.Run("send", func(t *testing.T) {
		b, err := req.Pack()
		require.NoError(t, err)

		pkt := make([]byte, 0, 2+len(b))
		pkt = binary.BigEndian.AppendUint16(pkt, uint16(len(b)))
		pkt = append(pkt, b...)

		n, err := conn.Write(pkt[:1])
		require.NoError(t, err)

		assert.Equal(t, 1, n)

		time.Sleep(proxytest.Timeout / 10)

		n, err = conn.Write(pkt[1:])
		require.NoError(t, err)

		assert.Equal(t, len(pkt)-1, n)
	}))

	require.True(t, t.Run("receive", func(t *testing.T) {
		dnsConn := &dns.Conn{Conn: conn}

		resp, err := dnsConn.ReadMsg()
		require.NoError(t, err)

		proxytest.RequireResponse(t, req, resp)
	}))
}

func TestProxy_HandleDNSRequest_emptyTCPMessage(t *testing.T) {
	t.Parallel()

	u := &dnsproxytest.Upstream{
		OnExchange: func(ctx context.Context, m *dns.Msg) (_ *dns.Msg, _ error) {
			panic(testutil.UnexpectedCall(ctx, m))
		},
		OnAddress: func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:   func() (err error) { return nil },
	}
	upsConf := &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{u},
	}

	p := newTestProxy(t, &proxy.Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		UpstreamConfig: upsConf,
		TrustedProxies: proxytest.DefaultTrustedProxies,
	})
	servicetest.RequireRun(t, p, proxytest.Timeout)

	conn := requireDial(t, p.Addr(proxy.ProtoTCP), proxytest.Timeout)

	pkt := binary.BigEndian.AppendUint16(nil, 0)

	_, err := conn.Write(pkt)
	require.NoError(t, err)

	dnsConn := &dns.Conn{Conn: conn}
	_, err = dnsConn.ReadMsg()
	assert.ErrorIs(t, err, io.EOF)
}

func TestProxy_HandleDNSRequest_partialTCPPrefix(t *testing.T) {
	t.Parallel()

	p := newTestProxy(t, nil)
	servicetest.RequireRun(t, p, testTimeout)

	t.Run("bad_conn", func(t *testing.T) {
		t.Parallel()

		conn := requireDial(t, p.Addr(proxy.ProtoTCP), proxytest.Timeout)

		n, err := conn.Write([]byte{0x00})
		require.NoError(t, err)

		assert.Equal(t, 1, n)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		// TODO(e.burkov):  Improve the [subtestSendTestMessages] helper to fit
		// into [proxytest.Timeout].
		conn := requireDial(t, p.Addr(proxy.ProtoTCP), 2*proxytest.Timeout)

		dnsConn := &dns.Conn{Conn: conn}

		subtestSendTestMessages(t, dnsConn)
	})
}
