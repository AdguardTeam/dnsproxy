package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	proxytest "github.com/AdguardTeam/dnsproxy/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// quicNextProtos is a list of ALPN tokens used by a QUIC connection.
var quicNextProtos = []string{proxy.NextProtoDQ, "doq-i02", "doq-i00", "dq"}

// minDNSPacketSize is the smallest possible DNS packet size.
const minDNSPacketSize = 12 + 5

func TestProxy_HandleDNSRequest_quic(t *testing.T) {
	t.Parallel()

	serverConfig, caPem := dnsproxytest.NewTLSConfig(t)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{
		ServerName: dnsproxytest.TLSServerName,
		RootCAs:    roots,
		NextProtos: quicNextProtos,
	}

	conf := &proxy.Config{
		Logger:         testLogger,
		QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TLSConfig:      serverConfig,
		UpstreamConfig: newTestUpstreamConfig(t),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	}

	var addr *net.UDPAddr
	t.Run("run", func(t *testing.T) {
		addr = testHandleDNSRequestQUIC(t, conf, tlsConfig)
	})
	require.False(t, t.Failed())

	conf.QUICListenAddr = []*net.UDPAddr{addr}
	conf.UpstreamConfig = newTestUpstreamConfig(t)

	require.True(t, t.Run("rerun", func(t *testing.T) {
		testHandleDNSRequestQUIC(t, conf, tlsConfig)
	}))
}

// testHandleDNSRequestQUIC starts a proxy using conf, checks both the current
// and draft DNS-over-QUIC protocols, and returns the proxy's listening address.
func testHandleDNSRequestQUIC(
	tb testing.TB,
	conf *proxy.Config,
	tlsConfig *tls.Config,
) (addr *net.UDPAddr) {
	tb.Helper()

	dnsProxy, err := proxy.New(conf)
	require.NoError(tb, err)

	servicetest.RequireRun(tb, dnsProxy, dnsproxytest.Timeout)

	addr = testutil.RequireTypeAssert[*net.UDPAddr](tb, dnsProxy.Addr(proxy.ProtoQUIC))

	conn, err := quic.DialAddrEarly(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, func() (err error) {
		return conn.CloseWithError(proxy.DoQCodeNoError, "")
	})

	for range 10 {
		sendTestQUICMessage(tb, conn, proxy.DoQv1)
		sendTestQUICMessage(tb, conn, proxy.DoQv1Draft)
	}

	return addr
}

func TestProxy_HandleDNSRequest_quicLargePackets(t *testing.T) {
	onHandle := func(_ context.Context, _ *proxy.Proxy, d *proxy.DNSContext) (err error) {
		d.Res = dnsproxytest.NewTestResponse(d.Req)

		return nil
	}

	reqHandler := &proxytest.Handler{
		OnHandle: onHandle,
	}

	serverConfig, caPem := dnsproxytest.NewTLSConfig(t)
	dnsProxy, err := proxy.New(&proxy.Config{
		Logger:         testLogger,
		UpstreamConfig: newTestUpstreamConfig(t),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		RequestHandler: reqHandler,
		TLSConfig:      serverConfig,
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
	})
	require.NoError(t, err)

	servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{
		ServerName: dnsproxytest.TLSServerName,
		RootCAs:    roots,
		NextProtos: quicNextProtos,
	}

	addr := dnsProxy.Addr(proxy.ProtoQUIC)

	conn, err := quic.DialAddrEarly(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return conn.CloseWithError(proxy.DoQCodeNoError, "")
	})

	msg := dnsproxytest.NewTestRequest()
	msg.Extra = []dns.RR{
		&dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096},
			Option: []dns.EDNS0{
				&dns.EDNS0_PADDING{Padding: make([]byte, 4096)},
			},
		},
	}

	resp := sendQUICMessage(t, msg, conn, proxy.DoQv1)
	dnsproxytest.RequireResponse(t, msg, resp)
}

// sendQUICMessage sends msg to the specified QUIC connection.
func sendQUICMessage(
	tb testing.TB,
	msg *dns.Msg,
	conn *quic.Conn,
	doqVersion proxy.DoQVersion,
) (resp *dns.Msg) {
	stream, err := conn.OpenStreamSync(context.Background())
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, stream.Close)

	packedMsg, err := msg.Pack()
	require.NoError(tb, err)

	buf := packedMsg
	if doqVersion == proxy.DoQv1 {
		buf = proxyutil.AddPrefix(packedMsg)
	}

	writeQUICStream(tb, buf, stream)

	require.NoError(tb, stream.Close())

	respBytes := make([]byte, 64*1024)
	n, err := stream.Read(respBytes)
	if err != nil {
		require.ErrorIs(tb, err, io.EOF)
	}
	require.Greater(tb, n, minDNSPacketSize)

	resp = new(dns.Msg)
	if doqVersion == proxy.DoQv1 {
		err = resp.Unpack(respBytes[2:])
	} else {
		err = resp.Unpack(respBytes)
	}
	require.NoError(tb, err)

	return resp
}

// writeQUICStream writes buf to the specified QUIC stream in chunks.  This way
// it is possible to test how the server deals with chunked DNS messages.
func writeQUICStream(tb testing.TB, buf []byte, stream *quic.Stream) {
	// Send the DNS query to the stream and split it into chunks of up
	// to 400 bytes.  400 is an arbitrary chosen value.
	chunkSize := 400
	for i := 0; i < len(buf); i += chunkSize {
		chunkStart := i
		chunkEnd := min(i+chunkSize, len(buf))

		_, err := stream.Write(buf[chunkStart:chunkEnd])
		require.NoError(tb, err)

		if len(buf) > chunkSize {
			// Emulate network latency.
			time.Sleep(time.Millisecond)
		}
	}
}

// sendTestQUICMessage sends a test message to the specified QUIC connection.
func sendTestQUICMessage(tb testing.TB, conn *quic.Conn, doqVersion proxy.DoQVersion) {
	tb.Helper()

	msg := dnsproxytest.NewTestRequest()
	resp := sendQUICMessage(tb, msg, conn, doqVersion)
	dnsproxytest.RequireResponse(tb, msg, resp)
}
