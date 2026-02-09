package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestQuicProxy(t *testing.T) {
	serverConfig, caPem := newTLSConfig(t)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{
		ServerName: tlsServerName,
		RootCAs:    roots,
		NextProtos: append([]string{NextProtoDQ}, compatProtoDQ...),
	}

	conf := &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		QUICListenAddr:         []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TLSConfig:              serverConfig,
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
	}

	var addr *net.UDPAddr
	t.Run("run", func(t *testing.T) {
		dnsProxy := mustNew(t, conf)

		servicetest.RequireRun(t, dnsProxy, testTimeout)

		addr = testutil.RequireTypeAssert[*net.UDPAddr](t, dnsProxy.Addr(ProtoQUIC))

		conn, err := quic.DialAddrEarly(context.Background(), addr.String(), tlsConfig, nil)
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, func() (err error) {
			return conn.CloseWithError(DoQCodeNoError, "")
		})

		for range 10 {
			sendTestQUICMessage(t, conn, DoQv1)

			// Send a message encoded for a draft version as well.
			sendTestQUICMessage(t, conn, DoQv1Draft)
		}
	})
	require.False(t, t.Failed())

	conf.QUICListenAddr = []*net.UDPAddr{addr}
	conf.UpstreamConfig = newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr)

	t.Run("rerun", func(t *testing.T) {
		dnsProxy := mustNew(t, conf)

		servicetest.RequireRun(t, dnsProxy, testTimeout)

		conn, err := quic.DialAddrEarly(context.Background(), addr.String(), tlsConfig, nil)
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, func() (err error) {
			return conn.CloseWithError(DoQCodeNoError, "")
		})

		sendTestQUICMessage(t, conn, DoQv1)

		// Send a message encoded for a draft version as well.
		sendTestQUICMessage(t, conn, DoQv1Draft)
	})
}

func TestQuicProxy_largePackets(t *testing.T) {
	reqHandler := &TestHandler{
		OnHandle: func(_ *Proxy, d *DNSContext) (err error) {
			d.Res = newTestResponse(d)

			return nil
		},
	}

	serverConfig, caPem := newTLSConfig(t)
	dnsProxy := mustNew(t, &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:         defaultTrustedProxies,
		RequestHandler:         reqHandler,
		TLSConfig:              serverConfig,
		TLSListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		HTTPSListenAddr:        []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		QUICListenAddr:         []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
	})

	servicetest.RequireRun(t, dnsProxy, testTimeout)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{
		ServerName: tlsServerName,
		RootCAs:    roots,
		NextProtos: append([]string{NextProtoDQ}, compatProtoDQ...),
	}

	// Create a DNS-over-QUIC client connection.
	addr := dnsProxy.Addr(ProtoQUIC)

	// Open a QUIC connection.
	conn, err := quic.DialAddrEarly(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return conn.CloseWithError(DoQCodeNoError, "")
	})

	// Create a test message large enough to take multiple QUIC frames.
	msg := newTestMessage()
	msg.Extra = []dns.RR{
		&dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096},
			Option: []dns.EDNS0{
				&dns.EDNS0_PADDING{Padding: make([]byte, 4096)},
			},
		},
	}

	resp := sendQUICMessage(t, msg, conn, DoQv1)
	requireResponse(t, msg, resp)
}

// newTestResponse creates a test response for the specified request.
func newTestResponse(d *DNSContext) (resp *dns.Msg) {
	resp = &dns.Msg{}
	resp.SetReply(d.Req)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   d.Req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
		},
		A: net.IP{8, 8, 8, 8},
	}}

	return resp
}

// sendQUICMessage sends msg to the specified QUIC connection.
func sendQUICMessage(
	t *testing.T,
	msg *dns.Msg,
	conn *quic.Conn,
	doqVersion DoQVersion,
) (resp *dns.Msg) {
	// Open a new QUIC stream to write there a test DNS query.
	stream, err := conn.OpenStreamSync(context.Background())
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, stream.Close)

	packedMsg, err := msg.Pack()
	require.NoError(t, err)

	buf := packedMsg
	if doqVersion == DoQv1 {
		buf = proxyutil.AddPrefix(packedMsg)
	}

	// Send the DNS query to the stream.
	err = writeQUICStream(buf, stream)
	require.NoError(t, err)

	// Close closes the write-direction of the stream and sends
	// a STREAM FIN packet.
	_ = stream.Close()

	// Now read the response from the stream.
	respBytes := make([]byte, 64*1024)
	n, err := stream.Read(respBytes)
	if err != nil {
		require.ErrorIs(t, err, io.EOF)
	}
	require.Greater(t, n, minDNSPacketSize)

	// Unpack the DNS response.
	resp = new(dns.Msg)
	if doqVersion == DoQv1 {
		err = resp.Unpack(respBytes[2:])
	} else {
		err = resp.Unpack(respBytes)
	}
	require.NoError(t, err)

	return resp
}

// writeQUICStream writes buf to the specified QUIC stream in chunks.  This way
// it is possible to test how the server deals with chunked DNS messages.
func writeQUICStream(buf []byte, stream *quic.Stream) (err error) {
	// Send the DNS query to the stream and split it into chunks of up
	// to 400 bytes.  400 is an arbitrary chosen value.
	chunkSize := 400
	for i := 0; i < len(buf); i += chunkSize {
		chunkStart := i
		chunkEnd := i + chunkSize
		if chunkEnd > len(buf) {
			chunkEnd = len(buf)
		}

		_, err = stream.Write(buf[chunkStart:chunkEnd])
		if err != nil {
			return err
		}

		if len(buf) > chunkSize {
			// Emulate network latency.
			time.Sleep(time.Millisecond)
		}
	}

	return nil
}

// sendTestQUICMessage send a test message to the specified QUIC connection.
func sendTestQUICMessage(t *testing.T, conn *quic.Conn, doqVersion DoQVersion) {
	msg := newTestMessage()
	resp := sendQUICMessage(t, msg, conn, doqVersion)
	requireResponse(t, msg, resp)
}
