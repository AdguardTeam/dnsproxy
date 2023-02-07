package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"testing"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestQuicProxy(t *testing.T) {
	// Prepare the proxy server.
	serverConfig, caPem := createServerTLSConfig(t)
	dnsProxy := createTestProxy(t, serverConfig)

	// Start listening.
	err := dnsProxy.Start()
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{
		ServerName: tlsServerName,
		RootCAs:    roots,
		NextProtos: append([]string{NextProtoDQ}, compatProtoDQ...),
	}

	// Create a DNS-over-QUIC client connection.
	addr := dnsProxy.Addr(ProtoQUIC)

	// Open QUIC connection.
	conn, err := quic.DialAddrEarly(addr.String(), tlsConfig, nil)
	require.NoError(t, err)
	defer func() {
		// TODO(ameshkov): check the error here.
		_ = conn.CloseWithError(DoQCodeNoError, "")
	}()

	// Send several test messages.
	for i := 0; i < 10; i++ {
		sendTestQUICMessage(t, conn, DoQv1)

		// Send a message encoded for a draft version as well.
		sendTestQUICMessage(t, conn, DoQv1Draft)
	}

	// Stop the proxy.
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

// sendTestQUICMessage send a test message to the specified QUIC connection.
func sendTestQUICMessage(t *testing.T, conn quic.Connection, doqVersion DoQVersion) {
	// Open a new stream.
	stream, err := conn.OpenStreamSync(context.Background())
	require.NoError(t, err)
	defer stream.Close()

	// Prepare a test message.
	msg := createTestMessage()
	packedMsg, err := msg.Pack()
	require.NoError(t, err)

	buf := packedMsg
	if doqVersion == DoQv1 {
		buf = proxyutil.AddPrefix(packedMsg)
	}

	// Send the DNS query to the stream.
	_, err = stream.Write(buf)
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
	reply := new(dns.Msg)
	if doqVersion == DoQv1 {
		err = reply.Unpack(respBytes[2:])
	} else {
		err = reply.Unpack(respBytes)
	}
	require.NoError(t, err)

	// Check the response
	requireResponse(t, msg, reply)
}
