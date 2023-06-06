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
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestQuicProxy(t *testing.T) {
	// Prepare the proxy server.
	serverConfig, caPem := createServerTLSConfig(t)
	dnsProxy := createTestProxy(t, serverConfig)
	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

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

	// Open a QUIC connection.
	conn, err := quic.DialAddrEarly(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return conn.CloseWithError(DoQCodeNoError, "")
	})

	// Send several test messages.
	for i := 0; i < 10; i++ {
		sendTestQUICMessage(t, conn, DoQv1)

		// Send a message encoded for a draft version as well.
		sendTestQUICMessage(t, conn, DoQv1Draft)
	}
}

func TestQuicProxy_largePackets(t *testing.T) {
	// Prepare the proxy server.
	serverConfig, caPem := createServerTLSConfig(t)
	dnsProxy := createTestProxy(t, serverConfig)

	// Make sure the request does not go to any real upstream.
	dnsProxy.RequestHandler = func(p *Proxy, d *DNSContext) (err error) {
		resp := &dns.Msg{}
		resp.SetReply(d.Req)
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   d.Req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
				},
				A: net.IP{8, 8, 8, 8},
			},
		}
		d.Res = resp

		return nil
	}

	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

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

	// Open a QUIC connection.
	conn, err := quic.DialAddrEarly(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return conn.CloseWithError(DoQCodeNoError, "")
	})

	// Create a test message large enough to take multiple QUIC frames.
	msg := createTestMessage()
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

// sendQUICMessage sends msg to the specified QUIC connection.
func sendQUICMessage(
	t *testing.T,
	msg *dns.Msg,
	conn quic.Connection,
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
func writeQUICStream(buf []byte, stream quic.Stream) (err error) {
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
func sendTestQUICMessage(t *testing.T, conn quic.Connection, doqVersion DoQVersion) {
	msg := createTestMessage()
	resp := sendQUICMessage(t, msg, conn, doqVersion)
	requireResponse(t, msg, resp)
}
