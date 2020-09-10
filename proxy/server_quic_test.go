package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/miekg/dns"

	"github.com/lucas-clemente/quic-go"
	"github.com/stretchr/testify/assert"
)

func TestQuicProxy(t *testing.T) {
	// Prepare the proxy server
	serverConfig, caPem := createServerTLSConfig(t)
	dnsProxy := createTestProxy(t, serverConfig)

	// Start listening
	err := dnsProxy.Start()
	assert.Nil(t, err)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{
		ServerName: tlsServerName,
		RootCAs:    roots,
		NextProtos: []string{NextProtoDQ},
	}

	// Create a DNS-over-QUIC client connection
	addr := dnsProxy.Addr(ProtoQUIC)

	// Open QUIC session
	sess, err := quic.DialAddr(addr.String(), tlsConfig, nil)
	assert.Nil(t, err)
	defer sess.CloseWithError(0, "")

	// Send several test messages
	for i := 0; i < 10; i++ {
		sendTestQUICMessage(t, sess)
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func sendTestQUICMessage(t *testing.T, sess quic.Session) {
	// Open stream
	stream, err := sess.OpenStreamSync(context.Background())
	assert.Nil(t, err)
	defer stream.Close()

	// Write
	msg := createTestMessage()
	buf, err := msg.Pack()
	assert.Nil(t, err)

	// Send the DNS query
	_, err = stream.Write(buf)
	assert.Nil(t, err)

	// Close closes the write-direction of the stream
	// and sends a STREAM FIN packet.
	stream.Close()

	// Now read the response
	respBytes := make([]byte, 64*1024)
	n, err := stream.Read(respBytes)
	assert.True(t, err == nil || err.Error() == "EOF")
	assert.True(t, n > minDNSPacketSize)

	// Unpack the response
	reply := new(dns.Msg)
	err = reply.Unpack(respBytes)
	assert.Nil(t, err)

	// Check the response
	assertResponse(t, reply)
}
