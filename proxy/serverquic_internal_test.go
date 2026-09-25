package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_HandleDNSRequest_quicTruncatedRequest(t *testing.T) {
	t.Parallel()

	serverConfig, caPem := dnsproxytest.NewTLSConfig(t)

	conf := &Config{
		Logger:         testLogger,
		QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TLSConfig:      serverConfig,
		UpstreamConfig: newTestUpstreamConfig(t, newTestUpstream(t)),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		RequestHandler: &testHandler{
			OnHandle: func(ctx context.Context, p *Proxy, d *DNSContext) (_ error) {
				panic(testutil.UnexpectedCall(ctx, p, d))
			},
		},
	}

	dnsProxy := mustNew(t, conf)

	req := (&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               0,
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(dnsproxytest.Host),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}).SetEdns0(4096, false)

	packed, err := req.Pack()
	require.NoError(t, err)

	fullBuf := proxyutil.AddPrefix(packed)

	dnsProxy.bytesPool = syncutil.NewPool(func() (v *[]byte) {
		b := make([]byte, 2+dns.MaxMsgSize)
		copy(b, fullBuf)

		return &b
	})

	servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

	addr := dnsProxy.Addr(ProtoQUIC)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPem))

	tlsConfig := &tls.Config{
		ServerName: dnsproxytest.TLSServerName,
		RootCAs:    roots,
		NextProtos: append([]string{NextProtoDQ}, compatProtoDQ...),
	}

	ctx := testutil.ContextWithTimeout(t, dnsproxytest.Timeout)

	conn, err := quic.DialAddrEarly(ctx, addr.String(), tlsConfig, nil)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return conn.CloseWithError(DoQCodeNoError, "")
	})

	truncLen := len(packed) - len(packed)/2
	require.Greater(t, truncLen, 0)

	truncated := packed[:truncLen]
	reqBuf := proxyutil.AddPrefix(truncated)
	require.Greater(t, len(reqBuf), minDNSPacketSize)

	stream, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, stream.Close)

	n, err := stream.Write(reqBuf)
	require.NoError(t, err)

	assert.Greater(t, n, minDNSPacketSize)
}
