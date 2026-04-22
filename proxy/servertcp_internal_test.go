package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestProxy_tcp(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	// Create a DNS-over-TCP client connection
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)

	sendTestMessages(t, conn)
}

func TestProxy_tls(t *testing.T) {
	serverConfig, caPem := newTLSConfig(t)
	dnsProxy := mustNew(t, &Config{
		Logger:         testLogger,
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TLSConfig:      serverConfig,
		UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies: defaultTrustedProxies,
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

func TestProxy_tcpProxyProtocolV2_RequiredHeader(t *testing.T) {
	dnsProxy := mustNew(t, &Config{
		Logger:                    testLogger,
		TCPListenAddr:             []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:            newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:            defaultTrustedProxies,
		TCPProxyProtocolV2Enabled: true,
	})
	servicetest.RequireRun(t, dnsProxy, testTimeout)

	addr := dnsProxy.Addr(ProtoTCP).String()

	t.Run("reject_without_header", func(t *testing.T) {
		conn, err := dns.Dial("tcp", addr)
		require.NoError(t, err)
		defer conn.Close()
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(testTimeout)))

		err = conn.WriteMsg(newTestMessage())
		require.NoError(t, err)

		_, err = conn.ReadMsg()
		require.Error(t, err)
	})

	t.Run("accept_with_header", func(t *testing.T) {
		rawConn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer rawConn.Close()

		src := netutil.NetAddrToAddrPort(rawConn.LocalAddr())
		dst := netutil.NetAddrToAddrPort(rawConn.RemoteAddr())
		_, err = rawConn.Write(proxyProtocolV2Header(src, dst))
		require.NoError(t, err)

		sendTestMessages(t, &dns.Conn{Conn: rawConn})
	})
}

func TestProxy_tcpProxyProtocolV2_DisabledRejectsHeader(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	rawConn, err := net.Dial("tcp", dnsProxy.Addr(ProtoTCP).String())
	require.NoError(t, err)
	defer rawConn.Close()

	src := netutil.NetAddrToAddrPort(rawConn.LocalAddr())
	dst := netutil.NetAddrToAddrPort(rawConn.RemoteAddr())
	_, err = rawConn.Write(proxyProtocolV2Header(src, dst))
	require.NoError(t, err)

	dnsConn := &dns.Conn{Conn: rawConn}
	require.NoError(t, dnsConn.SetReadDeadline(time.Now().Add(testTimeout)))
	err = dnsConn.WriteMsg(newTestMessage())
	require.NoError(t, err)

	_, err = dnsConn.ReadMsg()
	require.Error(t, err)
}

func TestProxy_tcpProxyProtocolV2_RejectsUntrustedProxy(t *testing.T) {
	dnsProxy := mustNew(t, &Config{
		Logger:                    testLogger,
		TCPListenAddr:             []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:            newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TCPProxyProtocolV2Enabled: true,
		TrustedProxies:            nil,
	})
	servicetest.RequireRun(t, dnsProxy, testTimeout)

	rawConn, err := net.Dial("tcp", dnsProxy.Addr(ProtoTCP).String())
	require.NoError(t, err)
	defer rawConn.Close()

	src := netutil.NetAddrToAddrPort(rawConn.LocalAddr())
	dst := netutil.NetAddrToAddrPort(rawConn.RemoteAddr())
	_, err = rawConn.Write(proxyProtocolV2Header(src, dst))
	require.NoError(t, err)

	dnsConn := &dns.Conn{Conn: rawConn}
	require.NoError(t, dnsConn.SetReadDeadline(time.Now().Add(testTimeout)))
	err = dnsConn.WriteMsg(newTestMessage())
	require.NoError(t, err)

	_, err = dnsConn.ReadMsg()
	require.Error(t, err)
}

func TestProxy_tlsProxyProtocolV2_Strict(t *testing.T) {
	serverConfig, caPem := newTLSConfig(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	clientTLSConf := &tls.Config{ServerName: tlsServerName, RootCAs: roots}

	dnsProxy := mustNew(t, &Config{
		Logger:                    testLogger,
		TLSListenAddr:             []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		TLSConfig:                 serverConfig,
		UpstreamConfig:            newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:            defaultTrustedProxies,
		TLSProxyProtocolV2Enabled: true,
	})
	servicetest.RequireRun(t, dnsProxy, testTimeout)

	addr := dnsProxy.Addr(ProtoTLS).String()

	t.Run("reject_without_header", func(t *testing.T) {
		rawConn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer rawConn.Close()

		tlsConn := tls.Client(rawConn, clientTLSConf)
		require.NoError(t, tlsConn.SetDeadline(time.Now().Add(testTimeout)))
		err = tlsConn.Handshake()
		require.Error(t, err)
	})

	t.Run("accept_with_header", func(t *testing.T) {
		rawConn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer rawConn.Close()

		src := netutil.NetAddrToAddrPort(rawConn.LocalAddr())
		dst := netutil.NetAddrToAddrPort(rawConn.RemoteAddr())
		_, err = rawConn.Write(proxyProtocolV2Header(src, dst))
		require.NoError(t, err)

		tlsConn := tls.Client(rawConn, clientTLSConf)
		err = tlsConn.Handshake()
		require.NoError(t, err)

		sendTestMessages(t, &dns.Conn{Conn: tlsConn})
	})
}

func TestProxy_tlsProxyProtocolV2_DisabledRejectsHeader(t *testing.T) {
	serverConfig, caPem := newTLSConfig(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	clientTLSConf := &tls.Config{ServerName: tlsServerName, RootCAs: roots}

	dnsProxy := mustNew(t, &Config{
		Logger:         testLogger,
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		TLSConfig:      serverConfig,
		UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies: defaultTrustedProxies,
	})
	servicetest.RequireRun(t, dnsProxy, testTimeout)

	rawConn, err := net.Dial("tcp", dnsProxy.Addr(ProtoTLS).String())
	require.NoError(t, err)
	defer rawConn.Close()

	src := netutil.NetAddrToAddrPort(rawConn.LocalAddr())
	dst := netutil.NetAddrToAddrPort(rawConn.RemoteAddr())
	_, err = rawConn.Write(proxyProtocolV2Header(src, dst))
	require.NoError(t, err)

	tlsConn := tls.Client(rawConn, clientTLSConf)
	require.NoError(t, tlsConn.SetDeadline(time.Now().Add(testTimeout)))
	err = tlsConn.Handshake()
	require.Error(t, err)
}

func proxyProtocolV2Header(src, dst netip.AddrPort) (hdr []byte) {
	srcAddr := src.Addr().Unmap()
	dstAddr := dst.Addr().Unmap()

	var famProto byte
	var addrPayload []byte
	switch {
	case srcAddr.Is4() && dstAddr.Is4():
		famProto = 0x11
		addrPayload = make([]byte, 12)
		copy(addrPayload[:4], srcAddr.AsSlice())
		copy(addrPayload[4:8], dstAddr.AsSlice())
		binary.BigEndian.PutUint16(addrPayload[8:10], src.Port())
		binary.BigEndian.PutUint16(addrPayload[10:12], dst.Port())
	case srcAddr.Is6() && dstAddr.Is6():
		famProto = 0x21
		addrPayload = make([]byte, 36)
		copy(addrPayload[:16], srcAddr.AsSlice())
		copy(addrPayload[16:32], dstAddr.AsSlice())
		binary.BigEndian.PutUint16(addrPayload[32:34], src.Port())
		binary.BigEndian.PutUint16(addrPayload[34:36], dst.Port())
	default:
		panic("source and destination address families must match")
	}

	hdr = make([]byte, proxyProtocolV2HeaderLen+len(addrPayload))
	copy(hdr[:len(proxyProtocolV2Signature)], proxyProtocolV2Signature[:])
	hdr[12] = 0x21
	hdr[13] = famProto
	binary.BigEndian.PutUint16(hdr[14:16], uint16(len(addrPayload)))
	copy(hdr[16:], addrPayload)

	return hdr
}
