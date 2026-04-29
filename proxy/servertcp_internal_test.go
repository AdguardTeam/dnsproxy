package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
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
		defer func() { require.NoError(t, conn.Close()) }()
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(testTimeout)))

		err = conn.WriteMsg(newTestMessage())
		require.NoError(t, err)

		_, err = conn.ReadMsg()
		require.Error(t, err)
	})

	t.Run("accept_with_header", func(t *testing.T) {
		rawConn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer func() { require.NoError(t, rawConn.Close()) }()

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
	defer func() { require.NoError(t, rawConn.Close()) }()

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
	defer func() { require.NoError(t, rawConn.Close()) }()

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
		defer func() { require.NoError(t, rawConn.Close()) }()

		tlsConn := tls.Client(rawConn, clientTLSConf)
		require.NoError(t, tlsConn.SetDeadline(time.Now().Add(testTimeout)))
		err = tlsConn.Handshake()
		require.Error(t, err)
	})

	t.Run("accept_with_header", func(t *testing.T) {
		rawConn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer func() { require.NoError(t, rawConn.Close()) }()

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
	defer func() { require.NoError(t, rawConn.Close()) }()

	src := netutil.NetAddrToAddrPort(rawConn.LocalAddr())
	dst := netutil.NetAddrToAddrPort(rawConn.RemoteAddr())
	_, err = rawConn.Write(proxyProtocolV2Header(src, dst))
	require.NoError(t, err)

	tlsConn := tls.Client(rawConn, clientTLSConf)
	require.NoError(t, tlsConn.SetDeadline(time.Now().Add(testTimeout)))
	err = tlsConn.Handshake()
	require.Error(t, err)
}

func TestProxy_tlsProxyProtocolV2_SlowConnCanBlockNextConn(t *testing.T) {
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
		MaxGoroutines:             1,
	})
	servicetest.RequireRun(t, dnsProxy, testTimeout)

	addr := dnsProxy.Addr(ProtoTLS).String()

	// First connection occupies the only request slot by sending an incomplete
	// PPv2 preface and stalling before request handling.
	slowConn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = slowConn.Close() }()

	_, err = slowConn.Write([]byte{0x0d})
	require.NoError(t, err)

	// Keep the first conn active for much longer than the PPv2 pre-read timeout.
	// After the fix, this should no longer gate subsequent connections for the
	// full hold duration.
	hold := 5 * time.Second
	time.AfterFunc(hold, func() { _ = slowConn.Close() })

	secondRawConn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = secondRawConn.Close() }()

	src := netutil.NetAddrToAddrPort(secondRawConn.LocalAddr())
	dst := netutil.NetAddrToAddrPort(secondRawConn.RemoteAddr())
	_, err = secondRawConn.Write(proxyProtocolV2Header(src, dst))
	require.NoError(t, err)

	start := time.Now()
	secondTLSConn := tls.Client(secondRawConn, clientTLSConf)
	err = secondTLSConn.Handshake()
	require.NoError(t, err)

	dnsConn := &dns.Conn{Conn: secondTLSConn}
	require.NoError(t, dnsConn.SetDeadline(time.Now().Add(testTimeout)))
	err = dnsConn.WriteMsg(newTestMessage())
	require.NoError(t, err)

	_, err = dnsConn.ReadMsg()
	require.NoError(t, err)

	elapsed := time.Since(start)
	require.Less(
		t,
		elapsed,
		700*time.Millisecond,
		fmt.Sprintf("expected second connection not to wait for stalled pre-DNS peer (%v), got %v", hold, elapsed),
	)
}

func TestProxy_tlsProxyProtocolV2_DiscardExtraPayload(t *testing.T) {
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

	rawConn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = rawConn.Close() }()

	src := netutil.NetAddrToAddrPort(rawConn.LocalAddr())
	dst := netutil.NetAddrToAddrPort(rawConn.RemoteAddr())

	// Add extra TLV-like bytes after the minimal address block.
	_, err = rawConn.Write(proxyProtocolV2HeaderWithExtra(src, dst, 1024))
	require.NoError(t, err)

	tlsConn := tls.Client(rawConn, clientTLSConf)
	err = tlsConn.Handshake()
	require.NoError(t, err)

	dnsConn := &dns.Conn{Conn: tlsConn}
	require.NoError(t, dnsConn.SetDeadline(time.Now().Add(testTimeout)))
	err = dnsConn.WriteMsg(newTestMessage())
	require.NoError(t, err)

	_, err = dnsConn.ReadMsg()
	require.NoError(t, err)
}

func TestProxy_tlsProxyProtocolV2_ProductionLikeConcurrentMix(t *testing.T) {
	serverConfig, caPem := newTLSConfig(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	clientTLSConf := &tls.Config{ServerName: tlsServerName, RootCAs: roots}

	const (
		slowPeers    = 2
		fastPeers    = 5
		holdDuration = 4 * time.Second
		// With the fix, normal peers should recover quickly (bounded by the
		// configured PPv2 read timeout) even while slow peers keep connections
		// open for a longer period.
		//
		// We allow some headroom for TLS handshake + local execution jitter.
		maxFastPeerElapsed = 2500 * time.Millisecond
	)

	dnsProxy := mustNew(t, &Config{
		Logger:                    testLogger,
		TLSListenAddr:             []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		TLSConfig:                 serverConfig,
		UpstreamConfig:            newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:            defaultTrustedProxies,
		TLSProxyProtocolV2Enabled: true,
		MaxGoroutines:             1,
	})
	servicetest.RequireRun(t, dnsProxy, testTimeout)

	addr := dnsProxy.Addr(ProtoTLS).String()

	// Start slow peers: send incomplete PPv2 preface and keep the connection
	// open.
	slowConns := make([]net.Conn, 0, slowPeers)
	for i := 0; i < slowPeers; i++ {
		rawConn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		_, err = rawConn.Write([]byte{0x0d})
		require.NoError(t, err)
		slowConns = append(slowConns, rawConn)
		conn := rawConn
		time.AfterFunc(holdDuration, func() { _ = conn.Close() })
	}
	defer func() {
		for _, c := range slowConns {
			_ = c.Close()
		}
	}()

	// Ensure slow peers are accepted.
	time.Sleep(50 * time.Millisecond)

	// Start fast peers concurrently.
	var wg sync.WaitGroup
	wg.Add(fastPeers)

	errCh := make(chan error, fastPeers)
	elapsedCh := make(chan time.Duration, fastPeers)

	for i := 0; i < fastPeers; i++ {
		go func() {
			defer wg.Done()

			rawConn, err := net.Dial("tcp", addr)
			if err != nil {
				errCh <- err
				return
			}
			defer func() { _ = rawConn.Close() }()

			src := netutil.NetAddrToAddrPort(rawConn.LocalAddr())
			dst := netutil.NetAddrToAddrPort(rawConn.RemoteAddr())
			_, err = rawConn.Write(proxyProtocolV2Header(src, dst))
			if err != nil {
				errCh <- err
				return
			}

			tlsConn := tls.Client(rawConn, clientTLSConf)
			if err := tlsConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				errCh <- err
				return
			}
			if err := tlsConn.Handshake(); err != nil {
				errCh <- err
				return
			}

			dnsConn := &dns.Conn{Conn: tlsConn}
			if err := dnsConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				errCh <- err
				return
			}

			start := time.Now()
			if err := dnsConn.WriteMsg(newTestMessage()); err != nil {
				errCh <- err
				return
			}
			if _, err := dnsConn.ReadMsg(); err != nil {
				errCh <- err
				return
			}
			elapsedCh <- time.Since(start)
		}()
	}

	wg.Wait()
	close(errCh)
	close(elapsedCh)

	for err := range errCh {
		t.Fatalf("fast peer failed: %v", err)
	}

	var maxElapsed time.Duration
	for e := range elapsedCh {
		if e > maxElapsed {
			maxElapsed = e
		}
	}

	require.Less(t, maxElapsed, maxFastPeerElapsed, fmt.Sprintf("expected fast peers to complete under %v, max elapsed=%v", maxFastPeerElapsed, maxElapsed))
}

func TestParseProxyProtocolV2Addr_IPv6(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("2001:db8::2")

	payload := make([]byte, 36)
	copy(payload[:16], src.AsSlice())
	copy(payload[16:32], dst.AsSlice())
	binary.BigEndian.PutUint16(payload[32:34], 5353)
	binary.BigEndian.PutUint16(payload[34:36], 853)

	addr, err := parseProxyProtocolV2Addr(0x21, payload)
	require.NoError(t, err)
	require.Equal(t, netip.AddrPortFrom(src, 5353), addr)
}

func TestParseProxyProtocolV2Addr_UnsupportedFamily(t *testing.T) {
	_, err := parseProxyProtocolV2Addr(0x31, []byte{1, 2, 3})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported proxy protocol v2 address family")
}

func TestProxyConsumeProxyProtocolV2_LOCALCommandKeepsRemoteAddr(t *testing.T) {
	remoteAddr := netip.MustParseAddrPort("127.0.0.1:12345")
	p := &Proxy{
		Config: Config{
			TrustedProxies: netutil.SubnetSetFunc(func(a netip.Addr) bool {
				return a == remoteAddr.Addr()
			}),
		},
	}

	header := makeProxyProtocolV2RawHeader(0x20, 0x00, []byte{0xaa, 0xbb, 0xcc})
	reader := bufio.NewReader(bytes.NewReader(header))

	addr, err := p.consumeProxyProtocolV2(t.Context(), reader, remoteAddr)
	require.NoError(t, err)
	require.Equal(t, remoteAddr, addr)
	require.Zero(t, reader.Buffered())
}

func TestProxyConsumeProxyProtocolV2_UnsupportedFamilyConsumesPayload(t *testing.T) {
	remoteAddr := netip.MustParseAddrPort("127.0.0.1:12345")
	p := &Proxy{
		Config: Config{
			TrustedProxies: netutil.SubnetSetFunc(func(a netip.Addr) bool {
				return a == remoteAddr.Addr()
			}),
		},
	}

	header := makeProxyProtocolV2RawHeader(0x21, 0x31, []byte{1, 2, 3, 4, 5})
	reader := bufio.NewReader(bytes.NewReader(header))

	_, err := p.consumeProxyProtocolV2(t.Context(), reader, remoteAddr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported proxy protocol v2 address family")
	require.Zero(t, reader.Buffered())
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

func proxyProtocolV2HeaderWithExtra(src, dst netip.AddrPort, extraPayloadLen int) (hdr []byte) {
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

	payloadLen := len(addrPayload) + extraPayloadLen
	hdr = make([]byte, proxyProtocolV2HeaderLen+payloadLen)
	copy(hdr[:len(proxyProtocolV2Signature)], proxyProtocolV2Signature[:])
	hdr[12] = 0x21
	hdr[13] = famProto
	binary.BigEndian.PutUint16(hdr[14:16], uint16(payloadLen))
	copy(hdr[16:16+len(addrPayload)], addrPayload)

	// The remaining bytes are extra TLVs we don't need for address extraction.
	return hdr
}

func makeProxyProtocolV2RawHeader(verCmd, famProto byte, payload []byte) (hdr []byte) {
	hdr = make([]byte, proxyProtocolV2HeaderLen+len(payload))
	copy(hdr[:len(proxyProtocolV2Signature)], proxyProtocolV2Signature[:])
	hdr[12] = verCmd
	hdr[13] = famProto
	binary.BigEndian.PutUint16(hdr[14:16], uint16(len(payload)))
	copy(hdr[16:], payload)

	return hdr
}
