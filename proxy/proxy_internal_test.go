package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	listenIP                = "127.0.0.1"
	testDefaultUpstreamAddr = "8.8.8.8:53"
	tlsServerName           = "testdns.adguard.com"
	testMessagesCount       = 10

	// defaultTestTTL used to guarantee caching.
	defaultTestTTL = 1000

	// testTimeout is the default timeout for tests.
	testTimeout = 500 * time.Millisecond
)

// localhostAnyPort is a [netip.AddrPort] having a value of 127.0.0.1:0.
var localhostAnyPort = netip.MustParseAddrPort(netutil.JoinHostPort(listenIP, 0))

// defaultTrustedProxies is a set of trusted proxies that includes all possible
// IP addresses.
var defaultTrustedProxies netutil.SubnetSet = netutil.SliceSubnetSet{
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::0/0"),
}

// mustNew wraps [New] function failing the test on error.
func mustNew(t *testing.T, conf *Config) (p *Proxy) {
	t.Helper()

	p, err := New(conf)
	require.NoError(t, err)

	return p
}

// sendTestMessages sends [testMessagesCount] DNS requests to the specified
// connection and checks the responses.
func sendTestMessages(t *testing.T, conn *dns.Conn) {
	for i := range testMessagesCount {
		req := newTestMessage()
		err := conn.WriteMsg(req)
		require.NoErrorf(t, err, "req number %d", i)

		res, err := conn.ReadMsg()
		require.NoErrorf(t, err, "resp number %d", i)

		requireResponse(t, req, res)
	}
}

func newTestMessage() *dns.Msg {
	return newHostTestMessage("google-public-dns-a.google.com")
}

func newHostTestMessage(host string) (req *dns.Msg) {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   host + ".",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}

func requireResponse(t testing.TB, req, reply *dns.Msg) {
	t.Helper()

	require.NotNil(t, reply)
	require.Lenf(t, reply.Answer, 1, "wrong number of answers: %d", len(reply.Answer))
	require.Equal(t, req.Id, reply.Id)

	a, ok := reply.Answer[0].(*dns.A)
	require.Truef(t, ok, "wrong answer type: %v", reply.Answer[0])

	require.Equalf(t, net.IPv4(8, 8, 8, 8), a.A.To16(), "wrong answer: %v", a.A)
}

func newTLSConfig(t *testing.T) (conf *tls.Config, certPem []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err)

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * time.Hour * 24)

	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"AdGuard Tests"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{tlsServerName},
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	require.NoError(t, err)

	certPem = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	cert, err := tls.X509KeyPair(certPem, keyPem)
	require.NoError(t, err)

	return &tls.Config{Certificates: []tls.Certificate{cert}, ServerName: tlsServerName}, certPem
}

// firstIP returns the first IP address from the DNS response.
func firstIP(resp *dns.Msg) (ip net.IP) {
	for _, ans := range resp.Answer {
		a, ok := ans.(*dns.A)
		if !ok {
			continue
		}

		return a.A
	}

	return nil
}

type testUpstream struct {
	ans []dns.RR

	ecsIP      net.IP
	ecsReqIP   net.IP
	ecsReqMask int
}

// type check
var _ upstream.Upstream = (*testUpstream)(nil)

// Exchange implements the upstream.Upstream interface for *testUpstream.
func (u *testUpstream) Exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	resp = &dns.Msg{}
	resp.SetReply(m)

	if u.ans != nil {
		resp.Answer = append(resp.Answer, u.ans...)
	}

	ecs, _ := ecsFromMsg(m)
	if ecs != nil {
		u.ecsReqIP = ecs.IP
		u.ecsReqMask, _ = ecs.Mask.Size()
	}
	if u.ecsIP != nil {
		setECS(resp, u.ecsIP, 24)
	}

	return resp, nil
}

// Address implements the upstream.Upstream interface for *testUpstream.
func (u *testUpstream) Address() (addr string) {
	return ""
}

// Close implements the upstream.Upstream interface for *testUpstream.
func (u *testUpstream) Close() (err error) {
	return nil
}

// newTestUpstreamConfigWithBoot creates a new UpstreamConfig with upstream
// addresses and a bootstrapped resolver.
func newTestUpstreamConfigWithBoot(
	t require.TestingT,
	timeout time.Duration,
	addrs ...string,
) (u *UpstreamConfig) {
	googleRslv, err := upstream.NewUpstreamResolver(
		"8.8.8.8:53",
		&upstream.Options{
			Logger:  slogutil.NewDiscardLogger(),
			Timeout: timeout,
		},
	)
	require.NoError(t, err)

	upsConf, err := ParseUpstreamsConfig(addrs, &upstream.Options{
		Logger:    slogutil.NewDiscardLogger(),
		Timeout:   timeout,
		Bootstrap: upstream.NewCachingResolver(googleRslv),
	})
	require.NoError(t, err)

	return upsConf
}

// newTestUpstreamConfig creates a new UpstreamConfig with a single upstream
// address and default timeout.
func newTestUpstreamConfig(
	t testing.TB,
	timeout time.Duration,
	addrs ...string,
) (u *UpstreamConfig) {
	t.Helper()

	upsConf, err := ParseUpstreamsConfig(addrs, &upstream.Options{
		Logger:  slogutil.NewDiscardLogger(),
		Timeout: timeout,
	})
	require.NoError(t, err)

	return upsConf
}

// mustStartDefaultProxy starts a new proxy with default settings and returns
// it.  It fails the test on error.
func mustStartDefaultProxy(t *testing.T) (p *Proxy) {
	t.Helper()

	p = mustNew(t, &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
	})

	ctx := context.Background()
	err := p.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return p.Shutdown(ctx) })

	return p
}

// TestProxyRace sends multiple parallel DNS requests to the
// fully configured dnsproxy to check for race conditions
func TestProxyRace(t *testing.T) {
	upsConf := newTestUpstreamConfig(
		t,
		defaultTimeout,
		// Use the same upstream twice so that we could rotate them
		testDefaultUpstreamAddr,
		testDefaultUpstreamAddr,
	)
	dnsProxy := mustNew(t, &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         upsConf,
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
	})

	ctx := context.Background()
	err := dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)

	g := &sync.WaitGroup{}
	g.Add(testMessagesCount)

	pt := testutil.PanicT{}
	for range testMessagesCount {
		go func() {
			defer g.Done()

			req := newTestMessage()
			writeErr := conn.WriteMsg(req)
			require.NoError(pt, writeErr)

			res, readErr := conn.ReadMsg()
			require.NoError(pt, readErr)

			// We do not check if msg IDs match because the order of responses may
			// be different.

			require.NotNil(pt, res)
			require.Len(pt, res.Answer, 1)
			require.IsType(pt, &dns.A{}, res.Answer[0])

			a := res.Answer[0].(*dns.A)
			require.Equal(pt, net.IPv4(8, 8, 8, 8), a.A.To16())
		}()
	}

	g.Wait()
}

// newTxts returns new test TXT RR strings.
func newTxts(t *testing.T, txtDataLen int) (txts []string) {
	t.Helper()

	const txtDataChunkLen = 255

	txtDataChunkNum := txtDataLen / txtDataChunkLen
	if txtDataLen%txtDataChunkLen > 0 {
		txtDataChunkNum++
	}

	txts = make([]string, txtDataChunkNum)
	randData := make([]byte, txtDataLen)
	n, err := rand.Read(randData)
	require.NoError(t, err)
	require.Equal(t, txtDataLen, n)

	for i, c := range randData {
		randData[i] = c%26 + 'a'
	}

	// *dns.TXT requires splitting the actual data into 256-byte chunks.
	for i := range txtDataChunkNum {
		r := txtDataChunkLen * (i + 1)
		if r > txtDataLen {
			r = txtDataLen
		}
		txts[i] = string(randData[txtDataChunkLen*i : r])
	}

	return txts
}

// newDNSContext returns new DNS request message context with Proto set to
// [ProtoUDP].  Constructs request message from the given parameters.
func newDNSContext(
	domain string,
	qtype uint16,
	qclass uint16,
	edns bool,
	udpsize uint16,
) (dctx *DNSContext) {
	req := newReq(domain, qtype, qclass)
	if edns {
		req.SetEdns0(udpsize, true)
	}

	return &DNSContext{
		Req:   req,
		Proto: ProtoUDP,
	}
}

// newReq returns new request message for provided parameters.
func newReq(domain string, qtype, qclass uint16) (req *dns.Msg) {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: dns.Id(),
		},
		Compress: true,
		Question: []dns.Question{{
			Name:   dns.Fqdn(domain),
			Qtype:  qtype,
			Qclass: qclass,
		}},
	}
}

func TestProxy_Resolve_dnssecCache(t *testing.T) {
	const (
		host = "example.com"

		// Larger than UDP buffer size to invoke truncation.
		txtDataLen = 1024
	)

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(host),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
		},
		Txt: newTxts(t, txtDataLen),
	}

	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(host),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
		},
		A: net.IP{1, 2, 3, 4},
	}

	ds := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(host),
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
		},
		Digest: "736f6d652064656c65676174696f6e207369676e6572",
	}

	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(host),
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    defaultTestTTL,
		},
		TypeCovered: dns.TypeA,
		Algorithm:   8,
		Labels:      2,
		SignerName:  dns.Fqdn(host),
		Signature:   "c29tZSBycnNpZyByZWxhdGVkIHN0dWZm",
	}

	u := &fakeUpstream{
		onExchange: func(m *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(m)

			q := m.Question[0]
			switch q.Qtype {
			case dns.TypeA:
				resp.Answer = append(resp.Answer, a)
			case dns.TypeTXT:
				resp.Answer = append(resp.Answer, txt)
			case dns.TypeDS:
				resp.Answer = append(resp.Answer, ds)
			default:
				// Go on.  The RRSIG resource record is added afterward.  This
				// upstream.Upstream implementation doesn't handle explicit
				// requests for it.
			}

			if len(resp.Answer) > 0 {
				resp.Answer[0].Header().Ttl = defaultTestTTL
			}

			if o := m.IsEdns0(); o != nil {
				resp.Answer = append(resp.Answer, rrsig)
				resp.SetEdns0(defaultUDPBufSize, o.Do())
			}

			return resp, nil
		},
		onAddress: func() (addr string) { return "" },
		onClose:   func() (err error) { return nil },
	}

	p := mustNew(t, &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         &UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		CacheEnabled:           true,
		CacheSizeBytes:         defaultCacheSize,
	})

	testCases := []struct {
		wantAns dns.RR
		name    string
		wantLen int
		edns    bool
	}{{
		wantAns: a,
		name:    "a_noedns",
		wantLen: 1,
		edns:    false,
	}, {
		wantAns: a,
		name:    "a_ends",
		wantLen: 2,
		edns:    true,
	}, {
		wantAns: txt,
		name:    "txt_noedns",
		wantLen: 1,
		edns:    false,
	}, {
		wantAns: txt,
		name:    "txt_edns",
		// Truncated.
		wantLen: 0,
		edns:    true,
	}, {
		wantAns: ds,
		name:    "ds_noedns",
		wantLen: 1,
		edns:    false,
	}, {
		wantAns: ds,
		name:    "ds_edns",
		wantLen: 2,
		edns:    true,
	}}

	for _, tc := range testCases {
		ansHdr := tc.wantAns.Header()
		dctx := newDNSContext(ansHdr.Name, ansHdr.Rrtype, ansHdr.Class, tc.edns, txtDataLen/2)

		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(p.cache.items.Clear)

			err := p.Resolve(dctx)
			require.NoError(t, err)

			res := dctx.Res
			require.NotNil(t, res)

			require.Len(t, res.Answer, tc.wantLen, res.Answer)
			switch tc.wantLen {
			case 0:
				assert.True(t, res.Truncated)
			case 1:
				res.Answer[0].Header().Ttl = defaultTestTTL
				assert.Equal(t, tc.wantAns, res.Answer[0])
			case 2:
				res.Answer[0].Header().Ttl = defaultTestTTL
				assert.Equal(t, tc.wantAns, res.Answer[0])
				assert.Equal(t, rrsig, res.Answer[1])
			default:
				t.Fatalf("wanted length has unexpected value %d", tc.wantLen)
			}

			cached, expired, key := p.cache.get(dctx.Req)
			require.NotNil(t, cached)
			require.Len(t, cached.m.Answer, 2)

			assert.False(t, expired)
			assert.Equal(t, key, msgToKey(dctx.Req))

			// Just make it match.
			cached.m.Answer[0].Header().Ttl = defaultTestTTL
			assert.Equal(t, tc.wantAns.String(), cached.m.Answer[0].String())
			assert.Equal(t, rrsig.String(), cached.m.Answer[1].String())
		})

	}
}

func TestExchangeWithReservedDomains(t *testing.T) {
	t.Parallel()

	dnsProxy := mustNew(t, &Config{
		Logger:        slogutil.NewDiscardLogger(),
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfigWithBoot(
			t,
			testTimeout,
			"[/adguard.com/]1.2.3.4",
			"[/google.ru/]2.3.4.5",
			"[/maps.google.ru/]#",
			"1.1.1.1",
		),
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
	})

	ctx := context.Background()
	err := dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	// Create a DNS-over-TCP client connection.
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)

	// Create google-a test message.
	req := newTestMessage()
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Make sure that dnsproxy is working.
	res, err := conn.ReadMsg()
	require.NoError(t, err)
	requireResponse(t, req, res)

	// Create adguard.com test message.
	req = newHostTestMessage("adguard.com")
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Test message should not be resolved.
	res, _ = conn.ReadMsg()
	require.Nil(t, res.Answer)

	// Create www.google.ru test message.
	req = newHostTestMessage("www.google.ru")
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Test message should not be resolved.
	res, _ = conn.ReadMsg()
	require.Empty(t, res.Answer)

	// Create maps.google.ru test message.
	req = newHostTestMessage("maps.google.ru")
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Test message should be resolved.
	res, _ = conn.ReadMsg()
	require.NotNil(t, res.Answer)
}

// TestOneByOneUpstreamsExchange tries to resolve DNS request
// with one valid and two invalid upstreams
func TestOneByOneUpstreamsExchange(t *testing.T) {
	t.Parallel()

	dnsProxy := mustNew(t, &Config{
		Logger:        slogutil.NewDiscardLogger(),
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfigWithBoot(
			t,
			testTimeout,
			"https://fake-dns.com/fake-dns-query",
			"tls://fake-dns.com",
			"1.1.1.1",
		),
		TrustedProxies:         defaultTrustedProxies,
		Fallbacks:              newTestUpstreamConfig(t, testTimeout, "1.2.3.4:567"),
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
	})

	ctx := context.Background()
	err := dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	// create a DNS-over-TCP client connection
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)

	// make sure that the response is okay and resolved by valid upstream
	req := newTestMessage()
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	start := time.Now()
	res, err := conn.ReadMsg()
	require.NoError(t, err)
	requireResponse(t, req, res)

	elapsed := time.Since(start)
	assert.Greater(t, 3*testTimeout, elapsed)
}

// newLocalUpstreamListener creates a new localhost listener on the specified
// port for tcp4 network and returns its listening address.
func newLocalUpstreamListener(t *testing.T, port uint16, h dns.Handler) (real netip.AddrPort) {
	t.Helper()

	startCh := make(chan struct{})
	upsSrv := &dns.Server{
		Addr:              netip.AddrPortFrom(netutil.IPv4Localhost(), port).String(),
		Net:               "tcp",
		Handler:           h,
		NotifyStartedFunc: func() { close(startCh) },
	}
	go func() {
		err := upsSrv.ListenAndServe()
		require.NoError(testutil.PanicT{}, err)
	}()

	<-startCh
	testutil.CleanupAndRequireSuccess(t, upsSrv.Shutdown)

	return testutil.RequireTypeAssert[*net.TCPAddr](t, upsSrv.Listener.Addr()).AddrPort()
}

func TestFallback(t *testing.T) {
	t.Parallel()

	responseCh := make(chan uint16)
	failCh := make(chan uint16)

	successHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		testutil.RequireSend(testutil.PanicT{}, responseCh, r.Id, testTimeout)

		require.NoError(testutil.PanicT{}, w.WriteMsg((&dns.Msg{}).SetReply(r)))
	})
	failHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		testutil.RequireSend(testutil.PanicT{}, failCh, r.Id, testTimeout)

		require.NoError(testutil.PanicT{}, w.WriteMsg(&dns.Msg{}))
	})

	successAddr := (&url.URL{
		Scheme: string(ProtoTCP),
		Host:   newLocalUpstreamListener(t, 0, successHandler).String(),
	}).String()
	alsoSuccessAddr := (&url.URL{
		Scheme: string(ProtoTCP),
		Host:   newLocalUpstreamListener(t, 0, successHandler).String(),
	}).String()
	failAddr := (&url.URL{
		Scheme: string(ProtoTCP),
		Host:   newLocalUpstreamListener(t, 0, failHandler).String(),
	}).String()

	dnsProxy := mustNew(t, &Config{
		Logger:        slogutil.NewDiscardLogger(),
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfig(
			t,
			testTimeout,
			failAddr,
			"[/specific.example/]"+alsoSuccessAddr,
			// almost.failing.example will fall here first.
			"[/failing.example/]"+failAddr,
		),
		TrustedProxies: defaultTrustedProxies,
		Fallbacks: newTestUpstreamConfig(
			t,
			testTimeout,
			failAddr,
			successAddr,
			"[/failing.example/]"+failAddr,
			"[/almost.failing.example/]"+alsoSuccessAddr,
		),
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
	})

	ctx := context.Background()
	err := dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	conn, err := dns.Dial("tcp", dnsProxy.Addr(ProtoTCP).String())
	require.NoError(t, err)

	testCases := []struct {
		name        string
		wantSignals []chan uint16
	}{{
		name: "general.example",
		wantSignals: []chan uint16{
			failCh,
			// Both non-specific fallbacks tried.
			failCh,
			responseCh,
		},
	}, {
		name: "specific.example",
		wantSignals: []chan uint16{
			responseCh,
		},
	}, {
		name: "failing.example",
		wantSignals: []chan uint16{
			failCh,
			failCh,
		},
	}, {
		name: "almost.failing.example",
		wantSignals: []chan uint16{
			failCh,
			responseCh,
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := newHostTestMessage(tc.name)
			err = conn.WriteMsg(req)
			require.NoError(t, err)

			for _, ch := range tc.wantSignals {
				reqID, ok := testutil.RequireReceive(testutil.PanicT{}, ch, testTimeout)
				require.True(t, ok)

				assert.Equal(t, req.Id, reqID)
			}

			_, err = conn.ReadMsg()
			require.NoError(t, err)
		})
	}
}

func TestFallbackFromInvalidBootstrap(t *testing.T) {
	t.Parallel()

	invalidRslv, err := upstream.NewUpstreamResolver("8.8.8.8:555", &upstream.Options{
		Logger:  slogutil.NewDiscardLogger(),
		Timeout: testTimeout,
	})
	require.NoError(t, err)

	// Prepare the proxy server
	upsConf, err := ParseUpstreamsConfig([]string{"tls://dns.adguard.com"}, &upstream.Options{
		Logger:    slogutil.NewDiscardLogger(),
		Bootstrap: invalidRslv, Timeout: testTimeout,
	})
	require.NoError(t, err)

	dnsProxy := mustNew(t, &Config{
		Logger:         slogutil.NewDiscardLogger(),
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: upsConf,
		TrustedProxies: defaultTrustedProxies,
		Fallbacks: newTestUpstreamConfig(
			t,
			testTimeout,
			"1.0.0.1",
			"8.8.8.8",
		),
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
	})

	// Start listening
	ctx := context.Background()
	err = dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)

	// Make sure that the response is okay and resolved by the fallback
	req := newTestMessage()
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	start := time.Now()
	res, err := conn.ReadMsg()
	require.NoError(t, err)
	requireResponse(t, req, res)

	elapsed := time.Since(start)
	assert.Greater(t, 3*testTimeout, elapsed)
}

func TestRefuseAny(t *testing.T) {
	dnsProxy := mustNew(t, &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		RefuseAny:              true,
	})

	// Start listening
	ctx := context.Background()
	err := dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{
		Net:     string(ProtoUDP),
		Timeout: testTimeout,
	}

	// Create a DNS request
	request := (&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
	}).SetQuestion("google.com.", dns.TypeANY)

	r, _, err := client.Exchange(request, addr.String())
	require.NoError(t, err)

	assert.Equal(t, dns.RcodeNotImplemented, r.Rcode)
}

func TestInvalidDNSRequest(t *testing.T) {
	dnsProxy := mustNew(t, &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		RefuseAny:              true,
	})

	// Start listening
	ctx := context.Background()
	err := dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	// Create a DNS-over-UDP client connection
	client := &dns.Client{
		Net:     string(ProtoUDP),
		Timeout: testTimeout,
	}

	// Create a DNS request
	request := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
	}

	r, _, err := client.Exchange(request, dnsProxy.Addr(ProtoUDP).String())
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeServerFailure, r.Rcode)
}

// Server must drop incoming Response messages
func TestResponseInRequest(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{
		Net:     string(ProtoUDP),
		Timeout: testTimeout,
	}

	req := newTestMessage()
	req.Response = true

	r, _, err := client.Exchange(req, addr.String())

	netErr := &net.OpError{}
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout())
	assert.Nil(t, r)
}

// Server must respond with SERVFAIL to requests without a Question
func TestNoQuestion(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{
		Net:     string(ProtoUDP),
		Timeout: testTimeout,
	}

	req := newTestMessage()
	req.Question = nil

	r, _, err := client.Exchange(req, addr.String())
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeServerFailure, r.Rcode)
}

// fakeUpstream is a mock upstream implementation to simplify testing.  It
// allows assigning custom Exchange and Address methods.
//
// TODO(e.burkov):  Use dnsproxytest.FakeUpstream instead.
type fakeUpstream struct {
	onExchange func(m *dns.Msg) (resp *dns.Msg, err error)
	onAddress  func() (addr string)
	onClose    func() (err error)
}

// type check
var _ upstream.Upstream = (*fakeUpstream)(nil)

// Exchange implements upstream.Upstream interface for *funcUpstream.
func (u *fakeUpstream) Exchange(m *dns.Msg) (resp *dns.Msg, err error) { return u.onExchange(m) }

// Address implements upstream.Upstream interface for *funcUpstream.
func (u *fakeUpstream) Address() (addr string) { return u.onAddress() }

// Close implements upstream.Upstream interface for *funcUpstream.
func (u *fakeUpstream) Close() (err error) { return u.onClose() }

func TestProxy_ReplyFromUpstream_badResponse(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	u := &fakeUpstream{
		onExchange: func(m *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(m)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   m.Question[0].Name,
					Class:  dns.ClassINET,
					Rrtype: dns.TypeA,
				},
				A: net.IP{1, 2, 3, 4},
			})
			// Make the response invalid.
			resp.Question = []dns.Question{}

			return resp, nil
		},
		onAddress: func() (addr string) { return "stub" },
		onClose:   func() error { panic("not implemented") },
	}

	d := &DNSContext{
		CustomUpstreamConfig: NewCustomUpstreamConfig(
			&UpstreamConfig{Upstreams: []upstream.Upstream{u}},
			false,
			0,
			false,
		),
		Req:  newHostTestMessage("host"),
		Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
	}

	var err error
	require.NotPanics(t, func() {
		err = dnsProxy.Resolve(d)
	})
	require.NoError(t, err)

	assert.Equal(t, d.Req.Question[0], d.Res.Question[0])
}

func TestExchangeCustomUpstreamConfig(t *testing.T) {
	prx := mustStartDefaultProxy(t)

	ansIP := net.IP{4, 3, 2, 1}
	u := &testUpstream{
		ans: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Rrtype: dns.TypeA,
				Name:   "host.",
				Ttl:    60,
			},
			A: ansIP,
		}},
	}

	d := DNSContext{
		CustomUpstreamConfig: NewCustomUpstreamConfig(
			&UpstreamConfig{Upstreams: []upstream.Upstream{u}},
			false,
			0,
			false,
		),
		Req:  newHostTestMessage("host"),
		Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
	}

	err := prx.Resolve(&d)
	require.NoError(t, err)

	assert.Equal(t, ansIP, firstIP(d.Res))
}

func TestExchangeCustomUpstreamConfigCache(t *testing.T) {
	prx := mustNew(t, &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		CacheEnabled:           true,
	})

	ctx := context.Background()
	err := prx.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return prx.Shutdown(ctx) })

	var count int

	ansIP := net.IP{4, 3, 2, 1}
	exchangeFunc := func(m *dns.Msg) (resp *dns.Msg, err error) {
		resp = &dns.Msg{}
		resp.SetReply(m)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Class:  dns.ClassINET,
				Rrtype: dns.TypeA,
				Ttl:    defaultTestTTL,
			},
			A: ansIP,
		})

		count++

		return resp, nil
	}
	u := &fakeUpstream{
		onExchange: exchangeFunc,
		onAddress:  func() (addr string) { return "stub" },
		onClose:    func() error { panic("not implemented") },
	}

	customUpstreamConfig := NewCustomUpstreamConfig(
		&UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		true,
		defaultCacheSize,
		prx.EnableEDNSClientSubnet,
	)

	d := DNSContext{
		CustomUpstreamConfig: customUpstreamConfig,
		Req:                  newHostTestMessage("host"),
		Addr:                 netip.MustParseAddrPort("1.2.3.0:1234"),
	}

	err = prx.Resolve(&d)
	require.NoError(t, err)

	require.Equal(t, 1, count)
	assert.Equal(t, ansIP, firstIP(d.Res))

	err = prx.Resolve(&d)
	require.NoError(t, err)

	assert.Equal(t, 1, count)
	assert.Equal(t, ansIP, firstIP(d.Res))

	customUpstreamConfig.ClearCache()

	err = prx.Resolve(&d)
	require.NoError(t, err)

	assert.Equal(t, 2, count)
	assert.Equal(t, ansIP, firstIP(d.Res))
}

func TestECS(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		ip := net.IP{1, 2, 3, 4}

		m := &dns.Msg{}
		subnet := setECS(m, ip, 16)

		ones, _ := subnet.Mask.Size()
		assert.Equal(t, 24, ones)

		var scope int
		subnet, scope = ecsFromMsg(m)
		assert.Equal(t, ip.Mask(subnet.Mask), subnet.IP)

		ones, _ = subnet.Mask.Size()
		assert.Equal(t, 24, ones)
		assert.Equal(t, 16, scope)
	})

	t.Run("ipv6", func(t *testing.T) {
		ip := net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		m := &dns.Msg{}
		subnet := setECS(m, ip, 48)

		ones, _ := subnet.Mask.Size()
		assert.Equal(t, 56, ones)

		var scope int
		subnet, scope = ecsFromMsg(m)
		assert.Equal(t, ip.Mask(subnet.Mask), subnet.IP)

		ones, _ = subnet.Mask.Size()
		assert.Equal(t, 56, ones)
		assert.Equal(t, 48, scope)
	})
}

// Resolve the same host with the different client subnet values
func TestECSProxy(t *testing.T) {
	var (
		ip1230 = net.IP{1, 2, 3, 0}
		ip2230 = net.IP{2, 2, 3, 0}
		ip4321 = net.IP{4, 3, 2, 1}
		ip4322 = net.IP{4, 3, 2, 2}
		ip4323 = net.IP{4, 3, 2, 3}
	)

	u := &testUpstream{
		ans: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 60},
			A:   ip4321,
		}},
		ecsIP: ip1230,
	}

	prx := mustNew(t, &Config{
		Logger:        slogutil.NewDiscardLogger(),
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{u},
		},
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
	})

	ctx := context.Background()
	err := prx.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return prx.Shutdown(ctx) })

	t.Run("cache_subnet", func(t *testing.T) {
		d := DNSContext{
			Req:  newHostTestMessage("host"),
			Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
		}

		err = prx.Resolve(&d)
		require.NoError(t, err)

		assert.Equal(t, net.IP{4, 3, 2, 1}, firstIP(d.Res))
		assert.Equal(t, ip1230, u.ecsReqIP)
	})

	t.Run("serve_subnet_cache", func(t *testing.T) {
		d := &DNSContext{
			Req:  newHostTestMessage("host"),
			Addr: netip.MustParseAddrPort("1.2.3.1:1234"),
		}
		u.ans, u.ecsIP, u.ecsReqIP = nil, nil, nil

		require.NoError(t, prx.Resolve(d))

		assert.Equal(t, ip4321, firstIP(d.Res))
		assert.Nil(t, u.ecsReqIP)
	})

	t.Run("another_subnet", func(t *testing.T) {
		d := DNSContext{
			Req:  newHostTestMessage("host"),
			Addr: netip.MustParseAddrPort("2.2.3.0:1234"),
		}
		u.ans = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 60},
			A:   ip4322,
		}}
		u.ecsIP = ip2230

		err = prx.Resolve(&d)
		require.NoError(t, err)

		assert.Equal(t, ip4322, firstIP(d.Res))
		assert.Equal(t, ip2230, u.ecsReqIP)
	})

	t.Run("cache_general", func(t *testing.T) {
		d := DNSContext{
			Req:  newHostTestMessage("host"),
			Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
		}
		u.ans = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 60},
			A:   ip4323,
		}}
		u.ecsIP, u.ecsReqIP = nil, nil

		err = prx.Resolve(&d)
		require.NoError(t, err)

		assert.Equal(t, ip4323, firstIP(d.Res))
		assert.Nil(t, u.ecsReqIP)
	})

	t.Run("serve_general_cache", func(t *testing.T) {
		d := DNSContext{
			Req:  newHostTestMessage("host"),
			Addr: netip.MustParseAddrPort("127.0.0.2:1234"),
		}
		u.ans, u.ecsIP, u.ecsReqIP = nil, nil, nil

		err = prx.Resolve(&d)
		require.NoError(t, err)

		assert.Equal(t, ip4323, firstIP(d.Res))
		assert.Nil(t, u.ecsReqIP)
	})
}

func TestECSProxyCacheMinMaxTTL(t *testing.T) {
	clientIP := net.IP{1, 2, 3, 0}
	u := &testUpstream{
		ans: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Rrtype: dns.TypeA,
				Name:   "host.",
				Ttl:    10,
			},
			A: net.IP{4, 3, 2, 1},
		}},
		ecsIP: clientIP,
	}

	prx := mustNew(t, &Config{
		Logger:                 slogutil.NewDiscardLogger(),
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         &UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
		CacheMinTTL:            20,
		CacheMaxTTL:            40,
	})

	ctx := context.Background()
	err := prx.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return prx.Shutdown(ctx) })

	// first request
	d := DNSContext{
		Req:  newHostTestMessage("host"),
		Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
	}
	err = prx.Resolve(&d)
	require.NoError(t, err)

	// get from cache - check min TTL
	ci, expired, key := prx.cache.getWithSubnet(d.Req, &net.IPNet{
		IP:   clientIP,
		Mask: net.CIDRMask(24, netutil.IPv4BitLen),
	})
	assert.False(t, expired)

	assert.Equal(t, key, msgToKeyWithSubnet(d.Req, clientIP, 24))
	assert.True(t, ci.m.Answer[0].Header().Ttl == prx.CacheMinTTL)

	// 2nd request
	clientIP = net.IP{1, 2, 4, 0}
	d.Req = newHostTestMessage("host")
	d.Addr = netip.MustParseAddrPort("1.2.4.0:1234")
	u.ans = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeA,
			Name:   "host.",
			Ttl:    60,
		},
		A: net.IP{4, 3, 2, 1},
	}}
	u.ecsIP = clientIP
	err = prx.Resolve(&d)
	require.NoError(t, err)

	// get from cache - check max TTL
	ci, expired, key = prx.cache.getWithSubnet(d.Req, &net.IPNet{
		IP:   clientIP,
		Mask: net.CIDRMask(24, netutil.IPv4BitLen),
	})
	assert.False(t, expired)
	assert.Equal(t, key, msgToKeyWithSubnet(d.Req, clientIP, 24))
	assert.True(t, ci.m.Answer[0].Header().Ttl == prx.CacheMaxTTL)
}

func TestProxy_Resolve_withOptimisticResolver(t *testing.T) {
	const (
		host             = "some.domain.name."
		nonOptimisticTTL = 3600
	)

	buildCtx := func() (dctx *DNSContext) {
		req := &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id()},
			Question: []dns.Question{{
				Name:   host,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		return &DNSContext{Req: req}
	}
	buildResp := func(req *dns.Msg, ttl uint32) (resp *dns.Msg) {
		resp = (&dns.Msg{}).SetReply(req)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: net.IP{1, 2, 3, 4},
		}}

		return resp
	}

	p := &Proxy{
		Config: Config{
			CacheEnabled:    true,
			CacheOptimistic: true,
		},
		logger: slogutil.NewDiscardLogger(),
	}

	p.initCache()
	out, in := make(chan unit), make(chan unit)
	p.shortFlighter.cr = &testCachingResolver{
		onReplyFromUpstream: func(dctx *DNSContext) (ok bool, err error) {
			dctx.Res = buildResp(dctx.Req, nonOptimisticTTL)

			return true, nil
		},
		onCacheResp: func(dctx *DNSContext) {
			// Report adding to cache is in process.
			out <- unit{}
			// Wait for tests to finish.
			<-in

			p.cacheResp(dctx)

			// Report adding tocache is finished.
			out <- unit{}
		},
	}

	// Two different contexts are made to emulate two different requests
	// with the same question section.
	firstCtx, secondCtx := buildCtx(), buildCtx()

	// Add expired response into cache.
	req := firstCtx.Req
	key := msgToKey(req)
	data := (&cacheItem{
		m: buildResp(req, 0),
		u: testUpsAddr,
	}).pack()
	items := glcache.New(glcache.Config{
		EnableLRU: true,
	})
	items.Set(key, data)
	p.cache.items = items

	err := p.Resolve(firstCtx)
	require.NoError(t, err)
	require.Len(t, firstCtx.Res.Answer, 1)

	assert.EqualValues(t, optimisticTTL, firstCtx.Res.Answer[0].Header().Ttl)

	// Wait for optimisticResolver to reach the tested function.
	<-out

	err = p.Resolve(secondCtx)
	require.NoError(t, err)
	require.Len(t, secondCtx.Res.Answer, 1)

	assert.EqualValues(t, optimisticTTL, secondCtx.Res.Answer[0].Header().Ttl)

	// Continue and wait for it to finish.
	in <- unit{}
	<-out

	// Should be served from cache.
	data = p.cache.items.Get(msgToKey(firstCtx.Req))
	unpacked, expired := p.cache.unpackItem(data, firstCtx.Req)
	require.False(t, expired)
	require.NotNil(t, unpacked)
	require.Len(t, unpacked.m.Answer, 1)

	assert.EqualValues(t, nonOptimisticTTL, unpacked.m.Answer[0].Header().Ttl)
}

func TestProxy_HandleDNSRequest_private(t *testing.T) {
	t.Parallel()

	privateSet := netutil.SubnetSetFunc(netutil.IsLocallyServed)

	localIP := netip.MustParseAddrPort("192.168.0.1:1")
	require.True(t, privateSet.Contains(localIP.Addr()))

	externalIP := netip.MustParseAddrPort("4.3.2.1:1")
	require.False(t, privateSet.Contains(externalIP.Addr()))

	privateReq := (&dns.Msg{}).SetQuestion("2.0.168.192.in-addr.arpa", dns.TypePTR)
	privateResp := (&dns.Msg{}).SetReply(privateReq)
	privateResp.Compress = true

	externalReq := (&dns.Msg{}).SetQuestion("2.2.3.4.in-addr.arpa", dns.TypePTR)
	externalResp := (&dns.Msg{}).SetReply(externalReq)
	externalResp.Compress = true

	nxdomainResp := (&dns.Msg{}).SetReply(privateReq)
	nxdomainResp.Rcode = dns.RcodeNameError

	generalUps := &fakeUpstream{
		onExchange: func(m *dns.Msg) (resp *dns.Msg, err error) {
			return externalResp.Copy(), nil
		},
		onAddress: func() (addr string) { return "general" },
		onClose:   func() (err error) { return nil },
	}
	privateUps := &fakeUpstream{
		onExchange: func(m *dns.Msg) (resp *dns.Msg, err error) {
			return privateResp.Copy(), nil
		},
		onAddress: func() (addr string) { return "private" },
		onClose:   func() (err error) { return nil },
	}

	messages := dnsproxytest.NewTestMessageConstructor()
	messages.OnNewMsgNXDOMAIN = func(_ *dns.Msg) (resp *dns.Msg) {
		return nxdomainResp
	}

	p := mustNew(t, &Config{
		Logger:        slogutil.NewDiscardLogger(),
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{generalUps},
		},
		PrivateRDNSUpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{privateUps},
		},
		PrivateSubnets:     privateSet,
		UsePrivateRDNS:     true,
		MessageConstructor: messages,
	})
	ctx := context.Background()
	require.NoError(t, p.Start(ctx))
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return p.Shutdown(ctx) })

	testCases := []struct {
		name    string
		want    *dns.Msg
		req     *dns.Msg
		cliAddr netip.AddrPort
	}{{
		name:    "local_requests_external",
		want:    externalResp,
		req:     externalReq,
		cliAddr: localIP,
	}, {
		name:    "external_requests_external",
		want:    externalResp,
		req:     externalReq,
		cliAddr: externalIP,
	}, {
		name:    "local_requests_private",
		want:    privateResp,
		req:     privateReq,
		cliAddr: localIP,
	}, {
		name:    "external_requests_private",
		want:    nxdomainResp,
		req:     privateReq,
		cliAddr: externalIP,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dctx := p.newDNSContext(ProtoUDP, tc.req, tc.cliAddr)

			require.NoError(t, p.handleDNSRequest(dctx))
			assert.Equal(t, tc.want, dctx.Res)
		})
	}
}
