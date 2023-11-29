package proxy

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Disable logging in tests.
	log.SetOutput(io.Discard)

	os.Exit(m.Run())
}

const (
	listenIP          = "127.0.0.1"
	upstreamAddr      = "8.8.8.8:53"
	tlsServerName     = "testdns.adguard.com"
	testMessagesCount = 10
)

// TestProxyRace sends multiple parallel DNS requests to the
// fully configured dnsproxy to check for race conditions
func TestProxyRace(t *testing.T) {
	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)

	// Use the same upstream twice so that we could rotate them
	dnsProxy.UpstreamConfig.Upstreams = append(dnsProxy.UpstreamConfig.Upstreams, dnsProxy.UpstreamConfig.Upstreams[0])

	// Start listening
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("cannot connect to the proxy: %s", err)
	}

	sendTestMessagesAsync(t, conn)

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

// defaultTestTTL used to guarantee caching.
const defaultTestTTL = 1000

type testDNSSECUpstream struct {
	a     dns.RR
	txt   dns.RR
	ds    dns.RR
	rrsig dns.RR
}

// type check
var _ upstream.Upstream = (*testDNSSECUpstream)(nil)

// Exchange implements the upstream.Upstream interface for *testDNSSECUpstream.
func (u *testDNSSECUpstream) Exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	resp = &dns.Msg{}
	resp.SetReply(m)

	q := m.Question[0]
	switch q.Qtype {
	case dns.TypeA:
		resp.Answer = append(resp.Answer, u.a)
	case dns.TypeTXT:
		resp.Answer = append(resp.Answer, u.txt)
	case dns.TypeDS:
		resp.Answer = append(resp.Answer, u.ds)
	default:
		// Go on.  The RRSIG resource record is added afterward.  This
		// upstream.Upstream implementation doesn't handle explicit
		// requests for it.
	}

	if len(resp.Answer) > 0 {
		resp.Answer[0].Header().Ttl = defaultTestTTL
	}

	if o := m.IsEdns0(); o != nil {
		resp.Answer = append(resp.Answer, u.rrsig)

		resp.SetEdns0(defaultUDPBufSize, o.Do())
	}

	return resp, nil
}

// Address implements the upstream.Upstream interface for *testDNSSECUpstream.
func (u *testDNSSECUpstream) Address() string {
	return ""
}

// Close implements the upstream.Upstream interface for *testDNSSECUpstream.
func (u *testDNSSECUpstream) Close() (err error) {
	return nil
}

func TestProxy_Resolve_dnssecCache(t *testing.T) {
	const host = "example.com"

	const (
		// Larger than UDP buffer size to invoke truncation.
		txtDataLen      = 1024
		txtDataChunkLen = 255
	)

	txtDataChunkNum := txtDataLen / txtDataChunkLen
	if txtDataLen%txtDataChunkLen > 0 {
		txtDataChunkNum++
	}

	txts := make([]string, txtDataChunkNum)
	randData := make([]byte, txtDataLen)
	n, err := rand.Read(randData)
	require.NoError(t, err)
	require.Equal(t, txtDataLen, n)
	for i, c := range randData {
		randData[i] = c%26 + 'a'
	}
	// *dns.TXT requires splitting the actual data into
	// 256-byte chunks.
	for i := 0; i < txtDataChunkNum; i++ {
		r := txtDataChunkLen * (i + 1)
		if r > txtDataLen {
			r = txtDataLen
		}
		txts[i] = string(randData[txtDataChunkLen*i : r])
	}
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(host),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
		},
		Txt: txts,
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

	p := &Proxy{}
	p.UpstreamConfig = &UpstreamConfig{
		Upstreams: []upstream.Upstream{&testDNSSECUpstream{
			a:     a,
			txt:   txt,
			ds:    ds,
			rrsig: rrsig,
		}},
	}
	p.cache = newCache(defaultCacheSize, false, false)

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
		req := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id: dns.Id(),
			},
			Compress: true,
			Question: []dns.Question{{
				Name:   dns.Fqdn(tc.wantAns.Header().Name),
				Qtype:  tc.wantAns.Header().Rrtype,
				Qclass: tc.wantAns.Header().Class,
			}},
		}
		if tc.edns {
			req.SetEdns0(txtDataLen/2, true)
		}

		dctx := &DNSContext{
			Req:   req,
			Proto: ProtoUDP,
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(p.cache.items.Clear)
			err = p.Resolve(dctx)
			require.NoError(t, err)

			res := dctx.Res
			require.NotNil(t, res)

			require.Len(t, res.Answer, tc.wantLen, res.Answer)
			switch tc.wantLen {
			case 0:
				assert.True(t, res.Truncated)
			case 1:
				res.Answer[0].Header().Ttl = defaultTestTTL
				assert.Equal(t, tc.wantAns.String(), res.Answer[0].String())
			case 2:
				res.Answer[0].Header().Ttl = defaultTestTTL
				assert.Equal(t, tc.wantAns.String(), res.Answer[0].String())
				assert.Equal(t, rrsig.String(), res.Answer[1].String())
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

func TestUpstreamsSort(t *testing.T) {
	testProxy := createTestProxy(t, nil)
	upstreams := []upstream.Upstream{}

	// there are 4 upstreams in configuration
	config := []string{"1.2.3.4", "1.1.1.1", "2.3.4.5", "8.8.8.8"}
	for _, u := range config {
		up, err := upstream.AddressToUpstream(u, &upstream.Options{Timeout: 1 * time.Second})
		if err != nil {
			t.Fatalf("Failed to create %s upstream: %s", u, err)
		}
		upstreams = append(upstreams, up)
	}

	upstreamRTTStats := map[string]int{}
	upstreamRTTStats["1.1.1.1:53"] = 10
	upstreamRTTStats["2.3.4.5:53"] = 20
	upstreamRTTStats["1.2.3.4:53"] = 30
	testProxy.upstreamRTTStats = upstreamRTTStats

	sortedUpstreams := testProxy.getSortedUpstreams(upstreams)

	// upstream without rtt stats means `zero rtt`; this upstream should be the first one after sorting
	if sortedUpstreams[0].Address() != "8.8.8.8:53" {
		t.Fatalf("wrong sort algorithm!")
	}

	// upstreams with rtt stats should be sorted from fast to slow
	if sortedUpstreams[1].Address() != "1.1.1.1:53" {
		t.Fatalf("wrong sort algorithm!")
	}

	if sortedUpstreams[2].Address() != "2.3.4.5:53" {
		t.Fatalf("wrong sort algorithm!")
	}

	if sortedUpstreams[3].Address() != "1.2.3.4:53" {
		t.Fatalf("wrong sort algorithm!")
	}
}

func TestExchangeWithReservedDomains(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)

	googleRslv, err := upstream.NewUpstreamResolver("8.8.8.8", &upstream.Options{
		Timeout: 1 * time.Second,
	})
	require.NoError(t, err)

	// Upstreams specification. Domains adguard.com and google.ru reserved
	// with fake upstreams, maps.google.ru excluded from dnsmasq.
	upstreams := []string{
		"[/adguard.com/]1.2.3.4",
		"[/google.ru/]2.3.4.5",
		"[/maps.google.ru/]#",
		"1.1.1.1",
	}
	config, err := ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			InsecureSkipVerify: false,
			Bootstrap:          googleRslv,
			Timeout:            1 * time.Second,
		},
	)
	require.NoError(t, err)

	dnsProxy.UpstreamConfig = config

	err = dnsProxy.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

	// Create a DNS-over-TCP client connection.
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)

	// Create google-a test message.
	req := createTestMessage()
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Make sure that dnsproxy is working.
	res, err := conn.ReadMsg()
	require.NoError(t, err)
	requireResponse(t, req, res)

	// Create adguard.com test message.
	req = createHostTestMessage("adguard.com")
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Test message should not be resolved.
	res, _ = conn.ReadMsg()
	require.Nil(t, res.Answer)

	// Create www.google.ru test message.
	req = createHostTestMessage("www.google.ru")
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Test message should not be resolved.
	res, _ = conn.ReadMsg()
	require.Nil(t, res.Answer)

	// Create maps.google.ru test message.
	req = createHostTestMessage("maps.google.ru")
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	// Test message should be resolved.
	res, _ = conn.ReadMsg()
	require.NotNil(t, res.Answer)
}

// TestOneByOneUpstreamsExchange tries to resolve DNS request
// with one valid and two invalid upstreams
func TestOneByOneUpstreamsExchange(t *testing.T) {
	timeOut := 1 * time.Second
	dnsProxy := createTestProxy(t, nil)

	// invalid fallback to make sure that reply is not coming from fallback
	// server
	var err error
	dnsProxy.Fallbacks, err = ParseUpstreamsConfig(
		[]string{"1.2.3.4:567"},
		&upstream.Options{Timeout: timeOut},
	)
	require.NoError(t, err)

	googleRslv, err := upstream.NewUpstreamResolver("8.8.8.8:53", &upstream.Options{
		Timeout: timeOut,
	})
	require.NoError(t, err)

	// add one valid and two invalid upstreams
	upstreams := []string{"https://fake-dns.com/fake-dns-query", "tls://fake-dns.com", "1.1.1.1"}
	dnsProxy.UpstreamConfig.Upstreams = []upstream.Upstream{}
	for _, line := range upstreams {
		var u upstream.Upstream
		u, err = upstream.AddressToUpstream(
			line,
			&upstream.Options{
				Bootstrap: googleRslv,
				Timeout:   timeOut,
			},
		)
		require.NoError(t, err)

		dnsProxy.UpstreamConfig.Upstreams = append(dnsProxy.UpstreamConfig.Upstreams, u)
	}

	err = dnsProxy.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

	// create a DNS-over-TCP client connection
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)

	// make sure that the response is okay and resolved by valid upstream
	req := createTestMessage()
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	start := time.Now()
	res, err := conn.ReadMsg()
	require.NoError(t, err)
	requireResponse(t, req, res)

	elapsed := time.Since(start)
	if elapsed > 3*timeOut {
		t.Fatalf("the operation took much more time than the configured timeout")
	}
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
	responseCh := make(chan uint16)
	failCh := make(chan uint16)

	const timeout = 1 * time.Second

	successHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		testutil.RequireSend(testutil.PanicT{}, responseCh, r.Id, timeout)

		require.NoError(testutil.PanicT{}, w.WriteMsg((&dns.Msg{}).SetReply(r)))
	})
	failHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		testutil.RequireSend(testutil.PanicT{}, failCh, r.Id, timeout)

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

	dnsProxy := createTestProxy(t, nil)

	var err error
	dnsProxy.UpstreamConfig, err = ParseUpstreamsConfig(
		[]string{
			failAddr,
			"[/specific.example/]" + alsoSuccessAddr,
			// almost.failing.example will fall here first.
			"[/failing.example/]" + failAddr,
		},
		&upstream.Options{Timeout: timeout},
	)
	require.NoError(t, err)

	dnsProxy.Fallbacks, err = ParseUpstreamsConfig(
		[]string{
			failAddr,
			successAddr,
			"[/failing.example/]" + failAddr,
			"[/almost.failing.example/]" + alsoSuccessAddr,
		},
		&upstream.Options{Timeout: timeout},
	)
	require.NoError(t, err)

	err = dnsProxy.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

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
			req := createHostTestMessage(tc.name)
			err = conn.WriteMsg(req)
			require.NoError(t, err)

			for _, ch := range tc.wantSignals {
				reqID, ok := testutil.RequireReceive(testutil.PanicT{}, ch, timeout)
				require.True(t, ok)

				assert.Equal(t, req.Id, reqID)
			}

			_, err = conn.ReadMsg()
			require.NoError(t, err)
		})
	}
}

func TestFallbackFromInvalidBootstrap(t *testing.T) {
	timeout := 1 * time.Second
	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)

	// List of fallback server addresses. Both are valid
	var err error
	dnsProxy.Fallbacks, err = ParseUpstreamsConfig(
		[]string{"1.0.0.1", "8.8.8.8"},
		&upstream.Options{Timeout: timeout},
	)
	require.NoError(t, err)

	invalidRslv, err := upstream.NewUpstreamResolver("8.8.8.8:555", &upstream.Options{
		Timeout: 1 * time.Second,
	})
	require.NoError(t, err)

	// Using a DoT server with invalid bootstrap.
	u, _ := upstream.AddressToUpstream(
		"tls://dns.adguard.com",
		&upstream.Options{
			Bootstrap: invalidRslv,
			Timeout:   timeout,
		},
	)
	dnsProxy.UpstreamConfig.Upstreams = []upstream.Upstream{}
	dnsProxy.UpstreamConfig.Upstreams = append(dnsProxy.UpstreamConfig.Upstreams, u)

	// Start listening
	err = dnsProxy.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)

	// Make sure that the response is okay and resolved by the fallback
	req := createTestMessage()
	err = conn.WriteMsg(req)
	require.NoError(t, err)

	start := time.Now()
	res, err := conn.ReadMsg()
	require.NoError(t, err)
	requireResponse(t, req, res)

	elapsed := time.Since(start)
	if elapsed > 3*timeout {
		t.Fatalf("the operation took much more time than the configured timeout")
	}
}

func TestRefuseAny(t *testing.T) {
	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.RefuseAny = true

	// Start listening
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	// Create a DNS request
	request := dns.Msg{}
	request.Id = dns.Id()
	request.RecursionDesired = true
	request.SetQuestion("google.com.", dns.TypeANY)

	r, _, err := client.Exchange(&request, addr.String())
	if err != nil {
		t.Fatalf("error in the first request: %s", err)
	}

	if r.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("wrong response code (must've been NotImpl)")
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func TestInvalidDNSRequest(t *testing.T) {
	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.RefuseAny = true

	// Start listening
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	// Create a DNS request
	request := dns.Msg{}
	request.Id = dns.Id()
	request.RecursionDesired = true

	r, _, err := client.Exchange(&request, addr.String())
	if err != nil {
		t.Fatalf("error in the first request: %s", err)
	}

	if r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("wrong response code (must've been ServerFailure)")
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

// Server must drop incoming Response messages
func TestResponseInRequest(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	err := dnsProxy.Start()
	assert.Nil(t, err)

	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	req := createTestMessage()
	req.Response = true

	r, _, err := client.Exchange(req, addr.String())
	assert.NotNil(t, err)
	assert.Nil(t, r)

	_ = dnsProxy.Stop()
}

// Server must respond with SERVFAIL to requests without a Question
func TestNoQuestion(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	require.NoError(t, dnsProxy.Start())
	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	req := createTestMessage()
	req.Question = nil

	r, _, err := client.Exchange(req, addr.String())
	require.NoError(t, err)

	assert.Equal(t, dns.RcodeServerFailure, r.Rcode)
}

// funcUpstream is a mock upstream implementation to simplify testing.  It
// allows assigning custom Exchange and Address methods.
type funcUpstream struct {
	exchangeFunc func(m *dns.Msg) (resp *dns.Msg, err error)
	addressFunc  func() (addr string)
}

// type check
var _ upstream.Upstream = (*funcUpstream)(nil)

// Exchange implements upstream.Upstream interface for *funcUpstream.
func (wu *funcUpstream) Exchange(m *dns.Msg) (*dns.Msg, error) {
	if wu.exchangeFunc == nil {
		return nil, nil
	}

	return wu.exchangeFunc(m)
}

// Address implements upstream.Upstream interface for *funcUpstream.
func (wu *funcUpstream) Address() (addr string) {
	if wu.addressFunc == nil {
		return "stub"
	}

	return wu.addressFunc()
}

// Close implements upstream.Upstream interface for *funcUpstream.
func (wu *funcUpstream) Close() (err error) {
	return nil
}

func TestProxy_ReplyFromUpstream_badResponse(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	require.NoError(t, dnsProxy.Start())
	testutil.CleanupAndRequireSuccess(t, dnsProxy.Stop)

	exchangeFunc := func(m *dns.Msg) (resp *dns.Msg, err error) {
		resp = &dns.Msg{}
		resp.SetReply(m)
		hdr := dns.RR_Header{
			Name:   m.Question[0].Name,
			Class:  dns.ClassINET,
			Rrtype: dns.TypeA,
		}
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: hdr,
			A:   net.IP{1, 2, 3, 4},
		})
		// Make the response invalid.
		resp.Question = []dns.Question{}

		return resp, nil
	}
	u := &funcUpstream{
		exchangeFunc: exchangeFunc,
	}

	d := &DNSContext{
		CustomUpstreamConfig: NewCustomUpstreamConfig(
			&UpstreamConfig{Upstreams: []upstream.Upstream{u}},
			false,
			0,
			false,
		),
		Req:  createHostTestMessage("host"),
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
	prx := createTestProxy(t, nil)
	err := prx.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, prx.Stop)

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
		Req:  createHostTestMessage("host"),
		Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
	}

	err = prx.Resolve(&d)
	require.NoError(t, err)

	assert.Equal(t, ansIP, getIPFromResponse(d.Res))
}

func TestExchangeCustomUpstreamConfigCache(t *testing.T) {
	prx := createTestProxy(t, nil)
	prx.CacheEnabled = true
	prx.initCache()

	err := prx.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, prx.Stop)

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
	u := &funcUpstream{
		exchangeFunc: exchangeFunc,
	}

	customUpstreamConfig := NewCustomUpstreamConfig(
		&UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		true,
		defaultCacheSize,
		prx.EnableEDNSClientSubnet,
	)

	d := DNSContext{
		CustomUpstreamConfig: customUpstreamConfig,
		Req:                  createHostTestMessage("host"),
		Addr:                 netip.MustParseAddrPort("1.2.3.0:1234"),
	}

	err = prx.Resolve(&d)
	require.NoError(t, err)

	assert.Equal(t, 1, count)
	assert.Equal(t, ansIP, getIPFromResponse(d.Res))

	err = prx.Resolve(&d)
	require.NoError(t, err)

	assert.Equal(t, 1, count)
	assert.Equal(t, ansIP, getIPFromResponse(d.Res))

	customUpstreamConfig.ClearCache()

	err = prx.Resolve(&d)
	require.NoError(t, err)

	assert.Equal(t, 2, count)
	assert.Equal(t, ansIP, getIPFromResponse(d.Res))
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
	prx := createTestProxy(t, nil)
	prx.EnableEDNSClientSubnet = true
	prx.CacheEnabled = true

	var (
		ip1230 = net.IP{1, 2, 3, 0}
		ip2230 = net.IP{2, 2, 3, 0}
		ip4321 = net.IP{4, 3, 2, 1}
		ip4322 = net.IP{4, 3, 2, 2}
		ip4323 = net.IP{4, 3, 2, 3}
	)

	u := testUpstream{
		ans: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 60},
			A:   ip4321,
		}},
		ecsIP: ip1230,
	}
	prx.UpstreamConfig.Upstreams = []upstream.Upstream{&u}
	err := prx.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, prx.Stop)

	t.Run("cache_subnet", func(t *testing.T) {
		d := DNSContext{
			Req:  createHostTestMessage("host"),
			Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
		}

		err = prx.Resolve(&d)
		require.NoError(t, err)

		assert.Equal(t, net.IP{4, 3, 2, 1}, getIPFromResponse(d.Res))
		assert.Equal(t, ip1230, u.ecsReqIP)
	})

	t.Run("serve_subnet_cache", func(t *testing.T) {
		d := DNSContext{
			Req:  createHostTestMessage("host"),
			Addr: netip.MustParseAddrPort("1.2.3.1:1234"),
		}
		u.ans, u.ecsIP, u.ecsReqIP = nil, nil, nil

		err = prx.Resolve(&d)
		require.NoError(t, err)

		assert.Equal(t, ip4321, getIPFromResponse(d.Res))
		assert.Nil(t, u.ecsReqIP)
	})

	t.Run("another_subnet", func(t *testing.T) {
		d := DNSContext{
			Req:  createHostTestMessage("host"),
			Addr: netip.MustParseAddrPort("2.2.3.0:1234"),
		}
		u.ans = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 60},
			A:   ip4322,
		}}
		u.ecsIP = ip2230

		err = prx.Resolve(&d)
		require.NoError(t, err)

		assert.Equal(t, ip4322, getIPFromResponse(d.Res))
		assert.Equal(t, ip2230, u.ecsReqIP)
	})

	t.Run("cache_general", func(t *testing.T) {
		d := DNSContext{
			Req:  createHostTestMessage("host"),
			Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
		}
		u.ans = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 60},
			A:   ip4323,
		}}
		u.ecsIP, u.ecsReqIP = nil, nil

		err = prx.Resolve(&d)
		require.NoError(t, err)

		assert.Equal(t, ip4323, getIPFromResponse(d.Res))
		assert.Nil(t, u.ecsReqIP)
	})

	t.Run("serve_general_cache", func(t *testing.T) {
		d := DNSContext{
			Req:  createHostTestMessage("host"),
			Addr: netip.MustParseAddrPort("127.0.0.2:1234"),
		}
		u.ans, u.ecsIP, u.ecsReqIP = nil, nil, nil

		err = prx.Resolve(&d)
		require.NoError(t, err)

		assert.Equal(t, ip4323, getIPFromResponse(d.Res))
		assert.Nil(t, u.ecsReqIP)
	})
}

func TestECSProxyCacheMinMaxTTL(t *testing.T) {
	clientIP := net.IP{1, 2, 3, 0}

	prx := createTestProxy(t, nil)
	prx.EnableEDNSClientSubnet = true
	prx.CacheEnabled = true
	prx.CacheMinTTL = 20
	prx.CacheMaxTTL = 40
	u := testUpstream{
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
	prx.UpstreamConfig.Upstreams = []upstream.Upstream{&u}
	err := prx.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, prx.Stop)

	// first request
	d := DNSContext{
		Req:  createHostTestMessage("host"),
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
	d.Req = createHostTestMessage("host")
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

func createTestDNSCryptProxy(t *testing.T) (*Proxy, dnscrypt.ResolverConfig) {
	p := createTestProxy(t, nil)
	p.UDPListenAddr = nil
	p.TCPListenAddr = nil
	port := getFreePort()
	p.DNSCryptUDPListenAddr = []*net.UDPAddr{
		{Port: int(port), IP: net.ParseIP(listenIP)},
	}
	p.DNSCryptTCPListenAddr = []*net.TCPAddr{
		{Port: int(port), IP: net.ParseIP(listenIP)},
	}

	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil)
	assert.Nil(t, err)

	cert, err := rc.CreateCert()
	assert.Nil(t, err)

	p.DNSCryptProviderName = rc.ProviderName
	p.DNSCryptResolverCert = cert
	return p, rc
}

func getFreePort() uint {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := uint(l.Addr().(*net.TCPAddr).Port)

	// stop listening immediately
	_ = l.Close()

	// sleep for 100ms (may be necessary on Windows)
	time.Sleep(100 * time.Millisecond)
	return port
}

func createTestProxy(t *testing.T, tlsConfig *tls.Config) *Proxy {
	t.Helper()

	p := Proxy{}

	if ip := net.ParseIP(listenIP); tlsConfig != nil {
		p.TLSListenAddr = []*net.TCPAddr{{IP: ip, Port: 0}}
		p.HTTPSListenAddr = []*net.TCPAddr{{IP: ip, Port: 0}}
		p.QUICListenAddr = []*net.UDPAddr{{IP: ip, Port: 0}}
		p.TLSConfig = tlsConfig
	} else {
		p.UDPListenAddr = []*net.UDPAddr{{IP: ip, Port: 0}}
		p.TCPListenAddr = []*net.TCPAddr{{IP: ip, Port: 0}}
	}
	upstreams := make([]upstream.Upstream, 0)
	dnsUpstream, err := upstream.AddressToUpstream(
		upstreamAddr,
		&upstream.Options{Timeout: defaultTimeout},
	)
	require.NoError(t, err)

	p.UpstreamConfig = &UpstreamConfig{}
	p.UpstreamConfig.Upstreams = append(upstreams, dnsUpstream)

	p.TrustedProxies = []string{"0.0.0.0/0", "::0/0"}

	p.RatelimitSubnetLenIPv4 = 24
	p.RatelimitSubnetLenIPv6 = 64

	return &p
}

func sendTestMessageAsync(t *testing.T, conn *dns.Conn, g *sync.WaitGroup) {
	defer func() {
		g.Done()
	}()

	req := createTestMessage()
	err := conn.WriteMsg(req)
	require.NoError(t, err)

	res, err := conn.ReadMsg()
	require.NoError(t, err)

	// We do not check if msg IDs match because the order of responses may
	// be different.

	require.NotNil(t, res)
	require.Lenf(t, res.Answer, 1, "wrong number of answers: %d", len(res.Answer))
	a, ok := res.Answer[0].(*dns.A)
	require.Truef(t, ok, "wrong answer type: %v", res.Answer[0])
	require.Equalf(t, net.IPv4(8, 8, 8, 8), a.A.To16(), "wrong answer: %v", a.A)
}

// sendTestMessagesAsync sends messages in parallel
// so that we could find race issues
func sendTestMessagesAsync(t *testing.T, conn *dns.Conn) {
	g := &sync.WaitGroup{}
	g.Add(testMessagesCount)

	for i := 0; i < testMessagesCount; i++ {
		go sendTestMessageAsync(t, conn, g)
	}

	g.Wait()
}

func sendTestMessages(t *testing.T, conn *dns.Conn) {
	for i := 0; i < 10; i++ {
		req := createTestMessage()
		err := conn.WriteMsg(req)
		if err != nil {
			t.Fatalf("cannot write message #%d: %s", i, err)
		}

		res, err := conn.ReadMsg()
		if err != nil {
			t.Fatalf("cannot read response to message #%d: %s", i, err)
		}
		requireResponse(t, req, res)
	}
}

func createTestMessage() *dns.Msg {
	return createHostTestMessage("google-public-dns-a.google.com")
}

func createHostTestMessage(host string) *dns.Msg {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	name := host + "."
	req.Question = []dns.Question{
		{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	return &req
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

func createServerTLSConfig(t *testing.T) (*tls.Config, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key: %s", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("failed to generate serial number: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * time.Hour * 24)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AdGuard Tests"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	template.DNSNames = append(template.DNSNames, tlsServerName)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(privateKey), privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}, ServerName: tlsServerName}, certPem
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// Return the first A value in response
func getIPFromResponse(resp *dns.Msg) net.IP {
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

func TestProxy_Resolve_withOptimisticResolver(t *testing.T) {
	const (
		host             = "some.domain.name."
		nonOptimisticTTL = 3600
	)

	buildCtx := func() (dctx *DNSContext) {
		req := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id: dns.Id(),
			},
			Question: []dns.Question{{
				Name:   host,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		return &DNSContext{
			Req: req,
		}
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
