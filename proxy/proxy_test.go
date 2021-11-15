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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/log"
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

func (u *testDNSSECUpstream) Address() string {
	return ""
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
		txtDataChunkNum += 1
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
	p.cache = &cache{
		items: glcache.New(glcache.Config{
			MaxSize:   defaultCacheSize,
			EnableLRU: true,
		}),
	}

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

			cached, expired, key := p.cache.Get(dctx.Req)
			require.NotNil(t, cached)
			require.Len(t, cached.Answer, 2)
			assert.False(t, expired)
			assert.Equal(t, key, msgToKey(dctx.Req))

			// Just make it match.
			cached.Answer[0].Header().Ttl = defaultTestTTL
			assert.Equal(t, tc.wantAns.String(), cached.Answer[0].String())
			assert.Equal(t, rrsig.String(), cached.Answer[1].String())
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

	// create upstreamRttStats for 3 upstreams
	upstreamRttStats := map[string]int{}
	upstreamRttStats["1.1.1.1:53"] = 10
	upstreamRttStats["2.3.4.5:53"] = 20
	upstreamRttStats["1.2.3.4:53"] = 30
	testProxy.upstreamRttStats = upstreamRttStats

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

	// upstreams specification. Domains adguard.com and google.ru reserved with fake upstreams, maps.google.ru excluded from dnsmasq.
	upstreams := []string{"[/adguard.com/]1.2.3.4", "[/google.ru/]2.3.4.5", "[/maps.google.ru/]#", "1.1.1.1"}
	config, err := ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			InsecureSkipVerify: false,
			Bootstrap:          []string{"8.8.8.8"},
			Timeout:            1 * time.Second,
		})
	if err != nil {
		t.Fatalf("Error while upstream config parsing: %s", err)
	}
	dnsProxy.UpstreamConfig = config

	err = dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// create a DNS-over-TCP client connection
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("cannot connect to the proxy: %s", err)
	}

	// create google-a test message
	req := createTestMessage()
	err = conn.WriteMsg(req)
	if err != nil {
		t.Fatalf("cannot write message: %s", err)
	}

	// make sure if dnsproxy is working
	res, err := conn.ReadMsg()
	if err != nil {
		t.Fatalf("cannot read response to message: %s", err)
	}
	assertResponse(t, res)

	// create adguard.com test message
	req = createHostTestMessage("adguard.com")
	err = conn.WriteMsg(req)
	if err != nil {
		t.Fatalf("cannot write message: %s", err)
	}

	// test message should not be resolved
	res, _ = conn.ReadMsg()
	if res.Answer != nil {
		t.Fatal("adguard.com should not be resolved")
	}

	// create www.google.ru test message
	req = createHostTestMessage("www.google.ru")
	err = conn.WriteMsg(req)
	if err != nil {
		t.Fatalf("cannot write message: %s", err)
	}

	// test message should not be resolved
	res, _ = conn.ReadMsg()
	if res.Answer != nil {
		t.Fatal("www.google.ru should not be resolved")
	}

	// create maps.google.ru test message
	req = createHostTestMessage("maps.google.ru")
	err = conn.WriteMsg(req)
	if err != nil {
		t.Fatalf("cannot write message: %s", err)
	}

	// test message should be resolved
	res, _ = conn.ReadMsg()
	if res.Answer == nil {
		t.Fatal("maps.google.ru should be resolved")
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

// TestOneByOneUpstreamsExchange tries to resolve DNS request
// with one valid and two invalid upstreams
func TestOneByOneUpstreamsExchange(t *testing.T) {
	timeOut := 1 * time.Second
	dnsProxy := createTestProxy(t, nil)

	// invalid fallback to make sure that reply is not coming from fallback server
	dnsProxy.Fallbacks = []upstream.Upstream{}
	fallback := "1.2.3.4:567"
	f, err := upstream.AddressToUpstream(
		fallback,
		&upstream.Options{Timeout: timeOut},
	)
	if err != nil {
		t.Fatalf("cannot create fallback upstream %s cause %s", fallback, err)
	}
	dnsProxy.Fallbacks = append(dnsProxy.Fallbacks, f)

	// add one valid and two invalid upstreams
	upstreams := []string{"https://fake-dns.com/fake-dns-query", "tls://fake-dns.com", "1.1.1.1"}
	dnsProxy.UpstreamConfig.Upstreams = []upstream.Upstream{}
	for _, line := range upstreams {
		var u upstream.Upstream
		u, err = upstream.AddressToUpstream(
			line,
			&upstream.Options{
				Bootstrap: []string{"8.8.8.8:53"},
				Timeout:   timeOut,
			},
		)
		if err != nil {
			t.Fatalf("cannot create upstream %s cause %s", line, err)
		}

		dnsProxy.UpstreamConfig.Upstreams = append(dnsProxy.UpstreamConfig.Upstreams, u)
	}

	err = dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// create a DNS-over-TCP client connection
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("cannot connect to the proxy: %s", err)
	}

	// make sure that the response is okay and resolved by valid upstream
	req := createTestMessage()
	err = conn.WriteMsg(req)
	if err != nil {
		t.Fatalf("cannot write message: %s", err)
	}

	start := time.Now()
	res, err := conn.ReadMsg()
	if err != nil {
		t.Fatalf("cannot read response to message: %s", err)
	}
	assertResponse(t, res)

	elapsed := time.Since(start)
	if elapsed > 3*timeOut {
		t.Fatalf("the operation took much more time than the configured timeout")
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func TestFallback(t *testing.T) {
	timeout := 1 * time.Second
	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)

	// List of fallback server addresses. Only one is valid
	fallbackAddresses := []string{"1.2.3.4", "1.2.3.5", "8.8.8.8"}
	dnsProxy.Fallbacks = []upstream.Upstream{}

	for _, s := range fallbackAddresses {
		f, _ := upstream.AddressToUpstream(
			s,
			&upstream.Options{Timeout: timeout},
		)
		dnsProxy.Fallbacks = append(dnsProxy.Fallbacks, f)
	}

	// using some random port to make sure that this upstream won't work
	u, _ := upstream.AddressToUpstream(
		"8.8.8.8:555",
		&upstream.Options{Timeout: timeout},
	)
	dnsProxy.UpstreamConfig = &UpstreamConfig{}
	dnsProxy.UpstreamConfig.Upstreams = make([]upstream.Upstream, 0)
	dnsProxy.UpstreamConfig.Upstreams = append(dnsProxy.UpstreamConfig.Upstreams, u)

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

	// Make sure that the response is okay and resolved by the fallback
	req := createTestMessage()
	err = conn.WriteMsg(req)
	if err != nil {
		t.Fatalf("cannot write message: %s", err)
	}

	start := time.Now()
	res, err := conn.ReadMsg()
	if err != nil {
		t.Fatalf("cannot read response to message: %s", err)
	}
	assertResponse(t, res)

	elapsed := time.Since(start)
	if elapsed > 3*timeout {
		t.Fatalf("the operation took much more time than the configured timeout")
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func TestFallbackFromInvalidBootstrap(t *testing.T) {
	timeout := 1 * time.Second
	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)

	// List of fallback server addresses. Both are valid
	fallbackAddresses := []string{"1.0.0.1", "8.8.8.8"}
	dnsProxy.Fallbacks = []upstream.Upstream{}

	for _, s := range fallbackAddresses {
		f, _ := upstream.AddressToUpstream(
			s,
			&upstream.Options{Timeout: timeout},
		)
		dnsProxy.Fallbacks = append(dnsProxy.Fallbacks, f)
	}

	// using a DOT server with invalid bootstrap
	u, _ := upstream.AddressToUpstream(
		"tls://dns.adguard.com",
		&upstream.Options{
			Bootstrap: []string{"8.8.8.8:555"},
			Timeout:   timeout,
		},
	)
	dnsProxy.UpstreamConfig.Upstreams = []upstream.Upstream{}
	dnsProxy.UpstreamConfig.Upstreams = append(dnsProxy.UpstreamConfig.Upstreams, u)

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

	// Make sure that the response is okay and resolved by the fallback
	req := createTestMessage()
	err = conn.WriteMsg(req)
	if err != nil {
		t.Fatalf("cannot write message: %s", err)
	}

	start := time.Now()
	res, err := conn.ReadMsg()
	if err != nil {
		t.Fatalf("cannot read response to message: %s", err)
	}
	assertResponse(t, res)

	elapsed := time.Since(start)
	if elapsed > 3*timeout {
		t.Fatalf("the operation took much more time than the configured timeout")
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
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
	t.Cleanup(func() {
		require.NoError(t, dnsProxy.Stop())
	})

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

// Exchange implements upstream.Upstream interface for *funcUpstream.
func (wu *funcUpstream) Exchange(m *dns.Msg) (*dns.Msg, error) {
	if wu.exchangeFunc == nil {
		return nil, nil
	}

	return wu.exchangeFunc(m)
}

// Address implements upstream.Upstream interface for *funcUpstream.
func (wu *funcUpstream) Address() string {
	if wu.addressFunc == nil {
		return "stub"
	}

	return wu.addressFunc()
}

func TestProxy_ReplyFromUpstream_badResponse(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	require.NoError(t, dnsProxy.Start())
	t.Cleanup(func() {
		require.NoError(t, dnsProxy.Stop())
	})

	exchangeFunc := func(m *dns.Msg) (resp *dns.Msg, err error) {
		resp = &dns.Msg{}
		resp.SetReply(m)
		hdr := dns.RR_Header{
			Name:   m.Question[0].Name,
			Class:  dns.ClassINET,
			Rrtype: uint16(dns.TypeA),
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
		CustomUpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		Req:                  createHostTestMessage("host"),
		Addr: &net.TCPAddr{
			IP: net.IP{1, 2, 3, 0},
		},
	}

	var err error
	require.NotPanics(t, func() {
		err = dnsProxy.Resolve(d)
	})
	require.NoError(t, err)

	assert.Equal(t, d.Req.Question[0], d.Res.Question[0])
}

func TestExchangeCustomUpstreamConfig(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	err := dnsProxy.Start()
	assert.True(t, err == nil)

	// this upstream will be used as a custom
	u := testUpstream{}
	u.aResp = new(dns.A)
	u.aResp.Hdr.Rrtype = dns.TypeA
	u.aResp.Hdr.Name = "host."
	u.aResp.A = net.IP{4, 3, 2, 1}
	u.aResp.Hdr.Ttl = 60
	config := &UpstreamConfig{Upstreams: []upstream.Upstream{&u}}

	// test request
	d := DNSContext{}
	d.CustomUpstreamConfig = config
	d.Req = createHostTestMessage("host")
	d.Addr = &net.TCPAddr{
		IP: net.IP{1, 2, 3, 0},
	}

	err = dnsProxy.Resolve(&d)
	assert.Nil(t, err)
	assert.Equal(t, u.aResp.A, getIPFromResponse(d.Res))
}

func TestECS(t *testing.T) {
	m := &dns.Msg{}
	_, mask := setECS(m, net.IP{1, 2, 3, 0}, 16)
	assert.True(t, mask == 24)
	ip, mask, scope := parseECS(m)
	assert.True(t, ip.Equal(net.IP{1, 2, 3, 0}))
	assert.True(t, mask == 24)
	assert.True(t, scope == 16)
}

// Resolve the same host with the different client subnet values
func TestECSProxy(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.EnableEDNSClientSubnet = true
	dnsProxy.CacheEnabled = true
	u := testUpstream{}
	dnsProxy.UpstreamConfig.Upstreams = []upstream.Upstream{&u}
	err := dnsProxy.Start()
	assert.True(t, err == nil)

	// first request
	d := DNSContext{}
	d.Req = createHostTestMessage("host")
	d.Addr = &net.TCPAddr{
		IP: net.IP{1, 2, 3, 0},
	}
	u.aResp = new(dns.A)
	u.aResp.Hdr.Rrtype = dns.TypeA
	u.aResp.Hdr.Name = "host."
	u.aResp.A = net.IP{4, 3, 2, 1}
	u.aResp.Hdr.Ttl = 60
	u.ecsIP = net.IP{1, 2, 3, 0}
	err = dnsProxy.Resolve(&d)
	assert.True(t, err == nil)
	assert.True(t, getIPFromResponse(d.Res).Equal(net.IP{4, 3, 2, 1}))
	assert.True(t, u.ecsReqIP.Equal(net.IP{1, 2, 3, 0}))

	// request from another client with the same subnet - must be served from cache
	d.Req = createHostTestMessage("host")
	d.Addr = &net.TCPAddr{
		IP: net.IP{1, 2, 3, 1},
	}
	u.aResp = nil
	u.ecsIP = nil
	u.ecsReqIP = nil
	err = dnsProxy.Resolve(&d)
	assert.True(t, err == nil)
	assert.True(t, getIPFromResponse(d.Res).Equal(net.IP{4, 3, 2, 1}))
	assert.True(t, u.ecsReqIP == nil)

	// request from a different subnet - different response
	d.Req = createHostTestMessage("host")
	d.Addr = &net.TCPAddr{
		IP: net.IP{2, 2, 3, 0},
	}
	u.aResp = new(dns.A)
	u.aResp.Hdr.Name = "host."
	u.aResp.A = net.IP{4, 3, 2, 2}
	u.aResp.Hdr.Ttl = 60
	u.ecsIP = net.IP{2, 2, 3, 0}
	u.ecsReqIP = nil
	err = dnsProxy.Resolve(&d)
	assert.True(t, err == nil)
	assert.True(t, getIPFromResponse(d.Res).Equal(net.IP{4, 3, 2, 2}))
	assert.True(t, u.ecsReqIP.Equal(net.IP{2, 2, 3, 0}))

	// request from a local IP - store in general (not subnet-aware) cache
	d.Req = createHostTestMessage("host")
	d.Addr = &net.TCPAddr{
		IP: net.IP{127, 0, 0, 1},
	}
	u.aResp = new(dns.A)
	u.aResp.Hdr.Rrtype = dns.TypeA
	u.aResp.Hdr.Name = "host."
	u.aResp.A = net.IP{4, 3, 2, 3}
	u.aResp.Hdr.Ttl = 60
	u.ecsIP = nil
	u.ecsReqIP = nil
	err = dnsProxy.Resolve(&d)
	assert.True(t, err == nil)
	assert.True(t, getIPFromResponse(d.Res).Equal(net.IP{4, 3, 2, 3}))
	assert.True(t, u.ecsReqIP == nil)

	// request from another local IP - get from general cache
	d.Req = createHostTestMessage("host")
	d.Addr = &net.TCPAddr{
		IP: net.IP{127, 0, 0, 2},
	}
	u.aResp = nil
	u.ecsIP = nil
	u.ecsReqIP = nil
	err = dnsProxy.Resolve(&d)
	assert.True(t, err == nil)
	assert.True(t, getIPFromResponse(d.Res).Equal(net.IP{4, 3, 2, 3}))
	assert.True(t, u.ecsReqIP == nil)

	_ = dnsProxy.Stop()
}

func TestECSProxyCacheMinMaxTTL(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.EnableEDNSClientSubnet = true
	dnsProxy.CacheEnabled = true
	dnsProxy.CacheMinTTL = 20
	dnsProxy.CacheMaxTTL = 40
	u := testUpstream{}
	dnsProxy.UpstreamConfig.Upstreams = []upstream.Upstream{&u}
	err := dnsProxy.Start()
	assert.True(t, err == nil)

	// first request
	clientIP := net.IP{1, 2, 3, 0}
	d := DNSContext{}
	d.Req = createHostTestMessage("host")
	d.Addr = &net.TCPAddr{
		IP: clientIP,
	}
	u.aResp = new(dns.A)
	u.aResp.Hdr.Rrtype = dns.TypeA
	u.aResp.Hdr.Name = "host."
	u.aResp.A = net.IP{4, 3, 2, 1}
	u.aResp.Hdr.Ttl = 10
	u.ecsIP = clientIP
	err = dnsProxy.Resolve(&d)
	assert.True(t, err == nil)

	// get from cache - check min TTL
	m, expired, key := dnsProxy.cache.GetWithSubnet(d.Req, clientIP, 24)
	assert.False(t, expired)
	assert.Equal(t, key, msgToKeyWithSubnet(d.Req, clientIP, 24))
	assert.True(t, m.Answer[0].Header().Ttl == dnsProxy.CacheMinTTL)

	// 2nd request
	clientIP = net.IP{1, 2, 4, 0}
	d.Req = createHostTestMessage("host")
	d.Addr = &net.TCPAddr{
		IP: clientIP,
	}
	u.aResp = new(dns.A)
	u.aResp.Hdr.Rrtype = dns.TypeA
	u.aResp.Hdr.Name = "host."
	u.aResp.A = net.IP{4, 3, 2, 1}
	u.aResp.Hdr.Ttl = 60
	u.ecsIP = clientIP
	err = dnsProxy.Resolve(&d)
	assert.True(t, err == nil)

	// get from cache - check max TTL
	m, expired, key = dnsProxy.cache.GetWithSubnet(d.Req, clientIP, 24)
	assert.False(t, expired)
	assert.Equal(t, key, msgToKeyWithSubnet(d.Req, clientIP, 24))
	assert.True(t, m.Answer[0].Header().Ttl == dnsProxy.CacheMaxTTL)

	_ = dnsProxy.Stop()
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
	l, _ := net.Listen("tcp", ":0")
	port := uint(l.Addr().(*net.TCPAddr).Port)

	// stop listening immediately
	_ = l.Close()

	// sleep for 100ms (may be necessary on Windows)
	time.Sleep(100 * time.Millisecond)
	return port
}

func createTestProxy(t *testing.T, tlsConfig *tls.Config) *Proxy {
	p := Proxy{}

	if tlsConfig != nil {
		p.TLSListenAddr = []*net.TCPAddr{
			{Port: 0, IP: net.ParseIP(listenIP)},
		}
		p.HTTPSListenAddr = []*net.TCPAddr{
			{Port: 0, IP: net.ParseIP(listenIP)},
		}
		p.QUICListenAddr = []*net.UDPAddr{
			{Port: 0, IP: net.ParseIP(listenIP)},
		}
		p.TLSConfig = tlsConfig
	} else {
		p.UDPListenAddr = []*net.UDPAddr{
			{Port: 0, IP: net.ParseIP(listenIP)},
		}
		p.TCPListenAddr = []*net.TCPAddr{
			{Port: 0, IP: net.ParseIP(listenIP)},
		}
	}
	upstreams := make([]upstream.Upstream, 0)
	dnsUpstream, err := upstream.AddressToUpstream(
		upstreamAddr,
		&upstream.Options{Timeout: defaultTimeout},
	)
	if err != nil {
		t.Fatalf("cannot prepare the upstream: %s", err)
	}
	p.UpstreamConfig = &UpstreamConfig{}
	p.UpstreamConfig.Upstreams = append(upstreams, dnsUpstream)

	p.TrustedProxies = []string{"0.0.0.0/0", "::0/0"}

	return &p
}

func sendTestMessageAsync(t *testing.T, conn *dns.Conn, g *sync.WaitGroup) {
	defer func() {
		g.Done()
	}()

	req := createTestMessage()
	err := conn.WriteMsg(req)
	if err != nil {
		t.Errorf("cannot write message: %s", err)

		return
	}

	res, err := conn.ReadMsg()
	if err != nil {
		t.Errorf("cannot read response to message: %s", err)

		return
	}

	assertResponse(t, res)
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
		assertResponse(t, res)
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

func assertResponse(t *testing.T, reply *dns.Msg) {
	t.Helper()

	if len(reply.Answer) != 1 {
		t.Fatalf("DNS upstream returned reply with wrong number of answers - %d", len(reply.Answer))
	}
	if a, ok := reply.Answer[0].(*dns.A); ok {
		if !net.IPv4(8, 8, 8, 8).Equal(a.A) {
			t.Fatalf("DNS upstream returned wrong answer instead of 8.8.8.8: %v", a.A)
		}
	} else {
		t.Fatalf("DNS upstream returned wrong answer type instead of A: %v", reply.Answer[0])
	}
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
	cname1Resp *dns.CNAME
	aResp      *dns.A
	aRespArr   []*dns.A
	ecsIP      net.IP
	ecsReqIP   net.IP
	ecsReqMask uint8
}

func (u *testUpstream) Exchange(m *dns.Msg) (*dns.Msg, error) {
	resp := dns.Msg{}
	resp.SetReply(m)

	if u.cname1Resp != nil {
		resp.Answer = append(resp.Answer, u.cname1Resp)
	}

	resp.Answer = append(resp.Answer, u.aResp)

	for _, a := range u.aRespArr {
		resp.Answer = append(resp.Answer, a)
	}

	u.ecsReqIP, u.ecsReqMask, _ = parseECS(m)
	if u.ecsIP != nil {
		_, _ = setECS(&resp, u.ecsIP, 24)
	}

	return &resp, nil
}

func (u *testUpstream) Address() string {
	return ""
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

	testFunc := func(t *testing.T, responsed bool) (firstCtx *DNSContext) {
		p.initCache()
		out, in := make(chan unit), make(chan unit)
		p.shortFlighter.resolve = func(dctx *DNSContext) (ok bool, err error) {
			dctx.Res = buildResp(dctx.Req, nonOptimisticTTL)

			return responsed, nil
		}
		p.shortFlighter.set = func(dctx *DNSContext) {
			defer func() {
				out <- unit{}
			}()

			// Report adding to cache is in process.
			out <- unit{}
			// Wait for tests to finish.
			<-in

			p.setInCache(dctx)
		}
		p.shortFlighter.delete = func(k []byte) {
			defer func() {
				out <- unit{}
			}()

			// Report deleting from cache is in process.
			out <- unit{}
			// Wait for tests to finish.
			<-in

			p.cache.Delete(k)
		}

		// Two different contexts are made to emulate two different
		// requests with the same question section.
		var secondCtx *DNSContext
		firstCtx, secondCtx = buildCtx(), buildCtx()

		// Add expired response into cache.
		req := firstCtx.Req
		key := msgToKey(req)
		data := packResponse(buildResp(req, 0))
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

		return firstCtx
	}

	t.Run("successful", func(t *testing.T) {
		firstCtx := testFunc(t, true)

		// Should be served from cache.
		data := p.cache.items.Get(msgToKey(firstCtx.Req))
		unpacked, expired := unpackResponse(data, firstCtx.Req, false)
		require.False(t, expired)
		require.NotNil(t, unpacked)
		require.Len(t, unpacked.Answer, 1)

		assert.EqualValues(t, nonOptimisticTTL, unpacked.Answer[0].Header().Ttl)
	})

	t.Run("unsuccessful", func(t *testing.T) {
		firstCtx := testFunc(t, false)

		// Should be removed from cache.
		assert.Nil(t, p.cache.items.Get(msgToKey(firstCtx.Req)))
	})
}
