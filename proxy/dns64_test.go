package proxy_test

import (
	"cmp"
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/AdguardTeam/dnsproxy/dnsproxytest"
	proxytest "github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSynTTL is a common TTL for DNS64 synthesized records.
const testSynTTL uint32 = 600

func TestProxy_HandleDNSRequest_dns64Race(t *testing.T) {
	fakeHost := proxytest.Host

	ans := proxytest.NewRR(t, proxytest.FQDN, dns.TypeA, proxytest.TTL, proxytest.IPv4)
	ups := &dnsproxytest.Upstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(req)
			if req.Question[0].Qtype == dns.TypeA {
				resp.Answer = []dns.RR{dns.Copy(ans)}
			}

			return resp, nil
		},
		OnAddress: func() (addr string) { return fakeHost },
		OnClose:   func() (err error) { return nil },
	}
	localUps := &dnsproxytest.Upstream{
		OnExchange: func(ctx context.Context, m *dns.Msg) (_ *dns.Msg, _ error) {
			panic(testutil.UnexpectedCall(ctx, m))
		},
		OnAddress: func() (addr string) { return fakeHost },
		OnClose:   func() (err error) { return nil },
	}

	dnsProxy, err := proxy.New(&proxy.Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		PrivateSubnets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		PrivateRDNSUpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{localUps},
		},
		TrustedProxies: proxytest.DefaultTrustedProxies,

		UseDNS64:       true,
		UsePrivateRDNS: true,
		// Valid NAT-64 prefix for 2001:67c:27e4:15::64 server.
		DNS64Prefs: []netip.Prefix{netip.MustParsePrefix("2001:67c:27e4:1064::/96")},
	})
	require.NoError(t, err)

	servicetest.RequireRun(t, dnsProxy, proxytest.Timeout)

	syncCh := make(chan struct{})

	// Send requests.
	g := &sync.WaitGroup{}
	g.Add(proxytest.MessageCount)

	addr := dnsProxy.Addr(proxy.ProtoTCP).String()
	for range proxytest.MessageCount {
		// The [dns.Conn] isn't safe for concurrent use despite the requirements
		// from the [net.Conn] documentation.
		var conn *dns.Conn
		conn, err = dns.Dial("tcp", addr)
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, conn.Close)

		go exchangeTestAAAARequestAsync(t, conn, g, proxytest.FQDN, syncCh)
	}

	close(syncCh)
	g.Wait()
}

// exchangeTestAAAARequestAsync is a test helper that sends an AAAA DNS request
// for the given FQDN and verifies the response contains a single AAAA record.
// It is intended to be used as a goroutine.
func exchangeTestAAAARequestAsync(
	tb testing.TB,
	conn *dns.Conn,
	g *sync.WaitGroup,
	fqdn string,
	syncCh chan struct{},
) {
	tb.Helper()

	pt := testutil.NewPanicT(tb)

	defer g.Done()

	req := (&dns.Msg{}).SetQuestion(fqdn, dns.TypeAAAA)
	<-syncCh

	err := conn.WriteMsg(req)
	require.NoError(pt, err)

	res, err := conn.ReadMsg()
	require.NoError(pt, err)
	require.Equal(pt, dns.RcodeSuccess, res.Rcode)
	require.NotEmpty(pt, res.Answer)

	require.IsType(pt, &dns.AAAA{}, res.Answer[0])
}

// Section indexes for upstream mock responses.
const (
	dns64SectionAnswer = iota
	dns64SectionAuthority
	dns64SectionAdditional

	dns64SectionsNum
)

// dns64AnswerMap describes upstream response sections for each question type.
type dns64AnswerMap = map[uint16][dns64SectionsNum][]dns.RR

func TestProxy_Resolve_dns64Simple(t *testing.T) {
	t.Parallel()

	ansA := proxytest.NewRR(t, proxytest.FQDN, dns.TypeA, proxytest.TTL, proxytest.IPv4)
	ansAAAA := proxytest.NewRR(t, proxytest.FQDN, dns.TypeAAAA, proxytest.TTL, proxytest.IPv6)

	testCases := []struct {
		name    string
		qname   string
		upsAns  dns64AnswerMap
		wantAns []dns.RR
		qtype   uint16
	}{{
		name:  "a",
		qname: proxytest.FQDN,
		upsAns: dns64AnswerMap{
			dns.TypeA: {
				dns64SectionAnswer: {ansA},
			},
			dns.TypeAAAA: {},
		},
		wantAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:     proxytest.FQDN,
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      proxytest.TTL,
				Rdlength: 4,
			},
			A: proxytest.IPv4.To4(),
		}},
		qtype: dns.TypeA,
	}, {
		name:  "aaaa",
		qname: proxytest.FQDN,
		upsAns: dns64AnswerMap{
			dns.TypeA: {},
			dns.TypeAAAA: {
				dns64SectionAnswer: {ansAAAA},
			},
		},
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:     proxytest.FQDN,
				Rrtype:   dns.TypeAAAA,
				Class:    dns.ClassINET,
				Ttl:      proxytest.TTL,
				Rdlength: 16,
			},
			AAAA: proxytest.IPv6,
		}},
		qtype: dns.TypeAAAA,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testProxyResolveDNS64(t, tc.qname, tc.qtype, tc.upsAns, tc.wantAns, nil)
		})
	}
}

func TestProxy_Resolve_dns64Synthesis(t *testing.T) {
	t.Parallel()

	someIPv4 := net.IP{1, 2, 3, 4}
	mappedIPv6 := net.ParseIP("64:ff9b::102:304")

	const (
		domainSOA     = "soa." + proxytest.FQDN
		fqdnCNAMEOnly = "cname." + proxytest.FQDN
		fqdnTerminal  = "terminal." + proxytest.FQDN
	)

	ansA := proxytest.NewRR(t, proxytest.FQDN, dns.TypeA, 3600, someIPv4)
	soaA := proxytest.NewRR(t, domainSOA, dns.TypeA, 3600, someIPv4)
	soa := proxytest.NewRR(t, domainSOA, dns.TypeSOA, testSynTTL+50, nil)
	cnameAnswers := dns64AnswerMap{
		dns.TypeA: {
			dns64SectionAnswer: {
				proxytest.NewRR(t, fqdnCNAMEOnly, dns.TypeCNAME, 3600, fqdnTerminal),
				proxytest.NewRR(t, fqdnTerminal, dns.TypeA, 3600, someIPv4),
			},
		},
		dns.TypeAAAA: {
			dns64SectionAnswer: {
				proxytest.NewRR(t, fqdnCNAMEOnly, dns.TypeCNAME, 3600, fqdnTerminal),
			},
			dns64SectionAuthority: {
				proxytest.NewRR(t, fqdnTerminal, dns.TypeSOA, proxytest.TTL, nil),
			},
		},
	}
	cnameWantAns := []dns.RR{
		&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:     fqdnCNAMEOnly,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 11,
			},
			Target: fqdnTerminal,
		},
		&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:     fqdnTerminal,
				Rrtype:   dns.TypeAAAA,
				Class:    dns.ClassINET,
				Ttl:      testSynTTL,
				Rdlength: 16,
			},
			AAAA: mappedIPv6,
		},
	}

	testCases := []struct {
		name    string
		qname   string
		upsAns  dns64AnswerMap
		wantAns []dns.RR
		qtype   uint16
	}{{
		name:  "default_ttl",
		qname: proxytest.FQDN,
		upsAns: dns64AnswerMap{
			dns.TypeA: {
				dns64SectionAnswer: {ansA},
			},
			dns.TypeAAAA: {},
		},
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:     proxytest.FQDN,
				Rrtype:   dns.TypeAAAA,
				Class:    dns.ClassINET,
				Ttl:      testSynTTL,
				Rdlength: 16,
			},
			AAAA: mappedIPv6,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:  "soa_ttl",
		qname: domainSOA,
		upsAns: dns64AnswerMap{
			dns.TypeA: {
				dns64SectionAnswer: {soaA},
			},
			dns.TypeAAAA: {
				dns64SectionAuthority: {soa},
			},
		},
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:     domainSOA,
				Rrtype:   dns.TypeAAAA,
				Class:    dns.ClassINET,
				Ttl:      testSynTTL + 50,
				Rdlength: 16,
			},
			AAAA: mappedIPv6,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:    "cname_chain_no_aaaa",
		qname:   fqdnCNAMEOnly,
		upsAns:  cnameAnswers,
		wantAns: cnameWantAns,
		qtype:   dns.TypeAAAA,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testProxyResolveDNS64(t, tc.qname, tc.qtype, tc.upsAns, tc.wantAns, nil)
		})
	}
}

func TestProxy_Resolve_dns64Filtered(t *testing.T) {
	t.Parallel()

	filteredIPv6 := net.ParseIP("64:ff9b::506:708")

	const (
		domainMapped  = proxytest.FQDN
		domainAnother = "another." + proxytest.FQDN
	)

	ansAAAA := proxytest.NewRR(t, domainMapped, dns.TypeAAAA, proxytest.TTL, filteredIPv6)
	ansCNAME := proxytest.NewRR(t, domainMapped, dns.TypeCNAME, proxytest.TTL, domainAnother)
	upsAns := dns64AnswerMap{
		dns.TypeA: {},
		dns.TypeAAAA: {
			dns64SectionAnswer: {
				ansAAAA,
				ansCNAME,
			},
		},
	}
	wantAns := []dns.RR{&dns.CNAME{
		Hdr: dns.RR_Header{
			Name:     domainMapped,
			Rrtype:   dns.TypeCNAME,
			Class:    dns.ClassINET,
			Ttl:      proxytest.TTL,
			Rdlength: 10,
		},
		Target: domainAnother,
	}}

	testProxyResolveDNS64(t, domainMapped, dns.TypeAAAA, upsAns, wantAns, nil)
}

func TestProxy_Resolve_dns64PTR(t *testing.T) {
	t.Parallel()

	someIPv4 := net.IP{1, 2, 3, 4}
	mappedIPv6 := net.ParseIP("64:ff9b::102:304")

	ptr64Domain, err := netutil.IPToReversedAddr(mappedIPv6)
	require.NoError(t, err)
	ptr64Domain = dns.Fqdn(ptr64Domain)

	ptrGlobDomain, err := netutil.IPToReversedAddr(someIPv4)
	require.NoError(t, err)
	ptrGlobDomain = dns.Fqdn(ptrGlobDomain)

	const (
		domainPointed = "local." + proxytest.FQDN
		domainGlob    = proxytest.FQDN
	)

	localRR := proxytest.NewRR(t, ptr64Domain, dns.TypePTR, proxytest.TTL, domainPointed)
	globalRR := proxytest.NewRR(t, ptrGlobDomain, dns.TypePTR, proxytest.TTL, domainGlob)
	pt := testutil.NewPanicT(t)
	localUps := newTestUpstreamWithExchange(
		t,
		func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			require.Equal(pt, ptr64Domain, req.Question[0].Name)
			resp = (&dns.Msg{}).SetReply(req)
			resp.Answer = []dns.RR{localRR}

			return resp, nil
		},
	)

	testCases := []struct {
		name    string
		qname   string
		upsAns  dns64AnswerMap
		wantAns []dns.RR
		qtype   uint16
	}{{
		name:   "local",
		qname:  ptr64Domain,
		upsAns: nil,
		wantAns: []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{
				Name:     ptr64Domain,
				Rrtype:   dns.TypePTR,
				Class:    dns.ClassINET,
				Ttl:      proxytest.TTL,
				Rdlength: 20,
			},
			Ptr: domainPointed,
		}},
		qtype: dns.TypePTR,
	}, {
		name:  "global",
		qname: ptrGlobDomain,
		upsAns: dns64AnswerMap{
			dns.TypePTR: {
				dns64SectionAnswer: {globalRR},
			},
		},
		wantAns: []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{
				Name:     ptrGlobDomain,
				Rrtype:   dns.TypePTR,
				Class:    dns.ClassINET,
				Ttl:      proxytest.TTL,
				Rdlength: 14,
			},
			Ptr: domainGlob,
		}},
		qtype: dns.TypePTR,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testProxyResolveDNS64(t, tc.qname, tc.qtype, tc.upsAns, tc.wantAns, localUps)
		})
	}
}

// testProxyResolveDNS64 starts a DNS64 proxy and checks its response.  localUps
// handles private reverse DNS requests.  If nil, such requests fail the test.
func testProxyResolveDNS64(
	tb testing.TB,
	qname string,
	qtype uint16,
	upsAns dns64AnswerMap,
	wantAns []dns.RR,
	localUps upstream.Upstream,
) {
	onExchange := func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		q := req.Question[0]

		pt := testutil.NewPanicT(tb)
		require.Contains(pt, upsAns, q.Qtype)

		answer := upsAns[q.Qtype]
		resp = (&dns.Msg{}).SetReply(req)
		resp.Answer = answer[dns64SectionAnswer]
		resp.Ns = answer[dns64SectionAuthority]
		resp.Extra = answer[dns64SectionAdditional]

		return resp, nil
	}
	ups := newTestUpstreamWithExchange(tb, onExchange)

	localUps = cmp.Or(localUps, newTestUpstreamWithExchange(tb,
		func(ctx context.Context, req *dns.Msg) (_ *dns.Msg, _ error) {
			panic(testutil.UnexpectedCall(ctx, req))
		},
	))

	p, err := proxy.New(&proxy.Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		PrivateRDNSUpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{localUps},
		},
		TrustedProxies: proxytest.DefaultTrustedProxies,
		CacheEnabled:   true,
		UseDNS64:       true,
		UsePrivateRDNS: true,
		PrivateSubnets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
	})
	require.NoError(tb, err)
	servicetest.RequireRun(tb, p, proxytest.Timeout)

	conn, err := dns.Dial("tcp", p.Addr(proxy.ProtoTCP).String())
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, conn.Close)

	err = conn.WriteMsg((&dns.Msg{}).SetQuestion(qname, qtype))
	require.NoError(tb, err)

	res, err := conn.ReadMsg()
	require.NoError(tb, err)
	require.NotNil(tb, res)

	assert.Equal(tb, wantAns, res.Answer)
}
