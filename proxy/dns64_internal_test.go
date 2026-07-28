package proxy

import (
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ipv4OnlyFqdn = "ipv4.only."

func TestDNS64Race(t *testing.T) {
	ans := newRR(t, ipv4OnlyFqdn, dns.TypeA, 3600, net.ParseIP("1.2.3.4"))
	ups := &dnsproxytest.Upstream{
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(req)
			if req.Question[0].Qtype == dns.TypeA {
				resp.Answer = []dns.RR{dns.Copy(ans)}
			}

			return resp, nil
		},
		OnAddress: func() (addr string) { return "fake.address" },
		OnClose:   func() (err error) { return nil },
	}
	localUps := &dnsproxytest.Upstream{
		OnExchange: func(m *dns.Msg) (_ *dns.Msg, _ error) { panic(testutil.UnexpectedCall(m)) },
		OnAddress:  func() (addr string) { return "fake.address" },
		OnClose:    func() (err error) { return nil },
	}

	dnsProxy := mustNew(t, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		PrivateSubnets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		PrivateRDNSUpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{localUps},
		},
		TrustedProxies: defaultTrustedProxies,

		UseDNS64:       true,
		UsePrivateRDNS: true,
		// Valid NAT-64 prefix for 2001:67c:27e4:15::64 server.
		DNS64Prefs: []netip.Prefix{netip.MustParsePrefix("2001:67c:27e4:1064::/96")},
	})

	servicetest.RequireRun(t, dnsProxy, testTimeout)

	syncCh := make(chan struct{})

	// Send requests.
	g := &sync.WaitGroup{}
	g.Add(testMessagesCount)

	addr := dnsProxy.Addr(ProtoTCP).String()
	for range testMessagesCount {
		// The [dns.Conn] isn't safe for concurrent use despite the requirements
		// from the [net.Conn] documentation.
		conn, err := dns.Dial("tcp", addr)
		require.NoError(t, err)

		go sendTestAAAAMessageAsync(conn, g, ipv4OnlyFqdn, syncCh)
	}

	close(syncCh)
	g.Wait()
}

func sendTestAAAAMessageAsync(conn *dns.Conn, g *sync.WaitGroup, fqdn string, syncCh chan struct{}) {
	pt := testutil.PanicT{}

	defer g.Done()

	req := (&dns.Msg{}).SetQuestion(fqdn, dns.TypeAAAA)
	<-syncCh

	err := conn.WriteMsg(req)
	require.NoError(pt, err)

	res, err := conn.ReadMsg()
	require.NoError(pt, err)
	require.Equal(pt, res.Rcode, dns.RcodeSuccess)
	require.NotEmpty(pt, res.Answer)

	require.IsType(pt, &dns.AAAA{}, res.Answer[0])
}

// newRR is a helper that creates a new dns.RR with the given name, qtype,
// ttl and value.  It fails the test if the qtype is not supported or the type
// of value doesn't match the qtype.
func newRR(tb testing.TB, name string, qtype uint16, ttl uint32, val any) (rr dns.RR) {
	tb.Helper()

	switch qtype {
	case dns.TypeA:
		rr = &dns.A{A: testutil.RequireTypeAssert[net.IP](tb, val)}
	case dns.TypeAAAA:
		rr = &dns.AAAA{AAAA: testutil.RequireTypeAssert[net.IP](tb, val)}
	case dns.TypeCNAME:
		rr = &dns.CNAME{Target: testutil.RequireTypeAssert[string](tb, val)}
	case dns.TypeSOA:
		rr = &dns.SOA{
			Ns:      "ns." + name,
			Mbox:    "hostmaster." + name,
			Serial:  1,
			Refresh: 1,
			Retry:   1,
			Expire:  1,
			Minttl:  1,
		}
	case dns.TypePTR:
		rr = &dns.PTR{Ptr: testutil.RequireTypeAssert[string](tb, val)}
	default:
		tb.Fatalf("unsupported qtype: %d", qtype)
	}

	*rr.Header() = dns.RR_Header{
		Name:   name,
		Rrtype: qtype,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}

	return rr
}

// TODO(e.burkov):  Refactor the test.
func TestProxy_Resolve_dns64(t *testing.T) {
	someIPv4 := net.IP{1, 2, 3, 4}
	someIPv6 := net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	mappedIPv6 := net.ParseIP("64:ff9b::102:304")

	ptr64Domain, err := netutil.IPToReversedAddr(mappedIPv6)
	require.NoError(t, err)
	ptr64Domain = dns.Fqdn(ptr64Domain)

	ptrGlobDomain, err := netutil.IPToReversedAddr(someIPv4)
	require.NoError(t, err)
	ptrGlobDomain = dns.Fqdn(ptrGlobDomain)

	localCliAddr := netip.MustParseAddrPort("192.168.1.1:1234")

	const (
		domainIPv6    = "ipv6.only."
		domainSOA     = "ipv4.soa."
		domainMapped  = "filterable.ipv6."
		domainAnother = "another.domain."

		domainPointed = "local1234.ipv4."
		domainGlob    = "real1234.ipv4."

		fqdnCNAMEOnly = "cname.chain."
		fqdnTerminal  = "terminal.node."
	)

	const (
		sectionAnswer = iota
		sectionAuthority
		sectionAdditional

		sectionsNum
	)

	// answerMap is a convenience alias for describing the upstream response for
	// a given question type.
	type answerMap = map[uint16][sectionsNum][]dns.RR

	pt := testutil.PanicT{}
	newUps := func(answers answerMap) (u upstream.Upstream) {
		return &dnsproxytest.Upstream{
			OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
				q := req.Question[0]
				require.Contains(pt, answers, q.Qtype)

				answer := answers[q.Qtype]

				resp = (&dns.Msg{}).SetReply(req)
				resp.Answer = answer[sectionAnswer]
				resp.Ns = answer[sectionAuthority]
				resp.Extra = answer[sectionAdditional]

				return resp, nil
			},
			OnAddress: func() (addr string) { return "fake.address" },
			OnClose:   func() (err error) { return nil },
		}
	}

	localRR := newRR(t, ptr64Domain, dns.TypePTR, 3600, domainPointed)
	localUps := &dnsproxytest.Upstream{
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			require.Equal(pt, req.Question[0].Name, ptr64Domain)
			resp = (&dns.Msg{}).SetReply(req)
			resp.Answer = []dns.RR{localRR}

			return resp, nil
		},
		OnAddress: func() (addr string) { return "fake.local.address" },
		OnClose:   func() (err error) { return nil },
	}

	testCases := []struct {
		name    string
		qname   string
		upsAns  answerMap
		wantAns []dns.RR
		qtype   uint16
	}{{
		name:  "simple_a",
		qname: ipv4OnlyFqdn,
		upsAns: answerMap{
			dns.TypeA: {
				sectionAnswer: {newRR(t, ipv4OnlyFqdn, dns.TypeA, 3600, someIPv4)},
			},
			dns.TypeAAAA: {},
		},
		wantAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   ipv4OnlyFqdn,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: someIPv4,
		}},
		qtype: dns.TypeA,
	}, {
		name:  "simple_aaaa",
		qname: domainIPv6,
		upsAns: answerMap{
			dns.TypeA: {},
			dns.TypeAAAA: {
				sectionAnswer: {newRR(t, domainIPv6, dns.TypeAAAA, 3600, someIPv6)},
			},
		},
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   domainIPv6,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			AAAA: someIPv6,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:  "actual_dns64",
		qname: ipv4OnlyFqdn,
		upsAns: answerMap{
			dns.TypeA: {
				sectionAnswer: {newRR(t, ipv4OnlyFqdn, dns.TypeA, 3600, someIPv4)},
			},
			dns.TypeAAAA: {},
		},
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   ipv4OnlyFqdn,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    maxDNS64SynTTL,
			},
			AAAA: mappedIPv6,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:  "actual_dns64_soattl",
		qname: domainSOA,
		upsAns: answerMap{
			dns.TypeA: {
				sectionAnswer: {newRR(t, domainSOA, dns.TypeA, 3600, someIPv4)},
			},
			dns.TypeAAAA: {
				sectionAuthority: {newRR(t, domainSOA, dns.TypeSOA, maxDNS64SynTTL+50, nil)},
			},
		},
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   domainSOA,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    maxDNS64SynTTL + 50,
			},
			AAAA: mappedIPv6,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:  "filtered",
		qname: domainMapped,
		upsAns: answerMap{
			dns.TypeA: {},
			dns.TypeAAAA: {
				sectionAnswer: {
					newRR(t, domainMapped, dns.TypeAAAA, 3600, net.ParseIP("64:ff9b::506:708")),
					newRR(t, domainMapped, dns.TypeCNAME, 3600, domainAnother),
				},
			},
		},
		wantAns: []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   domainMapped,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Target: domainAnother,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:   "ptr",
		qname:  ptr64Domain,
		upsAns: nil,
		wantAns: []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{
				Name:   ptr64Domain,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ptr: domainPointed,
		}},
		qtype: dns.TypePTR,
	}, {
		name:  "ptr_glob",
		qname: ptrGlobDomain,
		upsAns: answerMap{
			dns.TypePTR: {
				sectionAnswer: {newRR(t, ptrGlobDomain, dns.TypePTR, 3600, domainGlob)},
			},
		},
		wantAns: []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{
				Name:   ptrGlobDomain,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ptr: domainGlob,
		}},
		qtype: dns.TypePTR,
	}, {
		name:  "dns64_cname_chain_no_aaaa",
		qname: fqdnCNAMEOnly, // e.g., "cname.chain."
		upsAns: answerMap{
			dns.TypeA: {
				sectionAnswer: {
					newRR(t, fqdnCNAMEOnly, dns.TypeCNAME, 3600, fqdnTerminal),
					newRR(t, fqdnTerminal, dns.TypeA, 3600, someIPv4),
				},
			},
			dns.TypeAAAA: {
				sectionAnswer: {
					newRR(t, fqdnCNAMEOnly, dns.TypeCNAME, 3600, fqdnTerminal),
				},
				sectionAuthority: {
					newRR(t, fqdnTerminal, dns.TypeSOA, 300, nil),
				},
			},
		},
		wantAns: []dns.RR{
			&dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   fqdnCNAMEOnly,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Target: fqdnTerminal,
			},
			&dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   fqdnTerminal,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    maxDNS64SynTTL,
				},
				AAAA: mappedIPv6,
			},
		},
		qtype: dns.TypeAAAA,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustNew(t, &Config{
				Logger:        testLogger,
				UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
				TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
				UpstreamConfig: &UpstreamConfig{
					Upstreams: []upstream.Upstream{newUps(tc.upsAns)},
				},
				PrivateRDNSUpstreamConfig: &UpstreamConfig{
					Upstreams: []upstream.Upstream{localUps},
				},
				TrustedProxies: defaultTrustedProxies,
				CacheEnabled:   true,

				UseDNS64:       true,
				UsePrivateRDNS: true,
				PrivateSubnets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
			})

			servicetest.RequireRun(t, p, testTimeout)

			dctx := &DNSContext{
				Req:  (&dns.Msg{}).SetQuestion(tc.qname, tc.qtype),
				Addr: localCliAddr,
			}

			err = p.handleDNSRequest(testutil.ContextWithTimeout(t, defaultTimeout), dctx)
			require.NoError(t, err)

			res := dctx.Res
			require.NotNil(t, res)
			assert.Equal(t, tc.wantAns, res.Answer)
		})
	}
}
