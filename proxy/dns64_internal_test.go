package proxy

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ipv4OnlyFqdn = "ipv4.only."

func TestDNS64Race(t *testing.T) {
	ans := newRR(t, ipv4OnlyFqdn, dns.TypeA, 3600, net.ParseIP("1.2.3.4"))
	ups := &dnsproxytest.FakeUpstream{
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
	localUps := &dnsproxytest.FakeUpstream{
		OnExchange: func(_ *dns.Msg) (_ *dns.Msg, _ error) { panic("not implemented") },
		OnAddress:  func() (addr string) { return "fake.address" },
		OnClose:    func() (err error) { return nil },
	}

	dnsProxy := mustNew(t, &Config{
		Logger:         slogutil.NewDiscardLogger(),
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		PrivateSubnets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		PrivateRDNSUpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{localUps},
		},
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,

		UseDNS64:       true,
		UsePrivateRDNS: true,
		// Valid NAT-64 prefix for 2001:67c:27e4:15::64 server.
		DNS64Prefs: []netip.Prefix{netip.MustParsePrefix("2001:67c:27e4:1064::/96")},
	})

	ctx := context.Background()
	err := dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	syncCh := make(chan struct{})

	// Send requests.
	g := &sync.WaitGroup{}
	g.Add(testMessagesCount)

	addr := dnsProxy.Addr(ProtoTCP).String()
	for range testMessagesCount {
		// The [dns.Conn] isn't safe for concurrent use despite the requirements
		// from the [net.Conn] documentation.
		var conn *dns.Conn
		conn, err = dns.Dial("tcp", addr)
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
func newRR(t *testing.T, name string, qtype uint16, ttl uint32, val any) (rr dns.RR) {
	t.Helper()

	switch qtype {
	case dns.TypeA:
		rr = &dns.A{A: testutil.RequireTypeAssert[net.IP](t, val)}
	case dns.TypeAAAA:
		rr = &dns.AAAA{AAAA: testutil.RequireTypeAssert[net.IP](t, val)}
	case dns.TypeCNAME:
		rr = &dns.CNAME{Target: testutil.RequireTypeAssert[string](t, val)}
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
		rr = &dns.PTR{Ptr: testutil.RequireTypeAssert[string](t, val)}
	default:
		t.Fatalf("unsupported qtype: %d", qtype)
	}

	*rr.Header() = dns.RR_Header{
		Name:   name,
		Rrtype: qtype,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}

	return rr
}

func TestProxy_Resolve_dns64(t *testing.T) {
	const (
		ipv6Domain    = "ipv6.only."
		soaDomain     = "ipv4.soa."
		mappedDomain  = "filterable.ipv6."
		anotherDomain = "another.domain."

		pointedDomain = "local1234.ipv4."
		globDomain    = "real1234.ipv4."
	)

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
		return &dnsproxytest.FakeUpstream{
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

	localRR := newRR(t, ptr64Domain, dns.TypePTR, 3600, pointedDomain)
	localUps := &dnsproxytest.FakeUpstream{
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
		qname: ipv6Domain,
		upsAns: answerMap{
			dns.TypeA: {},
			dns.TypeAAAA: {
				sectionAnswer: {newRR(t, ipv6Domain, dns.TypeAAAA, 3600, someIPv6)},
			},
		},
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   ipv6Domain,
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
		qname: soaDomain,
		upsAns: answerMap{
			dns.TypeA: {
				sectionAnswer: {newRR(t, soaDomain, dns.TypeA, 3600, someIPv4)},
			},
			dns.TypeAAAA: {
				sectionAuthority: {newRR(t, soaDomain, dns.TypeSOA, maxDNS64SynTTL+50, nil)},
			},
		},
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   soaDomain,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    maxDNS64SynTTL + 50,
			},
			AAAA: mappedIPv6,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:  "filtered",
		qname: mappedDomain,
		upsAns: answerMap{
			dns.TypeA: {},
			dns.TypeAAAA: {
				sectionAnswer: {
					newRR(t, mappedDomain, dns.TypeAAAA, 3600, net.ParseIP("64:ff9b::506:708")),
					newRR(t, mappedDomain, dns.TypeCNAME, 3600, anotherDomain),
				},
			},
		},
		wantAns: []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   mappedDomain,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Target: anotherDomain,
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
			Ptr: pointedDomain,
		}},
		qtype: dns.TypePTR,
	}, {
		name:  "ptr_glob",
		qname: ptrGlobDomain,
		upsAns: answerMap{
			dns.TypePTR: {
				sectionAnswer: {newRR(t, ptrGlobDomain, dns.TypePTR, 3600, globDomain)},
			},
		},
		wantAns: []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{
				Name:   ptrGlobDomain,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ptr: globDomain,
		}},
		qtype: dns.TypePTR,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustNew(t, &Config{
				Logger:        slogutil.NewDiscardLogger(),
				UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
				TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
				UpstreamConfig: &UpstreamConfig{
					Upstreams: []upstream.Upstream{newUps(tc.upsAns)},
				},
				PrivateRDNSUpstreamConfig: &UpstreamConfig{
					Upstreams: []upstream.Upstream{localUps},
				},
				TrustedProxies:         defaultTrustedProxies,
				RatelimitSubnetLenIPv4: 24,
				RatelimitSubnetLenIPv6: 64,
				CacheEnabled:           true,

				UseDNS64:       true,
				UsePrivateRDNS: true,
				PrivateSubnets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
			})

			ctx := context.Background()
			err = p.Start(ctx)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, func() (err error) { return p.Shutdown(ctx) })

			dctx := &DNSContext{
				Req:  (&dns.Msg{}).SetQuestion(tc.qname, tc.qtype),
				Addr: localCliAddr,
			}

			err = p.handleDNSRequest(dctx)
			require.NoError(t, err)

			res := dctx.Res
			require.NotNil(t, res)
			assert.Equal(t, tc.wantAns, res.Answer)
		})
	}
}
