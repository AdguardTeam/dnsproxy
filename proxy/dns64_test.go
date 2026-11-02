package proxy_test

import (
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
	fakeHost := "fake.address"

	ans := proxytest.NewRR(t, proxytest.FQDN, dns.TypeA, 3600, proxytest.IPv4)
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

// TODO(f.setrakov):  Refactor the test.
func TestProxy_Resolve_dns64(t *testing.T) {
	someIPv4 := net.IP{1, 2, 3, 4}
	someIPv6 := net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	mappedIPv6 := net.ParseIP("64:ff9b::102:304")
	filteredIPv6 := net.ParseIP("64:ff9b::506:708")

	ptr64Domain, err := netutil.IPToReversedAddr(mappedIPv6)
	require.NoError(t, err)
	ptr64Domain = dns.Fqdn(ptr64Domain)

	ptrGlobDomain, err := netutil.IPToReversedAddr(someIPv4)
	require.NoError(t, err)
	ptrGlobDomain = dns.Fqdn(ptrGlobDomain)

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

	pt := testutil.NewPanicT(t)
	newUps := func(answers answerMap) (u upstream.Upstream) {
		return &dnsproxytest.Upstream{
			OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
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

	localRR := proxytest.NewRR(t, ptr64Domain, dns.TypePTR, 3600, domainPointed)
	localUps := &dnsproxytest.Upstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
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
		qname: proxytest.FQDN,
		upsAns: answerMap{
			dns.TypeA: {
				sectionAnswer: {proxytest.NewRR(t, proxytest.FQDN, dns.TypeA, 3600, someIPv4)},
			},
			dns.TypeAAAA: {},
		},
		wantAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:     proxytest.FQDN,
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 4,
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
				sectionAnswer: {proxytest.NewRR(t, domainIPv6, dns.TypeAAAA, 3600, someIPv6)},
			},
		},
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:     domainIPv6,
				Rrtype:   dns.TypeAAAA,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 16,
			},
			AAAA: someIPv6,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:  "actual_dns64",
		qname: proxytest.FQDN,
		upsAns: answerMap{
			dns.TypeA: {
				sectionAnswer: {proxytest.NewRR(t, proxytest.FQDN, dns.TypeA, 3600, someIPv4)},
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
		name:  "actual_dns64_soattl",
		qname: domainSOA,
		upsAns: answerMap{
			dns.TypeA: {
				sectionAnswer: {proxytest.NewRR(t, domainSOA, dns.TypeA, 3600, someIPv4)},
			},
			dns.TypeAAAA: {
				sectionAuthority: {proxytest.NewRR(t, domainSOA, dns.TypeSOA, testSynTTL+50, nil)},
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
		name:  "filtered",
		qname: domainMapped,
		upsAns: answerMap{
			dns.TypeA: {},
			dns.TypeAAAA: {
				sectionAnswer: {
					proxytest.NewRR(t, domainMapped, dns.TypeAAAA, 3600, filteredIPv6),
					proxytest.NewRR(t, domainMapped, dns.TypeCNAME, 3600, domainAnother),
				},
			},
		},
		wantAns: []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:     domainMapped,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 16,
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
				Name:     ptr64Domain,
				Rrtype:   dns.TypePTR,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 16,
			},
			Ptr: domainPointed,
		}},
		qtype: dns.TypePTR,
	}, {
		name:  "ptr_glob",
		qname: ptrGlobDomain,
		upsAns: answerMap{
			dns.TypePTR: {
				sectionAnswer: {proxytest.NewRR(t, ptrGlobDomain, dns.TypePTR, 3600, domainGlob)},
			},
		},
		wantAns: []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{
				Name:     ptrGlobDomain,
				Rrtype:   dns.TypePTR,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 15,
			},
			Ptr: domainGlob,
		}},
		qtype: dns.TypePTR,
	}, {
		name:  "dns64_cname_chain_no_aaaa",
		qname: fqdnCNAMEOnly,
		upsAns: answerMap{
			dns.TypeA: {
				sectionAnswer: {
					proxytest.NewRR(t, fqdnCNAMEOnly, dns.TypeCNAME, 3600, fqdnTerminal),
					proxytest.NewRR(t, fqdnTerminal, dns.TypeA, 3600, someIPv4),
				},
			},
			dns.TypeAAAA: {
				sectionAnswer: {
					proxytest.NewRR(t, fqdnCNAMEOnly, dns.TypeCNAME, 3600, fqdnTerminal),
				},
				sectionAuthority: {
					proxytest.NewRR(t, fqdnTerminal, dns.TypeSOA, 300, nil),
				},
			},
		},
		wantAns: []dns.RR{
			&dns.CNAME{
				Hdr: dns.RR_Header{
					Name:     fqdnCNAMEOnly,
					Rrtype:   dns.TypeCNAME,
					Class:    dns.ClassINET,
					Ttl:      3600,
					Rdlength: 15,
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
		},
		qtype: dns.TypeAAAA,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			udpAddr := net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)
			tcpAddr := net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)

			var p *proxy.Proxy
			p, err = proxy.New(&proxy.Config{
				Logger:        testLogger,
				UDPListenAddr: []*net.UDPAddr{udpAddr},
				TCPListenAddr: []*net.TCPAddr{tcpAddr},
				UpstreamConfig: &proxy.UpstreamConfig{
					Upstreams: []upstream.Upstream{newUps(tc.upsAns)},
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
			require.NoError(t, err)
			servicetest.RequireRun(t, p, proxytest.Timeout)

			var conn *dns.Conn
			conn, err = dns.Dial("tcp", p.Addr(proxy.ProtoTCP).String())
			require.NoError(t, err)

			err = conn.WriteMsg((&dns.Msg{}).SetQuestion(tc.qname, tc.qtype))
			require.NoError(t, err)

			var res *dns.Msg
			res, err = conn.ReadMsg()
			require.NoError(t, err)
			require.NotNil(t, res)

			assert.Equal(t, tc.wantAns, res.Answer)
		})
	}
}
