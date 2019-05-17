package mobile

import (
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDecodeFilteringRules(t *testing.T) {
	const filtersJSON = `
	[
		{"id": 1, "contents": "||google.com^\n||google.ru^\n||google.ua^\n"},
		{"id": 11, "contents": "0.0.0.0 yandex.ru\n0.0.0.0 yandex.ua\n0.0.0.0 bing.com"},
		{"id": 111, "contents": "2000:: bing.com\n::1 yahoo.com"}
	]`

	filters, err := decodeFilteringRulesMap(filtersJSON)
	assert.Nil(t, err)
	assert.Equal(t, len(filters), 3)

	rs, err := urlfilter.NewRuleStorage("")
	assert.Nil(t, err)
	engine := urlfilter.NewDNSEngine(filters, rs)
	assert.Equal(t, engine.RulesCount, 8)

	rules, ok := engine.Match("bing.com")
	assert.True(t, ok)
	assert.Equal(t, len(rules), 2)

	rules, ok = engine.Match("yandex.ru")
	assert.True(t, ok)
	assert.Equal(t, len(rules), 1)
	assert.Equal(t, rules[0].GetFilterListID(), 11)

	rules, ok = engine.Match("google.ru")
	assert.True(t, ok)
	assert.Equal(t, len(rules), 1)
	assert.Equal(t, rules[0].GetFilterListID(), 1)

	_, ok = engine.Match("example.org")
	assert.False(t, ok)

	err = rs.Close()
	assert.Nil(t, err)
}

// TestFilteringProxy test all kinds of DNS filtering rules:
// Network filtering rules should block request for any kind of request
// IPv4 Host filtering rules should block only A requests
// IPv6 Host filtering rules should block only AAAA requests
func TestFilteringProxy(t *testing.T) {
	mobileDNSProxy := createTestFilteringProxy()

	listener := &testDNSRequestProcessedListener{}
	ConfigureDNSRequestProcessedListener(listener)

	// Start listening
	err := mobileDNSProxy.Start()
	assert.Nil(t, err)

	// Create a DNS-over-TCP client connection
	addr := mobileDNSProxy.dnsProxy.Addr(proxy.ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	assert.Nil(t, err)

	// Create, send and assert regular test message
	sendAndAssertTestMessage(t, conn)

	// There are Network filtering rules, which matched this hosts
	testNetworkFilteringRule(t, conn, "example.com")
	testNetworkFilteringRule(t, conn, "example.org")

	// There are IPv4 Host filtering rules matched this hosts
	testAHostFilteringRule(t, conn, "google.com", net.IPv4(0, 0, 0, 0))
	testAHostFilteringRule(t, conn, "google.ru", net.IPv4(127, 0, 0, 1))
	testAHostFilteringRuleAAAARequest(t, conn, "google.com")
	testAHostFilteringRuleAAAARequest(t, conn, "google.ru")

	// There are IPv6 Host filtering rules, which matched this hosts
	testAAAAHostFilteringRule(t, conn, "yandex.ru", net.ParseIP("2000::"))
	testAAAAHostFilteringRule(t, conn, "yandex.ua", net.ParseIP("::1"))
	testAAAAHostFilteringRuleARequest(t, conn, "yandex.ru")
	testAAAAHostFilteringRuleARequest(t, conn, "yandex.ua")

	dnsRequestProcessedListenerGuard.Lock()
	if len(listener.e) != 13 {
		dnsRequestProcessedListenerGuard.Unlock()
		t.Fatalf("Wrong number of events registered by the test listener %d", len(listener.e))
	}
	dnsRequestProcessedListenerGuard.Unlock()

	// unregister listener
	ConfigureDNSRequestProcessedListener(nil)
	// Stop the proxy
	err = mobileDNSProxy.Stop()
	assert.Nil(t, err)
}

// TestFilteringProxyRace sends multiple parallel DNS requests, which should be blocked
func TestFilteringProxyRace(t *testing.T) {
	dnsProxy := createTestFilteringProxy()

	listener := &testDNSRequestProcessedListener{}
	ConfigureDNSRequestProcessedListener(listener)

	// Start listening
	err := dnsProxy.Start()
	assert.Nil(t, err)

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr()
	conn, err := dns.Dial("udp", addr)
	assert.Nil(t, err)

	sendTestMessagesAsync(t, conn)
	testNetworkFilteringRulesAsync(t, conn, "example.com")
	testNetworkFilteringRulesAsync(t, conn, "example.org")
	testHostFilteringRulesAsync(t, conn, "google.com", dns.TypeA, net.IPv4(0, 0, 0, 0))
	testHostFilteringRulesAsync(t, conn, "google.ru", dns.TypeA, net.IPv4(127, 0, 0, 1))
	testHostFilteringRulesAsync(t, conn, "yandex.ru", dns.TypeAAAA, net.ParseIP("2000::"))
	testHostFilteringRulesAsync(t, conn, "yandex.ua", dns.TypeAAAA, net.ParseIP("::1"))

	dnsRequestProcessedListenerGuard.Lock()
	if len(listener.e) != 90 {
		dnsRequestProcessedListenerGuard.Unlock()
		t.Fatalf("Wrong number of events registered by the test listener %d", len(listener.e))
	}
	dnsRequestProcessedListenerGuard.Unlock()
	// unregister listener
	ConfigureDNSRequestProcessedListener(nil)
	// Stop the proxy
	err = dnsProxy.Stop()
	assert.Nil(t, err)
}

func createTestFilteringProxy() *DNSProxy {
	const filtersJSON = `
	[
		{"id": 1, "contents": "||example.com^\n||example.org^"},
		{"id": 2, "contents": "0.0.0.0 google.com\n127.0.0.1 google.ru"},
		{"id": 3, "contents": "2000:: yandex.ru\n::1 yandex.ua"}
	]`

	upstreams := []string{
		"tls://dns.adguard.com",
		"https://dns.adguard.com/dns-query",
		// AdGuard DNS (DNSCrypt)
		"sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}
	upstreamsStr := strings.Join(upstreams, "\n")

	config := &Config{
		ListenAddr:         "127.0.0.1",
		ListenPort:         0, // Specify 0 to start listening on a random free port
		BootstrapDNS:       "8.8.8.8:53\n1.1.1.1:53",
		Fallbacks:          "8.8.8.8:53\n1.1.1.1:53",
		Timeout:            5000,
		Upstreams:          upstreamsStr,
		MaxGoroutines:      1,
		FilteringRulesJSON: filtersJSON,
	}

	mobileDNSProxy := DNSProxy{Config: config}
	return &mobileDNSProxy
}

// testNetworkFilteringRulesAsync sends requests, which should be blocked with network rules, in parallel
func testNetworkFilteringRulesAsync(t *testing.T, conn *dns.Conn, host string) {
	g := &sync.WaitGroup{}
	g.Add(testMessagesCount)

	for i := 0; i < testMessagesCount; i++ {
		go testNetworkFilteringRuleAsync(t, conn, host, g)
	}

	g.Wait()
}

func testNetworkFilteringRuleAsync(t *testing.T, conn *dns.Conn, host string, g *sync.WaitGroup) {
	defer func() {
		g.Done()
	}()

	testNetworkFilteringRule(t, conn, host)
}

// testHostFilteringRulesAsync sends requests, which should be blocked with host rules, in parallel
func testHostFilteringRulesAsync(t *testing.T, conn *dns.Conn, host string, reqType uint16, ip net.IP) {
	g := &sync.WaitGroup{}
	g.Add(testMessagesCount)

	for i := 0; i < testMessagesCount; i++ {
		go testHostFilteringRuleAsync(t, conn, host, ip, reqType, g)
	}

	g.Wait()
}

func testHostFilteringRuleAsync(t *testing.T, conn *dns.Conn, host string, ip net.IP, reqType uint16, g *sync.WaitGroup) {
	defer func() {
		g.Done()
	}()

	if reqType == dns.TypeA {
		testAHostFilteringRule(t, conn, host, ip)
	} else if reqType == dns.TypeAAAA {
		testAAAAHostFilteringRule(t, conn, host, ip)
	}
}

func sendAndAssertTestMessage(t *testing.T, conn *dns.Conn) {
	req := createTestMessage()
	err := conn.WriteMsg(req)
	assert.Nil(t, err)

	res, err := conn.ReadMsg()
	assert.Nil(t, err)

	assertResponse(t, res)
}

// testNetworkFilteringRule is a test for network filtering rules:
// - There is network filtering rules in the DNS Filtering filteringEngine
// - Both A and AAAA requests for this host should be filtered with NXDomain RCode
// If you'd like to test mobile event handler, note that this method will create two events
func testNetworkFilteringRule(t *testing.T, conn *dns.Conn, host string) {
	req := createHostTestMessage(host)
	err := conn.WriteMsg(req)
	assert.Nil(t, err)

	res, err := conn.ReadMsg()
	assert.Nil(t, err)

	assert.Nil(t, res.Answer)
	assert.Equal(t, len(res.Ns), 1)
	assert.Equal(t, res.Rcode, dns.RcodeNameError)

	req = createAAAATestMessage(host)
	err = conn.WriteMsg(req)
	assert.Nil(t, err)

	res, err = conn.ReadMsg()
	assert.Nil(t, err)

	assert.Nil(t, res.Answer)
	assert.Equal(t, len(res.Ns), 1)
	assert.Equal(t, res.Rcode, dns.RcodeNameError)
}

// testAHostFilteringRule is a test for the following case:
// - There is IPv4 filtering rule for the given host in the DNS Filtering filteringEngine
// - A request for this host should be filtered and response must contain the given ip address
func testAHostFilteringRule(t *testing.T, conn *dns.Conn, host string, ip net.IP) {
	req := createHostTestMessage(host)
	err := conn.WriteMsg(req)
	assert.Nil(t, err)

	res, err := conn.ReadMsg()
	assert.Nil(t, err)

	assertAResponse(t, res, ip)
}

// testAHostFilteringRuleAAAARequest is a test for the following case:
// - There is IPv4 host filtering rule for the given host in the DNS Filtering filteringEngine
// - AAAA request for this host should not be filtered
func testAHostFilteringRuleAAAARequest(t *testing.T, conn *dns.Conn, host string) {
	req := createAAAATestMessage(host)
	err := conn.WriteMsg(req)
	assert.Nil(t, err)

	res, err := conn.ReadMsg()
	assert.Nil(t, err)

	assert.NotNil(t, res.Answer)
	assert.Equal(t, res.Answer[0].Header().Rrtype, dns.TypeAAAA)
}

// testAHostFilteringRule is a test for the following case:
// - There is IPv6 filtering rule for the given host in the DNS Filtering filteringEngine
// - AAAA request for this host should be filtered and response must contain the given ip address
func testAAAAHostFilteringRule(t *testing.T, conn *dns.Conn, host string, ip net.IP) {
	req := createAAAATestMessage(host)
	err := conn.WriteMsg(req)
	assert.Nil(t, err)

	res, err := conn.ReadMsg()
	assert.Nil(t, err)

	assertAAAAResponse(t, res, ip)
}

// testAAAAHostFilteringRuleARequest is a test for the following case:
// - There is IPv6 host filtering rule for the given host in the DNS Filtering filteringEngine
// - A request for this host should not be filtered
func testAAAAHostFilteringRuleARequest(t *testing.T, conn *dns.Conn, host string) {
	req := createHostTestMessage(host)
	err := conn.WriteMsg(req)
	assert.Nil(t, err)

	res, err := conn.ReadMsg()
	assert.Nil(t, err)

	assert.NotNil(t, res.Answer)
	assert.Equal(t, res.Answer[0].Header().Rrtype, dns.TypeA)
}

// assertAResponse asserts known A response with the given IPv4 address
func assertAResponse(t *testing.T, reply *dns.Msg, ipv4 net.IP) {
	if len(reply.Answer) != 1 {
		t.Fatalf("DNS upstream returned reply with wrong number of answers - %d", len(reply.Answer))
	}

	if a, ok := reply.Answer[0].(*dns.A); ok {
		if !ipv4.Equal(a.A) {
			t.Fatalf("DNS upstream returned wrong answer instead of %v: %v", ipv4, a.A)
		}
	} else {
		t.Fatalf("DNS upstream returned wrong answer type instead of A: %v", reply.Answer[0])
	}
}

// assertAAAAResponse asserts known AAAA response with the given IPv6 address
func assertAAAAResponse(t *testing.T, reply *dns.Msg, ipv6 net.IP) {
	if len(reply.Answer) != 1 {
		t.Fatalf("DNS upstream returned reply with wrong number of answers - %d", len(reply.Answer))
	}

	if a, ok := reply.Answer[0].(*dns.AAAA); ok {
		if !ipv6.Equal(a.AAAA) {
			t.Fatalf("DNS upstream returned wrong answer instead of %v: %v", ipv6, a.AAAA)
		}
	} else {
		t.Fatalf("DNS upstream returned wrong answer type instead of A: %v", reply.Answer[0])
	}
}

func createAAAATestMessage(host string) *dns.Msg {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	name := host + "."
	req.Question = []dns.Question{
		{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
	}
	return &req
}
