package mobile

import (
	"net"
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

	// There are IPv6 Host filtering rules, which matched this hosts
	testAAAAHostFilteringRule(t, conn, "yandex.ru", net.ParseIP("2000::"))
	testAAAAHostFilteringRule(t, conn, "yandex.ua", net.ParseIP("::1"))
	testAAAAHostFilteringRuleARequest(t, conn, "yandex.ru")
	testAAAAHostFilteringRuleARequest(t, conn, "yandex.ua")

	assertListenerEventsCount(t, listener, 11)

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

	// Requests which shouldn't be blocked
	sendTestMessagesAsync(t, conn)

	// Network filtering rules
	testNetworkFilteringRulesAsync(t, conn, "example.com")
	testNetworkFilteringRulesAsync(t, conn, "example.org")

	// IPv4 rules and A requests
	testHostFilteringRulesAsync(t, conn, "google.com", dns.TypeA, net.IPv4(0, 0, 0, 0))
	testHostFilteringRulesAsync(t, conn, "google.ru", dns.TypeA, net.IPv4(127, 0, 0, 1))

	// IPv6 rules and AAAA requests
	testHostFilteringRulesAsync(t, conn, "yandex.ru", dns.TypeAAAA, net.ParseIP("2000::"))
	testHostFilteringRulesAsync(t, conn, "yandex.ua", dns.TypeAAAA, net.ParseIP("::1"))

	// Zero IPv4 rule should also block AAAA requests with IPv6Zero answer
	testHostFilteringRulesAsync(t, conn, "google.com", dns.TypeAAAA, net.IPv6zero)

	assertListenerEventsCount(t, listener, 100)

	// unregister listener
	ConfigureDNSRequestProcessedListener(nil)
	// Stop the proxy
	err = dnsProxy.Stop()
	assert.Nil(t, err)
}

func TestDNSRequestProcessedEvents(t *testing.T) {
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

	// Create, send and assert regular test message. Filtering proxy contains whitelist rule for google-public-dns-a.google.com
	eventsCount := 1
	sendAndAssertTestMessage(t, conn)
	assertDNSRequestProcessedEventWithListener(t, listener, "google-public-dns-a.google.com", "A", "@@||google-public-dns-a.google.com^", 4, eventsCount, true)

	// testAHostFilteringRule and testAAAAHostFilteringRule produce one event
	// Let's check events one-by-one

	// A request which blocked with IPv4 HostRule
	eventsCount++
	testAHostFilteringRule(t, conn, "google.ru", net.IPv4(127, 0, 0, 1))
	assertDNSRequestProcessedEventWithListener(t, listener, "google.ru", "A", "127.0.0.1 google.ru", 2, eventsCount, false)

	// A request which blocked with zero IPv4 HostRule
	eventsCount++
	testAHostFilteringRule(t, conn, "google.com", net.IPv4(0, 0, 0, 0))
	assertDNSRequestProcessedEventWithListener(t, listener, "google.com", "A", "0.0.0.0 google.com", 2, eventsCount, false)

	// AAAA request which blocked with zero IPv4 HostRule
	eventsCount++
	testAAAAHostFilteringRule(t, conn, "google.com", net.IPv6zero)
	assertDNSRequestProcessedEventWithListener(t, listener, "google.com", "AAAA", "0.0.0.0 google.com", 2, eventsCount, false)

	// AAAA request which blocked with IPv6 HostRule
	eventsCount++
	testAAAAHostFilteringRule(t, conn, "yandex.ru", net.ParseIP("2000::"))
	assertDNSRequestProcessedEventWithListener(t, listener, "yandex.ru", "AAAA", "2000:: yandex.ru", 3, eventsCount, false)

	// AAAA request which blocked with IPv6 HostRule
	eventsCount++
	testAAAAHostFilteringRule(t, conn, "yandex.ua", net.ParseIP("::1"))
	assertDNSRequestProcessedEventWithListener(t, listener, "yandex.ua", "AAAA", "::1 yandex.ua", 3, eventsCount, false)

	// IPv4 rule for google.ru is not 0.0.0.0. It means that AAAA request for google.ru shouldn't be blocked
	eventsCount++
	res := sendAAAATestMessage(t, conn, "google.ru")
	assert.NotNil(t, res.Answer[0])
	assert.Equal(t, res.Answer[0].Header().Rrtype, dns.TypeAAAA)
	assertDNSRequestProcessedEventWithListener(t, listener, "google.ru", "AAAA", "", 0, eventsCount, false)

	// IPv6 rule for yandex.ru shouldn't block A request
	eventsCount++
	res = sendATestMessage(t, conn, "yandex.ru")
	assert.NotNil(t, res.Answer[0])
	assert.Equal(t, res.Answer[0].Header().Rrtype, dns.TypeA)
	assertDNSRequestProcessedEventWithListener(t, listener, "yandex.ru", "A", "", 0, eventsCount, false)

	// There are two events produced with testNetworkFilteringRule: A and AAAA requests
	// We should check count of registered events and each event
	eventsCount += 2
	testNetworkFilteringRule(t, conn, "example.com")
	assertListenerEventsCount(t, listener, eventsCount)
	assertDNSRequestProcessedEvent(t, getDNSRequestProcessedEventByIdx(listener, eventsCount-2), "example.com", "A", "||example.com^", 1, false)
	assertDNSRequestProcessedEvent(t, getDNSRequestProcessedEventByIdx(listener, eventsCount-1), "example.com", "AAAA", "||example.com^", 1, false)

	eventsCount += 2
	testNetworkFilteringRule(t, conn, "example.org")
	assertListenerEventsCount(t, listener, eventsCount)
	assertDNSRequestProcessedEvent(t, getDNSRequestProcessedEventByIdx(listener, eventsCount-2), "example.org", "A", "||example.org^", 1, false)
	assertDNSRequestProcessedEvent(t, getDNSRequestProcessedEventByIdx(listener, eventsCount-1), "example.org", "AAAA", "||example.org^", 1, false)

	// unregister listener
	ConfigureDNSRequestProcessedListener(nil)
	// Stop the proxy
	err = dnsProxy.Stop()
	assert.Nil(t, err)
}

// assertDNSRequestProcessedEventWithListener asserts count of events in listener and the last event
func assertDNSRequestProcessedEventWithListener(t *testing.T, listener *testDNSRequestProcessedListener, domain, reqType, filteringRule string, filterListID, count int, whitelist bool) {
	assertListenerEventsCount(t, listener, count)
	event := getDNSRequestProcessedEventByIdx(listener, count-1)
	assertDNSRequestProcessedEvent(t, event, domain, reqType, filteringRule, filterListID, whitelist)
}

func assertDNSRequestProcessedEvent(t *testing.T, event DNSRequestProcessedEvent, domain, reqType, filteringRule string, filterListID int, whitelist bool) {
	assert.Equal(t, event.Domain, domain)
	assert.Equal(t, event.Type, reqType)
	assert.Equal(t, event.FilteringRule, filteringRule)
	assert.Equal(t, event.FilterListID, filterListID)
	assert.Equal(t, event.Whitelist, whitelist)
}

func getDNSRequestProcessedEventByIdx(listener *testDNSRequestProcessedListener, idx int) DNSRequestProcessedEvent {
	dnsRequestProcessedListenerGuard.Lock()
	defer dnsRequestProcessedListenerGuard.Unlock()
	return listener.e[idx]
}

func createTestFilteringProxy() *DNSProxy {
	const filtersJSON = `
	[
		{"id": 1, "contents": "||example.com^\n||example.org^"},
		{"id": 2, "contents": "0.0.0.0 google.com\n127.0.0.1 google.ru"},
		{"id": 3, "contents": "2000:: yandex.ru\n::1 yandex.ua"},
		{"id": 4, "contents": "@@||google-public-dns-a.google.com^"}
	]`

	config := createDefaultConfig()
	filteringConfig := &FilteringConfig{
		FilteringRulesJSON: filtersJSON,
		BlockWithNXDomain:  true,
	}

	mobileDNSProxy := DNSProxy{Config: config, FilteringConfig: filteringConfig}
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
	res := sendATestMessage(t, conn, host)
	assertAResponse(t, res, ip)
}

func sendATestMessage(t *testing.T, conn *dns.Conn, host string) *dns.Msg {
	req := createHostTestMessage(host)
	err := conn.WriteMsg(req)
	assert.Nil(t, err)
	res, err := conn.ReadMsg()
	assert.Nil(t, err)
	return res
}

// testAHostFilteringRule is a test for the following case:
// - There is IPv6 filtering rule for the given host in the DNS Filtering filteringEngine
// - AAAA request for this host should be filtered and response must contain the given ip address
func testAAAAHostFilteringRule(t *testing.T, conn *dns.Conn, host string, ip net.IP) {
	res := sendAAAATestMessage(t, conn, host)
	assertAAAAResponse(t, res, ip)
}

func sendAAAATestMessage(t *testing.T, conn *dns.Conn, host string) *dns.Msg {
	req := createAAAATestMessage(host)
	err := conn.WriteMsg(req)
	assert.Nil(t, err)
	res, err := conn.ReadMsg()
	assert.Nil(t, err)
	return res
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
