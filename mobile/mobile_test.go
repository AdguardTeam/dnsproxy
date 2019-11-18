package mobile

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"

	"github.com/stretchr/testify/assert"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"github.com/shirou/gopsutil/process"
)

const (
	testMessagesCount = 10
)

func TestMobileApi(t *testing.T) {
	upstreams := []string{
		"tls://dns.adguard.com",
		"https://dns.adguard.com/dns-query",
		// AdGuard DNS (DNSCrypt)
		"sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}
	upstreamsStr := strings.Join(upstreams, "\n")

	config := &Config{
		ListenAddr:    "127.0.0.1",
		ListenPort:    0, // Specify 0 to start listening on a random free port
		BootstrapDNS:  "8.8.8.8:53\n1.1.1.1:53",
		Fallbacks:     "8.8.8.8:53\n1.1.1.1:53",
		Timeout:       5000,
		Upstreams:     upstreamsStr,
		MaxGoroutines: 1,
	}

	listener := &testDNSRequestProcessedListener{}
	ConfigureDNSRequestProcessedListener(listener)

	mobileDNSProxy := DNSProxy{Config: config}
	err := mobileDNSProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the mobile proxy: %s", err)
	}

	//
	// Test that it resolves something
	//

	// Create a test DNS message
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "google-public-dns-a.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	addr := mobileDNSProxy.Addr()
	reply, err := dns.Exchange(&req, addr)
	if err != nil {
		t.Fatalf("Couldn't talk to upstream %s: %s", addr, err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("DNS upstream %s returned reply with wrong number of answers - %d", addr, len(reply.Answer))
	}
	if a, ok := reply.Answer[0].(*dns.A); ok {
		if !net.IPv4(8, 8, 8, 8).Equal(a.A) {
			t.Fatalf("DNS upstream %s returned wrong answer instead of 8.8.8.8: %v", addr, a.A)
		}
	} else {
		t.Fatalf("DNS upstream %s returned wrong answer type instead of A: %v", addr, reply.Answer[0])
	}

	assertListenerEventsCount(t, listener, 1)

	ConfigureDNSRequestProcessedListener(nil)
	err = mobileDNSProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the mobile proxy: %s", err)
	}
}

func TestMobileApiResolve(t *testing.T) {
	start := getRSS()
	log.Printf("RSS before init - %d kB\n", start/1024)

	upstreams := []string{
		// It seems that CloudFlare chooses more complicated cipher suites.
		// It leads to higher memory usage.
		"tls://1.1.1.1",
		"https://dns.cloudflare.com/dns-query",
		"tls://dns.adguard.com",
		"https://dns.adguard.com/dns-query",
		"176.103.130.130",
		// AdGuard DNS (DNSCrypt)
		"sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}
	upstreamsStr := strings.Join(upstreams, "\n")

	config := &Config{
		ListenAddr:    "127.0.0.1",
		ListenPort:    0, // Specify 0 to start listening on a random free port
		BootstrapDNS:  "8.8.8.8:53\n1.1.1.1:53",
		Fallbacks:     "8.8.8.8:53\n1.1.1.1:53",
		Timeout:       5000,
		Upstreams:     upstreamsStr,
		MaxGoroutines: 3,
	}

	listener := &testDNSRequestProcessedListener{}
	ConfigureDNSRequestProcessedListener(listener)

	mobileDNSProxy := DNSProxy{Config: config}
	err := mobileDNSProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the mobile proxy: %s", err)
	}

	afterLoad := getRSS()
	log.Printf("RSS after init - %d kB (%d kB diff)\n", afterLoad/1024, (afterLoad-start)/1024)

	for i := 0; i < testMessagesCount; i++ {
		msg := createTestMessage()
		bytes, _ := msg.Pack()
		resBytes, err := mobileDNSProxy.Resolve(bytes)
		if err != nil {
			t.Fatalf("cannot resolve: %s", err)
		}
		res := new(dns.Msg)
		err = res.Unpack(resBytes)
		if err != nil {
			t.Fatalf("cannot unpack response: %s", err)
		}
		assertResponse(t, res)
	}

	end := getRSS()
	log.Printf("RSS in the end - %d kB (%d kB diff)\n", end/1024, (end-afterLoad)/1024)

	assertListenerEventsCount(t, listener, testMessagesCount)

	// Stop proxy
	err = mobileDNSProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the mobile proxy: %s", err)
	}
}

func TestMobileApiMultipleQueries(t *testing.T) {
	start := getRSS()
	log.Printf("RSS before init - %d kB\n", start/1024)

	upstreams := []string{
		// It seems that CloudFlare chooses more complicated cipher suites.
		// It leads to higher memory usage.
		"tls://1.1.1.1",
		"https://dns.cloudflare.com/dns-query",
		"tls://dns.adguard.com",
		"https://dns.adguard.com/dns-query",
		"176.103.130.130",
		// AdGuard DNS (DNSCrypt)
		"sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}
	upstreamsStr := strings.Join(upstreams, "\n")

	config := &Config{
		ListenAddr:    "127.0.0.1",
		ListenPort:    0, // Specify 0 to start listening on a random free port
		BootstrapDNS:  "8.8.8.8:53\n1.1.1.1:53",
		Fallbacks:     "8.8.8.8:53\n1.1.1.1:53",
		Timeout:       5000,
		Upstreams:     upstreamsStr,
		MaxGoroutines: 5,
	}

	mobileDNSProxy := DNSProxy{Config: config}
	err := mobileDNSProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the mobile proxy: %s", err)
	}

	afterLoad := getRSS()
	log.Printf("RSS after init - %d kB (%d kB diff)\n", afterLoad/1024, (afterLoad-start)/1024)

	// Create a DNS-over-UDP client connection
	addr := mobileDNSProxy.dnsProxy.Addr(proxy.ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("cannot connect to the proxy: %s", err)
	}

	// Send test messages in parallel
	sendTestMessagesAsync(t, conn)

	// Uncomment if pprof is needed
	//f, err := os.Create("output.pprof")
	//if err != nil {
	//	log.Fatal("could not create memory profile: ", err)
	//}
	//defer f.Close()
	////runtime.GC() // get up-to-date statistics
	//if err := pprof.WriteHeapProfile(f); err != nil {
	//	log.Fatal("could not write memory profile: ", err)
	//}

	end := getRSS()
	log.Printf("RSS in the end - %d kB (%d kB diff)\n", end/1024, (end-afterLoad)/1024)

	// Stop proxy
	err = mobileDNSProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the mobile proxy: %s", err)
	}
}

func TestMobileApiDNS64(t *testing.T) {
	upstreams := []string{
		"tls://dns.adguard.com",
		"https://dns.adguard.com/dns-query",
		// AdGuard DNS (DNSCrypt)
		"sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}
	upstreamsStr := strings.Join(upstreams, "\n")
	config := &Config{
		ListenAddr:   "127.0.0.1",
		ListenPort:   0, // Specify 0 to start listening on a random free port
		BootstrapDNS: "8.8.8.8:53\n1.1.1.1:53",
		Fallbacks:    "8.8.8.8:53\n1.1.1.1:53",
		Timeout:      5000,
		Upstreams:    upstreamsStr,
	}

	dns64Server := createDNS64Server(t)
	err := dns64Server.Start()
	assert.Nil(t, err)
	defer dns64Server.Stop() // nolint

	allowDNS64IP4 = true // otherwise, 127.0.0.1 server will be discarded
	defer func() { allowDNS64IP4 = false }()
	config.SystemResolvers = dns64Server.Addr(proxy.ProtoTCP).String()
	config.DetectDNS64Prefix = true
	dnsProxy := DNSProxy{Config: config}
	err = dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the mobile dnsProxy: %s", err)
	}

	// Wait for NAT64 prefix calculation
	time.Sleep(6 * time.Second)

	//
	// Test that it resolves IPv4 only host with AAAA request type
	//

	// Create a test DNS message
	req := createHostTestMessageWithType("and.ru", dns.TypeAAAA)
	addr := dnsProxy.Addr()
	reply, err := dns.Exchange(req, addr)
	if err != nil {
		t.Fatalf("Couldn't talk to upstream %s: %s", addr, err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("DNS upstream %s returned reply with wrong number of answers - %d", addr, len(reply.Answer))
	}

	if len(reply.Answer) == 0 {
		t.Fatalf("No answers")
	}

	if _, ok := reply.Answer[0].(*dns.AAAA); !ok {
		t.Fatalf("DNS upstream %s returned wrong answer type instead of AAAA: %v", addr, reply.Answer[0])
	}

	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the mobile dnsProxy: %s", err)
	}
}

func TestDNS64AddressValidation(t *testing.T) {
	dns64 := "1.1.1.1\n1.1.1.1:53\nhttps://dns.adguard.com\n[2001:67c:27e4:15::64]:53\n2001:67c:27e4:15::64"
	addresses := validateIPv6Addresses(dns64)
	if len(addresses) != 2 {
		t.Fatalf("Wrong count of addresses: %d", len(addresses))
	}
	if addresses[0] != addresses[1] {
		t.Fatalf("Wrong addresses. Expected: [2001:67c:27e4:15::64]:53, actual: %s, %s", addresses[0], addresses[1])
	}
}

func TestExchangeWithClient(t *testing.T) {
	p := createDNS64Server(t)
	err := p.Start()
	assert.Nil(t, err)
	defer p.Stop() // nolint

	res := getNAT64PrefixWithClient("1.1.1.1:53")
	if res.err == nil {
		t.Fatalf("1.1.1.1:53 is not DNS64 server")
	}

	res = getNAT64PrefixWithClient(p.Addr(proxy.ProtoTCP).String())
	if res.err != nil {
		t.Fatalf("Error while ipv4only.arpa exchange: %s", res.err)
	}

	if len(res.prefix) != 12 {
		t.Fatalf("Wrong prefix format: %v", res.prefix)
	}
}

func TestParallelExchange(t *testing.T) {
	p := createDNS64Server(t)
	err := p.Start()
	assert.Nil(t, err)
	defer p.Stop() // nolint

	dns64 := []string{"1.1.1.1:53", p.Addr(proxy.ProtoTCP).String(), "8.8.8.8"}
	res := getNAT64PrefixParallel(dns64)
	if res.err != nil {
		t.Fatalf("Error while NAT64 prefix calculation: %s", res.err)
	}

	if len(res.prefix) != 12 {
		t.Fatalf("Invalid prefix: %v", res.prefix)
	}
}

func TestDNSProxyRestartRace(t *testing.T) {
	mobileDNSProxy := createTestFilteringProxy(BlockTypeRule)
	err := mobileDNSProxy.Start()
	assert.Nil(t, err)
	g := &sync.WaitGroup{}
	g.Add(testMessagesCount)
	for i := 0; i < testMessagesCount; i++ {
		go testDNSProxyRestartAsync(t, mobileDNSProxy, g)
	}

	g.Wait()
	err = mobileDNSProxy.Stop()
	assert.Nil(t, err)
}

func TestDNSProxyDisabledIPv6(t *testing.T) {
	config := createDefaultConfig()
	config.IPv6Disabled = true
	mobileDNSProxy := DNSProxy{Config: config}
	assert.Nil(t, mobileDNSProxy.Start())

	req := createAAAATestMessage("google.com")
	reply, err := dns.Exchange(req, mobileDNSProxy.Addr())
	assert.Nil(t, err)
	assert.Equal(t, reply.Rcode, dns.RcodeSuccess)
	assert.Nil(t, reply.Answer)

	assert.Nil(t, mobileDNSProxy.Stop())
}

// testDNSProxyRestartAsync restarts DNSProxy in separate goroutine
// And asserts thar dnsproxy and filtering engine are not nil nor before nor after the restart
func testDNSProxyRestartAsync(t *testing.T, d *DNSProxy, g *sync.WaitGroup) {
	defer func() {
		g.Done()
	}()

	d.Lock()
	assert.NotNil(t, d.dnsProxy)
	assert.NotNil(t, d.filteringEngine)
	d.Unlock()

	err := d.Restart(createDefaultConfig())

	d.Lock()
	assert.NotNil(t, d.dnsProxy)
	assert.NotNil(t, d.filteringEngine)
	d.Unlock()

	assert.Nil(t, err)
}

func sendTestMessageAsync(t *testing.T, conn *dns.Conn, g *sync.WaitGroup) {
	defer func() {
		g.Done()
	}()

	req := createTestMessage()
	err := conn.WriteMsg(req)
	if err != nil {
		t.Fatalf("cannot write message: %s", err)
	}

	res, err := conn.ReadMsg()
	if err != nil {
		t.Fatalf("cannot read response to message: %s", err)
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

func createTestMessage() *dns.Msg {
	return createHostTestMessage("google-public-dns-a.google.com")
}

func createHostTestMessage(host string) *dns.Msg {
	return createHostTestMessageWithType(host, dns.TypeA)
}

func createHostTestMessageWithType(host string, dnsType uint16) *dns.Msg {
	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	name := host + "."
	req.Question = []dns.Question{
		{Name: name, Qtype: dnsType, Qclass: dns.ClassINET},
	}
	return req
}

func assertResponse(t *testing.T, reply *dns.Msg) {
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

func getRSS() uint64 {
	proc, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		panic(err)
	}
	minfo, err := proc.MemoryInfo()
	if err != nil {
		panic(err)
	}
	return minfo.RSS
}

type testDNSRequestProcessedListener struct {
	e []DNSRequestProcessedEvent
}

func (l *testDNSRequestProcessedListener) DNSRequestProcessed(e *DNSRequestProcessedEvent) {
	l.e = append(l.e, *e)
}

func assertListenerEventsCount(t *testing.T, listener *testDNSRequestProcessedListener, count int) {
	dnsRequestProcessedListenerGuard.Lock()
	if len(listener.e) != count {
		dnsRequestProcessedListenerGuard.Unlock()
		t.Fatalf("Wrong number of events registered by the test listener. Expected: %d; Actual: %d", count, len(listener.e))
	}
	dnsRequestProcessedListenerGuard.Unlock()
}

// createDNS64Server creates a DNS64 server mock for unit-tests
func createDNS64Server(t *testing.T) *proxy.Proxy {
	p := proxy.Proxy{}
	p.UDPListenAddr = &net.UDPAddr{Port: 0, IP: net.ParseIP("127.0.0.1")}
	p.TCPListenAddr = &net.TCPAddr{Port: 0, IP: net.ParseIP("127.0.0.1")}
	dnsUpstream, err := upstream.AddressToUpstream("8.8.8.8:53", upstream.Options{})
	assert.Nil(t, err)
	p.Upstreams = []upstream.Upstream{dnsUpstream}
	p.RequestHandler = func(p *proxy.Proxy, d *proxy.DNSContext) error {
		if d.Req.Question[0].Qtype != dns.TypeAAAA {
			return nil
		}

		resp := dns.Msg{}
		resp.SetReply(d.Req)

		// Pref64 + "well-known IPv4"
		// https://tools.ietf.org/html/rfc7050#section-2.2
		ip := "2001:67c:27e4:1064::c000:ab"
		answer, err := dns.NewRR(fmt.Sprintf("%s %d AAAA %s", d.Req.Question[0].Name, 100, ip))
		assert.Nil(t, err)
		resp.Answer = append(resp.Answer, answer)
		d.Res = &resp
		return nil
	}
	return &p
}

func createDefaultConfig() *Config {
	upstreams := []string{
		"tls://dns.adguard.com",
		"https://dns.adguard.com/dns-query",
		// AdGuard DNS (DNSCrypt)
		"sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}
	upstreamsStr := strings.Join(upstreams, "\n")

	return &Config{
		ListenAddr:    "127.0.0.1",
		ListenPort:    0, // Specify 0 to start listening on a random free port
		BootstrapDNS:  "8.8.8.8:53\n1.1.1.1:53",
		Fallbacks:     "8.8.8.8:53\n1.1.1.1:53",
		Timeout:       5000,
		Upstreams:     upstreamsStr,
		MaxGoroutines: 1,
	}
}
