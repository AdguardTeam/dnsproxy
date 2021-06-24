package upstream

import (
	"net"
	"testing"

	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestUpstreamDNSCrypt(t *testing.T) {
	// AdGuard DNS (DNSCrypt)
	address := "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	u, err := AddressToUpstream(address, &Options{Timeout: dialTimeout})
	assert.Nil(t, err)

	// Test that it responds properly
	for i := 0; i < 10; i++ {
		checkUpstream(t, u, address)
	}
}

func TestDNSCryptTruncated(t *testing.T) {
	// Prepare the test DNSCrypt server config
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil)
	assert.Nil(t, err)

	cert, err := rc.CreateCert()
	assert.Nil(t, err)

	s := &dnscrypt.Server{
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      &testDNSCryptHandler{},
	}

	// Prepare TCP listener
	tcpConn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	assert.Nil(t, err)
	defer tcpConn.Close()

	// Prepare UDP listener - on the same port
	port := tcpConn.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	assert.Nil(t, err)
	defer udpConn.Close()

	// Start the server
	go s.ServeUDP(udpConn)
	go s.ServeTCP(tcpConn)

	// Now prepare a client for this test server
	stamp, err := rc.CreateStamp(udpConn.LocalAddr().String())
	assert.Nil(t, err)
	u, err := AddressToUpstream(stamp.String(), &Options{Timeout: timeout})
	assert.Nil(t, err)

	req := new(dns.Msg)
	req.SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)
	req.RecursionDesired = true

	// Check that response is not truncated (even though it's huge)
	res, err := u.Exchange(req)
	assert.Nil(t, err)
	assert.False(t, res.Truncated)
}

type testDNSCryptHandler struct{}

// ServeDNS - implements Handler interface
func (h *testDNSCryptHandler) ServeDNS(rw dnscrypt.ResponseWriter, r *dns.Msg) error {
	res := new(dns.Msg)
	res.SetReply(r)
	answer := new(dns.TXT)
	answer.Hdr = dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeTXT,
		Ttl:    300,
		Class:  dns.ClassINET,
	}

	veryLongString := "VERY LONG STRINGVERY LONG STRINGVERY LONG STRINGVERY LONG STRINGVERY LONG STRINGVERY LONG STRINGVERY LONG STRING"
	for i := 0; i < 50; i++ {
		answer.Txt = append(answer.Txt, veryLongString)
	}

	res.Answer = append(res.Answer, answer)
	return rw.WriteMsg(res)
}
