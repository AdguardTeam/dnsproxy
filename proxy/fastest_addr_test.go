package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func createARec(host, ip string) *dns.A {
	a := new(dns.A)
	a.Hdr.Rrtype = dns.TypeA
	a.Hdr.Name = host
	a.A = net.ParseIP(ip)
	a.Hdr.Ttl = 60
	return a
}

// . Upstream server returns "127.0.0.1", "8.8.8.8" IP addresses:
//    "127.0.0.1" is dead, "8.8.8.8" is alive
// . The algorithm returns "8.8.8.8"
//
// . Upstream server returns "127.0.0.1", "8.8.8.8", "127.0.0.2" IP addresses:
//    "127.0.0.1" is dead, "8.8.8.8" is alive, "127.0.0.2" is alive
// . The algorithm returns "127.0.0.2"
func TestFastestAddr(t *testing.T) {
	f := FastestAddr{}
	f.Init()
	f.allowICMP = false
	f.tcpPort = 80
	up1 := &testUpstream{}

	// start listening TCP port on 127.0.0.2
	addr := net.TCPAddr{
		IP:   net.ParseIP("127.0.0.2"),
		Port: int(f.tcpPort),
	}
	lisn, err := net.ListenTCP("tcp4", &addr)
	if err != nil {
		log.Info("skipping test: %s", err)
		return
	}
	defer lisn.Close()

	log.SetLevel(log.DEBUG)

	// add the 1st A response record
	up1.aResp = createARec("test.org.", "127.0.0.1")

	// add the 2nd A response record
	up1.aRespArr = append(up1.aRespArr, createARec("test.org.", "8.8.8.8"))

	ups := []upstream.Upstream{up1}
	req := createHostTestMessage("test.org")
	resp, up, err := f.exchangeFastest(req, ups)
	assert.True(t, err == nil)
	assert.True(t, up == up1)
	assert.True(t, resp != nil)
	ip := resp.Answer[0].(*dns.A).A.String()
	assert.True(t, ip == "8.8.8.8")

	f.tcpPort = 8081

	// add the 3rd A response record
	up1.aRespArr = append(up1.aRespArr, createARec("test.org.", "127.0.0.2"))

	// 127.0.0.2 (from tcp-connection) is faster than 8.8.8.8 (from cache)
	resp, up, err = f.exchangeFastest(req, ups)
	ip = resp.Answer[0].(*dns.A).A.String()
	assert.True(t, ip == "127.0.0.2")
}

// . Upstream server returns "127.0.0.1", "127.0.0.2", "127.0.0.3" IP addresses:
//    all are dead
// . The algorithm returns "127.0.0.1"
func TestFastestAddrAllDead(t *testing.T) {
	f := FastestAddr{}
	f.Init()
	f.allowICMP = false
	f.tcpPort = 8081
	up1 := &testUpstream{}

	up1.aResp = createARec("test.org.", "127.0.0.1")
	up1.aRespArr = append(up1.aRespArr, createARec("test.org.", "127.0.0.2"))
	up1.aRespArr = append(up1.aRespArr, createARec("test.org.", "127.0.0.3"))

	ups := []upstream.Upstream{up1}
	req := createHostTestMessage("test.org")
	resp, _, err := f.exchangeFastest(req, ups)
	assert.True(t, err == nil)
	ip := resp.Answer[0].(*dns.A).A.String()
	assert.True(t, ip == "127.0.0.1")
}
