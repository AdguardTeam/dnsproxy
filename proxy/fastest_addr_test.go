package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
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

// . Upstream server returns "10.15.16.17" (dead), "127.0.0.1" (alive)
// . The algorithm returns "127.0.0.1"
func TestFastestAddrOneDeadIP(t *testing.T) {
	// Listener that we're using for TCP checks
	listener, err := net.Listen("tcp", ":0")
	assert.Nil(t, err)
	defer listener.Close()

	f := FastestAddr{}
	f.Init()
	f.tcpPorts = []uint{uint(listener.Addr().(*net.TCPAddr).Port)}
	up1 := &testUpstream{}

	// add the 1st A response record
	// this IP is dead (nothing is listening on our port)
	up1.aResp = createARec("test.org.", "10.15.16.17")

	// add the 2nd A response record
	// Alive IP address
	up1.aRespArr = append(up1.aRespArr, createARec("test.org.", "127.0.0.1"))

	// Check that it's alive
	ups := []upstream.Upstream{up1}
	req := createHostTestMessage("test.org")
	resp, up, err := f.exchangeFastest(req, ups)
	assert.Nil(t, err)
	assert.Equal(t, up, up1)
	assert.NotNil(t, resp)
	ip := resp.Answer[0].(*dns.A).A.String()
	assert.Equal(t, "127.0.0.1", ip)
}

// . Upstream server returns "8.8.8.8" (alive, slow), "127.0.0.1" (alive, fast)
// . The algorithm returns "127.0.0.1"
func TestFastestAddrOneFaster(t *testing.T) {
	// Listener that we're using for TCP checks
	listener, err := net.Listen("tcp", ":0")
	assert.Nil(t, err)
	defer listener.Close()

	f := FastestAddr{}
	f.Init()
	f.tcpPorts = []uint{443, uint(listener.Addr().(*net.TCPAddr).Port)}
	up1 := &testUpstream{}

	// add the 1st A response record
	// this IP is alive, but it's slower than localhost
	up1.aResp = createARec("test.org.", "8.8.8.8")

	// add the 2nd A response record
	// This IP is alive and much faster
	up1.aRespArr = append(up1.aRespArr, createARec("test.org.", "127.0.0.1"))

	// Check that localhost is faster
	ups := []upstream.Upstream{up1}
	req := createHostTestMessage("test.org")
	resp, up, err := f.exchangeFastest(req, ups)
	assert.Nil(t, err)
	assert.Equal(t, up, up1)
	assert.NotNil(t, resp)
	ip := resp.Answer[0].(*dns.A).A.String()
	assert.Equal(t, "127.0.0.1", ip)
}

// . Upstream server returns "127.0.0.1", "127.0.0.2", "127.0.0.3" IP addresses:
//    all are dead
// . The algorithm returns "127.0.0.1"
func TestFastestAddrAllDead(t *testing.T) {
	f := FastestAddr{}
	f.Init()
	f.tcpPorts = []uint{40812}
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
