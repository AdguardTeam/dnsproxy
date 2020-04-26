package fastip

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// . Upstream server returns "10.15.16.17" (dead), "127.0.0.1" (alive)
// . The algorithm returns "127.0.0.1"
func TestFastestAddrOneDeadIP(t *testing.T) {
	// Listener that we're using for TCP checks
	listener, err := net.Listen("tcp", ":0")
	assert.Nil(t, err)
	defer listener.Close()

	f := NewFastestAddr()
	f.tcpPorts = []uint{uint(listener.Addr().(*net.TCPAddr).Port)}
	up1 := &testUpstream{}
	up2 := &testUpstream{}

	// add the 1st A response record
	// this IP is dead (nothing is listening on our port)
	up1.addARec("test.org.", "10.15.16.17")

	// add the 2nd A response record
	// Alive IP address
	up2.addARec("test.org.", "127.0.0.1")

	// Check that it's alive
	ups := []upstream.Upstream{up1, up2}
	req := createHostTestMessage("test.org")
	resp, up, err := f.ExchangeFastest(req, ups)
	assert.Nil(t, err)
	assert.Equal(t, up, up2)
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

	f := NewFastestAddr()
	f.tcpPorts = []uint{443, uint(listener.Addr().(*net.TCPAddr).Port)}
	up1 := &testUpstream{}
	up2 := &testUpstream{}

	// add the 1st A response record
	// this IP is alive, but it's slower than localhost
	up1.addARec("test.org.", "8.8.8.8")

	// add the 2nd A response record
	// This IP is alive and much faster
	up2.addARec("test.org.", "127.0.0.1")

	// Check that localhost is faster
	ups := []upstream.Upstream{up1, up2}
	req := createHostTestMessage("test.org")
	resp, up, err := f.ExchangeFastest(req, ups)
	assert.Nil(t, err)
	assert.Equal(t, up, up2)
	assert.NotNil(t, resp)
	ip := resp.Answer[0].(*dns.A).A.String()
	assert.Equal(t, "127.0.0.1", ip)
}

// . Upstream server returns "127.0.0.1", "127.0.0.2", "127.0.0.3" IP addresses:
//    all are dead
// . The algorithm returns "127.0.0.1"
func TestFastestAddrAllDead(t *testing.T) {
	f := NewFastestAddr()
	f.tcpPorts = []uint{getFreePort()}
	up1 := &testUpstream{}

	up1.addARec("test.org.", "127.0.0.1")
	up1.addARec("test.org.", "127.0.0.2")
	up1.addARec("test.org.", "127.0.0.3")

	ups := []upstream.Upstream{up1}
	req := createHostTestMessage("test.org")
	resp, _, err := f.ExchangeFastest(req, ups)
	assert.Nil(t, err)
	ip := resp.Answer[0].(*dns.A).A.String()
	assert.Equal(t, "127.0.0.1", ip)
}

type testUpstream struct {
	aRespArr []*dns.A
}

func (u *testUpstream) Exchange(m *dns.Msg) (*dns.Msg, error) {
	resp := dns.Msg{}
	resp.SetReply(m)

	for _, a := range u.aRespArr {
		resp.Answer = append(resp.Answer, a)
	}

	return &resp, nil
}

func (u *testUpstream) Address() string {
	return ""
}

func (u *testUpstream) addARec(host, ip string) {
	a := new(dns.A)
	a.Hdr.Rrtype = dns.TypeA
	a.Hdr.Name = host
	a.A = net.ParseIP(ip)
	a.Hdr.Ttl = 60

	u.aRespArr = append(u.aRespArr, a)
}

func createHostTestMessage(host string) *dns.Msg {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	name := host + "."
	req.Question = []dns.Question{
		{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	return &req
}
