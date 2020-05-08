package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestBogusNXDomainTypeA(t *testing.T) {
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.CacheEnabled = true
	dnsProxy.BogusNXDomain = []net.IP{net.ParseIP("4.3.2.1")}

	u := testUpstream{}
	dnsProxy.Upstreams = []upstream.Upstream{&u}
	err := dnsProxy.Start()
	assert.Nil(t, err)

	// first request
	// upstream answers with a bogus IP
	u.aResp = new(dns.A)
	u.aResp.Hdr.Rrtype = dns.TypeA
	u.aResp.Hdr.Name = "host."
	u.aResp.A = net.ParseIP("4.3.2.1")
	u.aResp.Hdr.Ttl = 10

	clientIP := net.IP{1, 2, 3, 0}
	d := DNSContext{}
	d.Req = createHostTestMessage("host")
	d.Addr = &net.TCPAddr{
		IP: clientIP,
	}

	err = dnsProxy.Resolve(&d)
	assert.Nil(t, err)

	// check response
	assert.NotNil(t, d.Res)
	assert.Equal(t, dns.RcodeNameError, d.Res.Rcode)

	// second request
	// upstream answers with a normal IP
	u.aResp = new(dns.A)
	u.aResp.Hdr.Rrtype = dns.TypeA
	u.aResp.Hdr.Name = "host."
	u.aResp.A = net.ParseIP("4.3.2.2")
	u.aResp.Hdr.Ttl = 10

	err = dnsProxy.Resolve(&d)
	assert.Nil(t, err)

	// check response
	assert.NotNil(t, d.Res)
	assert.Equal(t, dns.RcodeSuccess, d.Res.Rcode)

	_ = dnsProxy.Stop()
}
