// Package dnsproxytest provides utilities for testing dnsproxy module.
package dnsproxytest

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const (
	// Timeout is the common timeout for tests and contexts.
	Timeout = 1 * time.Second

	// CacheSize is the default size of the cache in bytes.
	CacheSize = 64 * 1024

	// MessageCount is the default number of messages used in tests requiring
	// multiple DNS requests.
	MessageCount = 10

	// TLSServerName is a common TLS server name value for tests.
	TLSServerName = "testdns.adguard.com"

	// Host is a common host for tests.
	Host = "test.example"

	// TTL is a common time-to-live value in seconds for tests.
	TTL = 300
)

var (
	// LocalhostAnyPort is a [netip.AddrPort] having a value of 127.0.0.1:0.
	LocalhostAnyPort = netip.AddrPortFrom(netutil.IPv4Localhost(), 0)

	// IPv4 is a common IPv4 address for tests.
	IPv4 = net.IPv4(192, 0, 2, 1)
)

// DefaultTrustedProxies is a set of trusted proxies that includes all possible
// IP addresses.
var DefaultTrustedProxies = netutil.SliceSubnetSet{
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::/0"),
}

// NewTestRequest returns common DNS request for tests.  This helper must not be
// used in IPv6-related tests.
func NewTestRequest() (msg *dns.Msg) {
	return NewTestRequestWithHost(Host)
}

// NewTestRequestWithHost returns DNS request with common values and given host.
// This helper must not be used in IPv6-related tests.
func NewTestRequestWithHost(host string) (req *dns.Msg) {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(host),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}

// NewTestResponse is a helper that returns new default response for given
// request.  Response will contain single A record with [IPv4] value.  req must
// not be nil.  This helper must not be used in IPv6-related tests.
func NewTestResponse(req *dns.Msg) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetReply(req)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Class:  dns.ClassINET,
			Rrtype: dns.TypeA,
			Ttl:    TTL,
		},
		A: IPv4,
	}}

	return resp
}

// RequireResponse is a test helper that ensures that the DNS reply matches the
// request and contains an A record with [IPv4].  It is intended to be used
// alongside [NewTestRequest] or [NewTestRequestWithHost].  This helper must not
// be used in IPv6-related tests.
func RequireResponse(tb testing.TB, req, reply *dns.Msg) {
	tb.Helper()

	require.NotNil(tb, reply)
	require.Len(tb, reply.Answer, 1)
	require.Equal(tb, req.Id, reply.Id)

	a := testutil.RequireTypeAssert[*dns.A](tb, reply.Answer[0])

	require.Equal(tb, IPv4, a.A.To16())
}
