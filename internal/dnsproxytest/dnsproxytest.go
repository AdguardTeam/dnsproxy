// Package dnsproxytest provides utilities for testing dnsproxy module.
package dnsproxytest

import (
	"net"
	"net/netip"
	"runtime"
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
)

var (
	// LocalhostAnyPort is a [netip.AddrPort] having a value of 127.0.0.1:0.
	LocalhostAnyPort = netip.AddrPortFrom(netutil.IPv4Localhost(), 0)

	// IPv4 is a common IPv4 address for test response A records.  It uses the
	// [net.IP] form for convenient comparisons with [dns.A.A].
	//
	// TODO(f.setrakov): Use an address from one of the IPv4 documentation
	// ranges.
	IPv4 = net.IPv4(8, 8, 8, 8)
)

// DefaultTrustedProxies is a set of trusted proxies that includes all possible
// IP addresses.
var DefaultTrustedProxies = netutil.SliceSubnetSet{
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::/0"),
}

// NewTestRequest returns common DNS request for tests.
func NewTestRequest() (msg *dns.Msg) {
	return NewTestRequestWithHost("google-public-dns-a.google.com")
}

// NewTestRequestWithHost returns DNS request with common values and given host.
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

// RequireResponse is a test helper that ensures that the DNS reply matches the
// request and contains an A record with [IPv4].  It is intended to be used
// alongside [NewTestRequest] or [NewTestRequestWithHost].
func RequireResponse(tb testing.TB, req, reply *dns.Msg) {
	tb.Helper()

	require.NotNil(tb, reply)
	require.Len(tb, reply.Answer, 1)
	require.Equal(tb, req.Id, reply.Id)

	a := testutil.RequireTypeAssert[*dns.A](tb, reply.Answer[0])

	require.Equal(tb, IPv4, a.A.To16())
}

// NewFreePort is a best-effort helper function that returns a free TCP port
// that can be used for testing.  Note that there is theoretically a TOCTTOU
// race here: the port may be reoccupied between the time it is released and the
// time the caller binds to it.
//
// TODO(m.kazantsev):  Move to the top-level dnsproxytest package.
func NewFreePort(tb testing.TB) (p uint) {
	tb.Helper()

	l, err := net.Listen("tcp", LocalhostAnyPort.String())
	require.NoError(tb, err)

	p = uint(l.Addr().(*net.TCPAddr).Port)

	// Stop listening immediately.
	require.NoError(tb, l.Close())

	// Sleeping for some time may be necessary on Windows.
	if runtime.GOOS == "windows" {
		time.Sleep(100 * time.Millisecond)
	}

	return p
}
