package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/internal/nettest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/ameshkov/dnsstamps"
	"github.com/stretchr/testify/require"
)

func TestProxy_HandleDNSRequest_dnscrypt(t *testing.T) {
	t.Parallel()

	// Prepare the proxy server.
	dnsProxy, rc := newTestDNSCryptProxy(t)

	servicetest.RequireRun(t, dnsProxy, dnsproxytest.Timeout)

	// Generate a DNS stamp.
	port := testutil.RequireTypeAssert[*net.UDPAddr](t, dnsProxy.Addr(ProtoDNSCrypt)).Port
	addr := netutil.JoinHostPort(listenIP, uint16(port))
	stamp, err := rc.CreateStamp(addr)
	require.NoError(t, err)

	// Test DNSCrypt proxy on both UDP and TCP.
	checkDNSCryptProxy(t, dnscrypt.ProtoUDP, stamp)
	checkDNSCryptProxy(t, dnscrypt.ProtoTCP, stamp)
}

// newTestDNSCryptProxy is a helper function that creates a DNSCrypt proxy and
// the corresponding resolver configuration for testing.
func newTestDNSCryptProxy(tb testing.TB) (p *Proxy, rc dnscrypt.ResolverConfig) {
	tb.Helper()

	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(tb, err)

	cert, err := rc.NewCert()
	require.NoError(tb, err)

	port := nettest.NewFreePort(tb)
	p = mustNew(tb, &Config{
		Logger: testLogger,
		DNSCryptUDPListenAddr: []*net.UDPAddr{{
			Port: int(port), IP: net.ParseIP(listenIP),
		}},
		DNSCryptTCPListenAddr: []*net.TCPAddr{{
			Port: int(port), IP: net.ParseIP(listenIP),
		}},
		UpstreamConfig:         newTestUpstreamConfig(tb, newTestUpstream(tb)),
		TrustedProxies:         dnsproxytest.DefaultTrustedProxies,
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
		CacheMinTTL:            20,
		CacheMaxTTL:            40,
		DNSCryptProviderName:   rc.ProviderName,
		DNSCryptResolverCert:   cert,
	})

	return p, rc
}

// checkDNSCryptProxy is a helper function that checks the DNSCrypt proxy by
// sending a test message and verifying the response.
func checkDNSCryptProxy(tb testing.TB, proto dnscrypt.Proto, stamp dnsstamps.ServerStamp) {
	tb.Helper()

	c := dnscrypt.NewClient(&dnscrypt.ClientConfig{
		Logger: slogutil.NewDiscardLogger(),
		Proto:  proto,
	})

	ctx := testutil.ContextWithTimeout(tb, dnsproxytest.Timeout)

	ri, err := c.DialStampContext(ctx, stamp)
	require.NoError(tb, err)

	msg := dnsproxytest.NewTestRequest()
	reply, err := c.ExchangeContext(ctx, msg, ri)
	require.NoError(tb, err)
	dnsproxytest.RequireResponse(tb, msg, reply)
}
