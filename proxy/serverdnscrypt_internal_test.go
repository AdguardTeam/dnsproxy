package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/ameshkov/dnsstamps"
	"github.com/stretchr/testify/require"
)

func TestDNSCryptProxy(t *testing.T) {
	t.Parallel()

	// Prepare the proxy server.
	dnsProxy, rc := newTestDNSCryptProxy(t)

	servicetest.RequireRun(t, dnsProxy, testTimeout)

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

	port := dnsproxytest.NewFreePort(tb)
	upstreamConf := newTestUpstreamConfig(tb, defaultTimeout, testDefaultUpstreamAddr)
	p = mustNew(tb, &Config{
		Logger: testLogger,
		DNSCryptUDPListenAddr: []*net.UDPAddr{{
			Port: int(port), IP: net.ParseIP(listenIP),
		}},
		DNSCryptTCPListenAddr: []*net.TCPAddr{{
			Port: int(port), IP: net.ParseIP(listenIP),
		}},
		UpstreamConfig:         upstreamConf,
		TrustedProxies:         defaultTrustedProxies,
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

	// Create a DNSCrypt client.
	c := dnscrypt.NewClient(&dnscrypt.ClientConfig{
		Logger: slogutil.NewDiscardLogger(),
		Proto:  proto,
	})

	ctx := testutil.ContextWithTimeout(tb, testTimeout)

	// Fetch the server certificate.
	ri, err := c.DialStampContext(ctx, stamp)
	require.NoError(tb, err)

	// Send the test message.
	msg := newTestMessage()
	reply, err := c.ExchangeContext(ctx, msg, ri)
	require.NoError(tb, err)
	requireResponse(tb, msg, reply)
}
