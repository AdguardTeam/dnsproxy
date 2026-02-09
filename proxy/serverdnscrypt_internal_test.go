package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/stretchr/testify/assert"
)

// TODO(d.kolyshev): Remove this after quic-go has migrated to slog.
func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

func getFreePort() uint {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := uint(l.Addr().(*net.TCPAddr).Port)

	// stop listening immediately
	_ = l.Close()

	// sleep for 100ms (may be necessary on Windows)
	time.Sleep(100 * time.Millisecond)
	return port
}

func createTestDNSCryptProxy(t *testing.T) (*Proxy, dnscrypt.ResolverConfig) {
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil)
	assert.NoError(t, err)

	cert, err := rc.CreateCert()
	assert.NoError(t, err)

	port := getFreePort()
	p := mustNew(t, &Config{
		Logger: slogutil.NewDiscardLogger(),
		DNSCryptUDPListenAddr: []*net.UDPAddr{{
			Port: int(port), IP: net.ParseIP(listenIP),
		}},
		DNSCryptTCPListenAddr: []*net.TCPAddr{{
			Port: int(port), IP: net.ParseIP(listenIP),
		}},
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
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

func TestDNSCryptProxy(t *testing.T) {
	// Prepare the proxy server
	dnsProxy, rc := createTestDNSCryptProxy(t)

	servicetest.RequireRun(t, dnsProxy, testTimeout)

	// Generate a DNS stamp
	port := testutil.RequireTypeAssert[*net.UDPAddr](t, dnsProxy.Addr(ProtoDNSCrypt)).Port
	addr := netutil.JoinHostPort(listenIP, uint16(port))
	stamp, err := rc.CreateStamp(addr)
	assert.Nil(t, err)

	// Test DNSCrypt proxy on both UDP and TCP
	checkDNSCryptProxy(t, "udp", stamp)
	checkDNSCryptProxy(t, "tcp", stamp)
}

func checkDNSCryptProxy(t *testing.T, proto string, stamp dnsstamps.ServerStamp) {
	// Create a DNSCrypt client
	c := &dnscrypt.Client{
		Timeout: defaultTimeout,
		Net:     proto,
	}

	// Fetch the server certificate
	ri, err := c.DialStamp(stamp)
	assert.Nil(t, err)

	// Send the test message
	msg := newTestMessage()
	reply, err := c.Exchange(msg, ri)
	assert.Nil(t, err)
	requireResponse(t, msg, reply)
}
