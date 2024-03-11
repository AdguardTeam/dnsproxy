package proxy

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		DNSCryptUDPListenAddr: []*net.UDPAddr{{
			Port: int(port), IP: net.ParseIP(listenIP),
		}},
		DNSCryptTCPListenAddr: []*net.TCPAddr{{
			Port: int(port), IP: net.ParseIP(listenIP),
		}},
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
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

	// Start listening
	ctx := context.Background()
	err := dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	// Generate a DNS stamp
	addr := fmt.Sprintf("%s:%d", listenIP, dnsProxy.Addr(ProtoDNSCrypt).(*net.UDPAddr).Port)
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
