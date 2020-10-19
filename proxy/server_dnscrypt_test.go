package proxy

import (
	"fmt"
	"net"
	"testing"

	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/stretchr/testify/assert"
)

func TestDNSCryptProxy(t *testing.T) {
	// Prepare the proxy server
	dnsProxy, rc := createTestDNSCryptProxy(t)

	// Start listening
	err := dnsProxy.Start()
	assert.Nil(t, err)
	defer func() {
		assert.Nil(t, dnsProxy.Stop())
	}()

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
	msg := createTestMessage()
	reply, err := c.Exchange(msg, ri)
	assert.Nil(t, err)
	assertResponse(t, reply)
}
