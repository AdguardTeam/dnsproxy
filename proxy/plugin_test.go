package proxy

import "testing"

func TestPlugins(t *testing.T) {
	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.Start()

	dnsProxy.Stop()
}
