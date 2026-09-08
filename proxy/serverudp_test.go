package proxy_test

import (
	"testing"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestProxy_udp(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(proxy.ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)

	sendTestMessages(t, conn)
}
