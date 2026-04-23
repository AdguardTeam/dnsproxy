package proxy

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestUdpProxy(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	// Create a DNS-over-UDP client connection
	addr, err := dnsProxy.Addr(ProtoUDP)
	require.NoError(t, err)

	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)

	sendTestMessages(t, conn)
}
