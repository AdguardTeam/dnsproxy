package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilteringHandler(t *testing.T) {
	// Initializing the test middleware
	m := &sync.RWMutex{}
	blockResponse := false

	// Prepare the proxy server
	dnsProxy := mustNew(t, &Config{
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies:         defaultTrustedProxies,
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		RequestHandler: func(p *Proxy, d *DNSContext) error {
			m.Lock()
			defer m.Unlock()

			if !blockResponse {
				// Use the default Resolve method if response is not blocked
				return p.Resolve(d)
			}

			resp := dns.Msg{}
			resp.SetRcode(d.Req, dns.RcodeNotImplemented)
			resp.RecursionAvailable = true

			// Set the response right away
			d.Res = &resp
			return nil
		},
	})

	// Start listening
	ctx := context.Background()
	err := dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	// Send the first message (not blocked)
	req := newTestMessage()

	r, _, err := client.Exchange(req, addr.String())
	require.NoError(t, err)
	requireResponse(t, req, r)

	// Now send the second and make sure it is blocked
	m.Lock()
	blockResponse = true
	m.Unlock()

	r, _, err = client.Exchange(req, addr.String())
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeNotImplemented, r.Rcode)
}
