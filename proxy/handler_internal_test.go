package proxy

import (
	"net"
	"sync"
	"testing"

	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilteringHandler(t *testing.T) {
	// Initializing the test middleware
	m := &sync.RWMutex{}
	blockResponse := false

	reqHandler := &TestHandler{
		OnHandle: func(p *Proxy, d *DNSContext) (err error) {
			m.Lock()
			defer m.Unlock()

			if !blockResponse {
				// Use the default Resolve method if response is not blocked.
				return p.Resolve(d)
			}

			resp := dns.Msg{}
			resp.SetRcode(d.Req, dns.RcodeNotImplemented)
			resp.RecursionAvailable = true

			// Set the response right away
			d.Res = &resp

			return nil
		},
	}

	// Prepare the proxy server.
	dnsProxy := mustNew(t, &Config{
		Logger:         testLogger,
		TrustedProxies: defaultTrustedProxies,
		UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		RequestHandler: reqHandler,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
	})

	servicetest.RequireRun(t, dnsProxy, testTimeout)

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{
		Net:     string(ProtoUDP),
		Timeout: testTimeout,
	}

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
