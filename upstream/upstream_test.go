package upstream

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Disable logging in tests.
	log.SetOutput(io.Discard)

	os.Exit(m.Run())
}

func TestBootstrapTimeout(t *testing.T) {
	const (
		timeout = 100 * time.Millisecond
		count   = 10
	)

	// Specifying some wrong port instead so that bootstrap DNS timed out for sure
	u, err := AddressToUpstream("tls://one.one.one.one", &Options{
		Bootstrap: []string{"8.8.8.8:555"},
		Timeout:   timeout,
	})
	require.NoError(t, err)

	ch := make(chan int, count)
	abort := make(chan string, 1)
	for i := 0; i < count; i++ {
		go func(idx int) {
			t.Logf("Start %d", idx)
			start := time.Now()
			req := createTestMessage()

			_, err := u.Exchange(req)

			if err == nil {
				abort <- fmt.Sprintf("the upstream must have timed out: %v", err)
			}

			elapsed := time.Since(start)
			if elapsed > 2*timeout {
				abort <- fmt.Sprintf("exchange took more time than the configured timeout: %v", elapsed)
			}
			t.Logf("Finished %d", idx)
			ch <- idx
		}(i)
	}
	for i := 0; i < count; i++ {
		select {
		case res := <-ch:
			t.Logf("Got result from %d", res)
		case msg := <-abort:
			t.Fatalf("Aborted from the goroutine: %s", msg)
		case <-time.After(timeout * 10):
			t.Fatalf("No response in time")
		}
	}
}

// TestUpstreamRace launches several parallel lookups, useful when testing with -race
func TestUpstreamRace(t *testing.T) {
	const (
		timeout = 5 * time.Second
		count   = 5
	)

	// Specifying some wrong port instead so that bootstrap DNS timed out for sure
	u, err := AddressToUpstream(
		"tls://1.1.1.1",
		&Options{Timeout: timeout},
	)
	if err != nil {
		t.Fatalf("cannot create upstream: %s", err)
	}

	ch := make(chan int, count)
	abort := make(chan string, 1)
	for i := 0; i < count; i++ {
		go func(idx int) {
			t.Logf("Start %d", idx)
			req := createTestMessage()
			res, err := u.Exchange(req)
			if err != nil {
				abort <- fmt.Sprintf("%s failed to resolve: %v", u.Address(), err)
				return
			}
			assertResponse(t, res)
			t.Logf("Finished %d", idx)
			ch <- idx
		}(i)
	}
	for i := 0; i < count; i++ {
		select {
		case res := <-ch:
			t.Logf("Got result from %d", res)
		case msg := <-abort:
			t.Fatalf("Aborted from the goroutine: %s", msg)
		case <-time.After(timeout * 10):
			t.Fatalf("No response in time")
		}
	}
}

func TestUpstreams(t *testing.T) {
	upstreams := []struct {
		address   string
		bootstrap []string
	}{{
		address:   "8.8.8.8:53",
		bootstrap: []string{"8.8.8.8:53"},
	}, {
		address:   "1.1.1.1",
		bootstrap: []string{},
	}, {
		address:   "1.1.1.1",
		bootstrap: []string{"1.0.0.1"},
	}, {
		address:   "tcp://1.1.1.1:53",
		bootstrap: []string{},
	}, {
		address:   "94.140.14.14:5353",
		bootstrap: []string{},
	}, {
		address:   "tls://1.1.1.1",
		bootstrap: []string{},
	}, {
		address:   "tls://9.9.9.9:853",
		bootstrap: []string{},
	}, {
		address:   "tls://dns.adguard.com",
		bootstrap: []string{"8.8.8.8:53"},
	}, {
		address:   "tls://dns.adguard.com:853",
		bootstrap: []string{"8.8.8.8:53"},
	}, {
		address:   "tls://dns.adguard.com:853",
		bootstrap: []string{"8.8.8.8"},
	}, {
		address:   "tls://one.one.one.one",
		bootstrap: []string{},
	}, {
		address:   "https://1dot1dot1dot1.cloudflare-dns.com/dns-query",
		bootstrap: []string{"8.8.8.8:53"},
	}, {
		address:   "https://dns.google/dns-query",
		bootstrap: []string{},
	}, {
		address:   "https://doh.opendns.com/dns-query",
		bootstrap: []string{},
	}, {
		// AdGuard DNS (DNSCrypt)
		address:   "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		bootstrap: []string{},
	}, {
		// AdGuard Family (DNSCrypt)
		address:   "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
		bootstrap: []string{"8.8.8.8"},
	}, {
		// Cloudflare DNS (DoH)
		address:   "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk",
		bootstrap: []string{"8.8.8.8:53"},
	}, {
		// Google (Plain)
		address:   "sdns://AAcAAAAAAAAABzguOC44Ljg",
		bootstrap: []string{},
	}, {
		// AdGuard DNS (DNS-over-TLS)
		address:   "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t",
		bootstrap: []string{"8.8.8.8:53"},
	}, {
		// AdGuard DNS (DNS-over-QUIC)
		address:   "sdns://BAcAAAAAAAAAAAATZG5zLmFkZ3VhcmQuY29tOjc4NA",
		bootstrap: []string{"8.8.8.8:53"},
	}, {
		// Cloudflare DNS
		address:   "https://1.1.1.1/dns-query",
		bootstrap: []string{},
	}, {
		// Cloudflare DNS
		address:   "quic://dns-unfiltered.adguard.com:784",
		bootstrap: []string{},
	}}
	for _, test := range upstreams {
		t.Run(test.address, func(t *testing.T) {
			u, err := AddressToUpstream(
				test.address,
				&Options{Bootstrap: test.bootstrap, Timeout: timeout},
			)
			require.NoErrorf(t, err, "failed to generate upstream from address %s", test.address)

			checkUpstream(t, u, test.address)
		})
	}
}

func TestAddressToUpstream(t *testing.T) {
	opt := &Options{Bootstrap: []string{"1.1.1.1"}}

	testCases := []struct {
		addr string
		opt  *Options
		want string
	}{{
		addr: "1.1.1.1",
		opt:  nil,
		want: "1.1.1.1:53",
	}, {
		addr: "one.one.one.one",
		opt:  nil,
		want: "one.one.one.one:53",
	}, {
		addr: "udp://one.one.one.one",
		opt:  nil,
		want: "one.one.one.one:53",
	}, {
		addr: "tcp://one.one.one.one",
		opt:  opt,
		want: "tcp://one.one.one.one:53",
	}, {
		addr: "tls://one.one.one.one",
		opt:  opt,
		want: "tls://one.one.one.one:853",
	}, {
		addr: "https://one.one.one.one",
		opt:  opt,
		want: "https://one.one.one.one:443",
	}}

	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			u, err := AddressToUpstream(tc.addr, tc.opt)
			require.NoError(t, err)

			assert.Equal(t, tc.want, u.Address())
		})
	}
}

func TestAddressToUpstream_bads(t *testing.T) {
	testCases := []struct {
		addr       string
		wantErrMsg string
	}{{
		addr:       "asdf://1.1.1.1",
		wantErrMsg: "unsupported url scheme: asdf",
	}, {
		addr:       "12345.1.1.1:1234567",
		wantErrMsg: "invalid address: 12345.1.1.1:1234567",
	}, {
		addr:       ":1234567",
		wantErrMsg: "invalid address: :1234567",
	}, {
		addr:       "host:",
		wantErrMsg: "invalid address: host:",
	}}

	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			_, err := AddressToUpstream(tc.addr, nil)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestUpstreamDoTBootstrap(t *testing.T) {
	upstreams := []struct {
		address   string
		bootstrap []string
	}{{
		address:   "tls://one.one.one.one/",
		bootstrap: []string{"tls://1.1.1.1"},
	}, {
		address:   "tls://one.one.one.one/",
		bootstrap: []string{"https://1.1.1.1/dns-query"},
	}, {
		address: "tls://one.one.one.one/",
		// Cisco OpenDNS
		bootstrap: []string{"sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ"},
	}}

	for _, tc := range upstreams {
		t.Run(tc.address, func(t *testing.T) {
			u, err := AddressToUpstream(tc.address, &Options{
				Bootstrap: tc.bootstrap,
				Timeout:   timeout,
			})
			require.NoErrorf(t, err, "failed to generate upstream from address %s", tc.address)

			checkUpstream(t, u, tc.address)
		})
	}
}

func TestUpstreamDefaultOptions(t *testing.T) {
	addresses := []string{"tls://1.1.1.1", "8.8.8.8"}

	for _, address := range addresses {
		u, err := AddressToUpstream(address, nil)
		require.NoErrorf(t, err, "failed to generate upstream from address %s", address)

		checkUpstream(t, u, address)
	}
}

// Test for DoH and DoT upstreams with two bootstraps (only one is valid)
func TestUpstreamsInvalidBootstrap(t *testing.T) {
	upstreams := []struct {
		address   string
		bootstrap []string
	}{{
		address:   "tls://dns.adguard.com",
		bootstrap: []string{"1.1.1.1:555", "8.8.8.8:53"},
	}, {
		address:   "tls://dns.adguard.com:853",
		bootstrap: []string{"1.0.0.1", "8.8.8.8:535"},
	}, {
		address:   "https://1dot1dot1dot1.cloudflare-dns.com/dns-query",
		bootstrap: []string{"8.8.8.1", "1.0.0.1"},
	}, {
		address:   "https://doh.opendns.com:443/dns-query",
		bootstrap: []string{"1.2.3.4:79", "8.8.8.8:53"},
	}, {
		// Cloudflare DNS (DoH)
		address:   "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk",
		bootstrap: []string{"8.8.8.8:53", "8.8.8.1:53"},
	}, {
		// AdGuard DNS (DNS-over-TLS)
		address:   "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t",
		bootstrap: []string{"1.2.3.4:55", "8.8.8.8"},
	}}

	for _, tc := range upstreams {
		t.Run(tc.address, func(t *testing.T) {
			u, err := AddressToUpstream(tc.address, &Options{
				Bootstrap: tc.bootstrap,
				Timeout:   timeout,
			})
			require.NoErrorf(t, err, "failed to generate upstream from address %s", tc.address)

			checkUpstream(t, u, tc.address)
		})
	}

	_, err := AddressToUpstream("tls://example.org", &Options{
		Bootstrap: []string{"8.8.8.8", "asdfasdf"},
	})
	assert.Error(t, err) // bad bootstrap "asdfasdf"
}

func TestUpstreamsWithServerIP(t *testing.T) {
	// use invalid bootstrap to make sure it fails if tries to use it
	invalidBootstrap := []string{"1.2.3.4:55"}

	upstreams := []struct {
		address   string
		serverIP  net.IP
		bootstrap []string
	}{{
		address:   "tls://dns.adguard.com",
		serverIP:  net.IP{94, 140, 14, 14},
		bootstrap: invalidBootstrap,
	}, {
		address:   "https://dns.adguard.com/dns-query",
		serverIP:  net.IP{94, 140, 14, 14},
		bootstrap: invalidBootstrap,
	}, {
		// AdGuard DNS DoH with the IP address specified.
		address:   "sdns://AgcAAAAAAAAADzE3Ni4xMDMuMTMwLjEzMAAPZG5zLmFkZ3VhcmQuY29tCi9kbnMtcXVlcnk",
		serverIP:  nil,
		bootstrap: invalidBootstrap,
	}, {
		// AdGuard DNS DoT with the IP address specified.
		address:   "sdns://AwAAAAAAAAAAEzE3Ni4xMDMuMTMwLjEzMDo4NTMAD2Rucy5hZGd1YXJkLmNvbQ",
		serverIP:  nil,
		bootstrap: invalidBootstrap,
	}}

	for _, tc := range upstreams {
		opts := &Options{
			Bootstrap:     tc.bootstrap,
			Timeout:       timeout,
			ServerIPAddrs: []net.IP{tc.serverIP},
		}
		u, err := AddressToUpstream(tc.address, opts)
		if err != nil {
			t.Fatalf("Failed to generate upstream from address %s: %s", tc.address, err)
		}

		t.Run(tc.address, func(t *testing.T) {
			checkUpstream(t, u, tc.address)
		})
	}
}

func checkUpstream(t *testing.T, u Upstream, addr string) {
	t.Helper()

	req := createTestMessage()
	reply, err := u.Exchange(req)
	require.NoErrorf(t, err, "couldn't talk to upstream %s", addr)

	assertResponse(t, reply)
}

func createTestMessage() *dns.Msg {
	return createHostTestMessage("google-public-dns-a.google.com")
}

func createHostTestMessage(host string) (req *dns.Msg) {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(host),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}

func assertResponse(t *testing.T, reply *dns.Msg) {
	require.NotNil(t, reply)
	require.Lenf(t, reply.Answer, 1, "wrong number of answers: %d", len(reply.Answer))

	a, ok := reply.Answer[0].(*dns.A)
	require.Truef(t, ok, "wrong answer type: %v", reply.Answer[0])

	assert.Equalf(t, net.IPv4(8, 8, 8, 8), a.A.To16(), "wrong answer: %v", a.A)
}

func TestAddPort(t *testing.T) {
	testCases := []struct {
		name string
		want string
		host string
		port int
	}{{
		name: "empty",
		want: ":0",
		host: "",
		port: 0,
	}, {
		name: "hostname",
		want: "example.org:53",
		host: "example.org",
		port: 53,
	}, {
		name: "ipv4",
		want: "1.2.3.4:1",
		host: "1.2.3.4",
		port: 1,
	}, {
		name: "ipv6",
		want: "[::1]:1",
		host: "[::1]",
		port: 1,
	}, {
		name: "hostname_with_port",
		want: "example.org:54",
		host: "example.org:54",
		port: 53,
	}, {
		name: "ipv4_with_port",
		want: "1.2.3.4:2",
		host: "1.2.3.4:2",
		port: 1,
	}, {
		name: "ipv6_with_port",
		want: "[::1]:2",
		host: "[::1]:2",
		port: 1,
	}}

	for _, tc := range testCases {
		u := &url.URL{
			Host: tc.host,
		}

		t.Run(tc.name, func(t *testing.T) {
			addPort(u, tc.port)
			assert.Equal(t, tc.want, u.Host)
		})
	}
}
