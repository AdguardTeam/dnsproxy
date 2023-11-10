package upstream

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(ameshkov): make tests here not depend on external servers.

func TestMain(m *testing.M) {
	// Disable logging in tests.
	log.SetOutput(io.Discard)

	os.Exit(m.Run())
}

func TestUpstream_bootstrapTimeout(t *testing.T) {
	const (
		timeout = 100 * time.Millisecond
		count   = 10
	)

	// Test listener that never accepts connections to emulate faulty bootstrap.
	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, udpListener.Close)

	rslv, err := NewUpstreamResolver(udpListener.LocalAddr().String(), &Options{
		Timeout: timeout,
	})
	require.NoError(t, err)

	// Create an upstream that uses this faulty bootstrap.
	u, err := AddressToUpstream("tls://random-domain-name", &Options{
		Bootstrap: rslv,
		Timeout:   timeout,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	ch := make(chan int, count)
	abort := make(chan string, 1)
	for i := 0; i < count; i++ {
		go func(idx int) {
			t.Logf("Start %d", idx)
			req := createTestMessage()

			start := time.Now()
			_, rErr := u.Exchange(req)
			elapsed := time.Since(start)

			if rErr == nil {
				// Must not happen since bootstrap server cannot work.
				abort <- fmt.Sprintf("the upstream must have timed out: %v", rErr)
			}

			// Check that the test didn't take too much time compared to the
			// configured timeout.  The actual elapsed time may be higher than
			// the timeout due to the execution environment, 3 is an arbitrarily
			// chosen multiplier to account for that.
			if elapsed > 3*timeout {
				abort <- fmt.Sprintf(
					"exchange took more time than the configured timeout: %s",
					elapsed,
				)
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

func TestUpstreams(t *testing.T) {
	googleRslv, err := NewUpstreamResolver("8.8.8.8:53", &Options{
		Timeout: timeout,
	})
	require.NoError(t, err)
	cloudflareRslv, err := NewUpstreamResolver("1.0.0.1:53", &Options{
		Timeout: timeout,
	})
	require.NoError(t, err)

	upstreams := []struct {
		bootstrap Resolver
		address   string
	}{{
		bootstrap: googleRslv,
		address:   "8.8.8.8:53",
	}, {
		bootstrap: nil,
		address:   "1.1.1.1",
	}, {
		bootstrap: cloudflareRslv,
		address:   "1.1.1.1",
	}, {
		bootstrap: nil,
		address:   "tcp://1.1.1.1:53",
	}, {
		bootstrap: nil,
		address:   "94.140.14.14:5353",
	}, {
		bootstrap: nil,
		address:   "tls://1.1.1.1",
	}, {
		bootstrap: nil,
		address:   "tls://9.9.9.9:853",
	}, {
		bootstrap: googleRslv,
		address:   "tls://dns.adguard.com",
	}, {
		bootstrap: googleRslv,
		address:   "tls://dns.adguard.com:853",
	}, {
		bootstrap: googleRslv,
		address:   "tls://dns.adguard.com:853",
	}, {
		bootstrap: nil,
		address:   "tls://one.one.one.one",
	}, {
		bootstrap: googleRslv,
		address:   "https://1dot1dot1dot1.cloudflare-dns.com/dns-query",
	}, {
		bootstrap: nil,
		address:   "https://dns.google/dns-query",
	}, {
		bootstrap: nil,
		address:   "https://doh.opendns.com/dns-query",
	}, {
		// AdGuard DNS (DNSCrypt)
		bootstrap: nil,
		address:   "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}, {
		// AdGuard Family (DNSCrypt)
		bootstrap: googleRslv,
		address:   "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
	}, {
		// Cloudflare DNS (DNS-over-HTTPS)
		bootstrap: googleRslv,
		address:   "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk",
	}, {
		// Google (Plain)
		bootstrap: nil,
		address:   "sdns://AAcAAAAAAAAABzguOC44Ljg",
	}, {
		// AdGuard DNS (DNS-over-TLS)
		bootstrap: googleRslv,
		address:   "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t",
	}, {
		// AdGuard DNS (DNS-over-QUIC)
		bootstrap: googleRslv,
		address:   "sdns://BAcAAAAAAAAAAAAXZG5zLmFkZ3VhcmQtZG5zLmNvbTo3ODQ",
	}, {
		// Cloudflare DNS (DNS-over-HTTPS)
		bootstrap: nil,
		address:   "https://1.1.1.1/dns-query",
	}, {
		// AdGuard DNS (DNS-over-QUIC)
		bootstrap: googleRslv,
		address:   "quic://dns.adguard-dns.com",
	}, {
		// Google DNS (HTTP3)
		bootstrap: nil,
		address:   "h3://dns.google/dns-query",
	}}

	for _, test := range upstreams {
		t.Run(test.address, func(t *testing.T) {
			u, upsErr := AddressToUpstream(
				test.address,
				&Options{Bootstrap: test.bootstrap, Timeout: timeout},
			)
			require.NoErrorf(t, upsErr, "failed to generate upstream from address %s", test.address)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			checkUpstream(t, u, test.address)
		})
	}
}

func TestAddressToUpstream(t *testing.T) {
	cloudflareRslv, err := NewUpstreamResolver("1.1.1.1", nil)
	require.NoError(t, err)

	opt := &Options{Bootstrap: cloudflareRslv}

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
	}, {
		addr: "h3://one.one.one.one",
		opt:  opt,
		want: "https://one.one.one.one:443",
	}}

	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			u, upsErr := AddressToUpstream(tc.addr, tc.opt)
			require.NoError(t, upsErr)
			testutil.CleanupAndRequireSuccess(t, u.Close)

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
		addr: "12345.1.1.1:1234567",
		wantErrMsg: `invalid address 12345.1.1.1:1234567: ` +
			`strconv.ParseUint: parsing "1234567": value out of range`,
	}, {
		addr: ":1234567",
		wantErrMsg: `invalid address :1234567: ` +
			`strconv.ParseUint: parsing "1234567": value out of range`,
	}, {
		addr:       "host:",
		wantErrMsg: `invalid address host:: strconv.ParseUint: parsing "": invalid syntax`,
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
		bootstrap string
	}{{
		address:   "tls://one.one.one.one/",
		bootstrap: "tls://1.1.1.1",
	}, {
		address:   "tls://one.one.one.one/",
		bootstrap: "https://1.1.1.1/dns-query",
	}, {
		address: "tls://one.one.one.one/",
		// Cisco OpenDNS
		bootstrap: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
	}}

	for _, tc := range upstreams {
		t.Run(tc.address, func(t *testing.T) {
			rslv, err := NewUpstreamResolver(tc.bootstrap, &Options{
				Timeout: timeout,
			})
			require.NoError(t, err)

			u, err := AddressToUpstream(tc.address, &Options{
				Bootstrap: rslv,
				Timeout:   timeout,
			})
			require.NoErrorf(t, err, "failed to generate upstream from address %s", tc.address)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			checkUpstream(t, u, tc.address)
		})
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
			var rslv ConsequentResolver
			for _, b := range tc.bootstrap {
				r, err := NewUpstreamResolver(b, &Options{
					Timeout: timeout,
				})
				require.NoError(t, err)

				rslv = append(rslv, r)
			}

			u, err := AddressToUpstream(tc.address, &Options{
				Bootstrap: rslv,
				Timeout:   timeout,
			})
			require.NoErrorf(t, err, "failed to generate upstream from address %s", tc.address)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			checkUpstream(t, u, tc.address)
		})
	}

	t.Run("bad_bootstrap", func(t *testing.T) {
		_, err := NewUpstreamResolver("asdfasdf", nil)
		assert.Error(t, err) // bad bootstrap "asdfasdf"
	})
}

func TestAddressToUpstream_StaticResolver(t *testing.T) {
	h := func(w dns.ResponseWriter, m *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(m)))
	}
	dotSrv := startDoTServer(t, h)
	dohSrv := startDoHServer(t, testDoHServerOptions{})
	_, dohPort, err := net.SplitHostPort(dohSrv.addr)
	require.NoError(t, err)

	badResolver := &UpstreamResolver{Upstream: nil}

	dotStamp := (&dnsstamps.ServerStamp{
		ServerAddrStr: netip.AddrPortFrom(netutil.IPv4Localhost(), uint16(dotSrv.port)).String(),
		Proto:         dnsstamps.StampProtoTypeTLS,
		ProviderName:  netip.AddrPortFrom(netutil.IPv4Localhost(), uint16(dotSrv.port)).String(),
	}).String()
	dohStamp := (&dnsstamps.ServerStamp{
		ServerAddrStr: dohSrv.addr,
		Proto:         dnsstamps.StampProtoTypeDoH,
		ProviderName:  dohSrv.addr,
		Path:          "/dns-query",
	}).String()

	upstreams := []struct {
		rslv    Resolver
		name    string
		address string
	}{{
		rslv:    StaticResolver{netutil.IPv4Localhost()},
		name:    "dot",
		address: fmt.Sprintf("tls://some.dns.server:%d", dotSrv.port),
	}, {
		rslv:    StaticResolver{netutil.IPv4Localhost()},
		name:    "doh",
		address: fmt.Sprintf("https://some.dns.server:%s/dns-query", dohPort),
	}, {
		rslv:    badResolver,
		name:    "dot_stamp",
		address: dotStamp,
	}, {
		rslv:    badResolver,
		name:    "doh_stamp",
		address: dohStamp,
	}}

	for _, tc := range upstreams {
		t.Run(tc.name, func(t *testing.T) {
			opts := &Options{
				Bootstrap:          tc.rslv,
				Timeout:            timeout,
				InsecureSkipVerify: true,
			}
			u, uErr := AddressToUpstream(tc.address, opts)
			require.NoError(t, uErr)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			assert.NotPanics(t, func() {
				checkUpstream(t, u, tc.address)
			})
		})
	}
}

func TestAddPort(t *testing.T) {
	testCases := []struct {
		name string
		want string
		host string
		port uint16
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
		host: "::1",
		port: 1,
	}, {
		name: "ipv6_with_brackets",
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
		name: "ipv6_with_brackets_and_port",
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

// checkUpstream sends a test message to the upstream and checks the result.
func checkUpstream(t *testing.T, u Upstream, addr string) {
	t.Helper()

	req := createTestMessage()
	reply, err := u.Exchange(req)
	require.NoErrorf(t, err, "couldn't talk to upstream %s", addr)

	requireResponse(t, req, reply)
}

// checkRaceCondition runs several goroutines in parallel and each of them calls
// checkUpstream several times.
func checkRaceCondition(u Upstream) {
	wg := sync.WaitGroup{}

	// The number of requests to run in every goroutine.
	reqCount := 10
	// The overall number of goroutines to run.
	goroutinesCount := 3

	makeRequests := func() {
		defer wg.Done()
		for i := 0; i < reqCount; i++ {
			req := createTestMessage()
			// Ignore exchange errors here, the point is to check for races.
			_, _ = u.Exchange(req)
		}
	}

	wg.Add(goroutinesCount)
	for i := 0; i < goroutinesCount; i++ {
		go makeRequests()
	}

	wg.Wait()
}

// createTestMessage creates a *dns.Msg that we use for tests and that we then
// check with requireResponse.
func createTestMessage() (m *dns.Msg) {
	return createHostTestMessage("google-public-dns-a.google.com")
}

// respondToTestMessage crafts a *dns.Msg response to a message created by
// createTestMessage.
func respondToTestMessage(m *dns.Msg) (resp *dns.Msg) {
	resp = &dns.Msg{}
	resp.SetReply(m)
	resp.Answer = append(resp.Answer, &dns.A{
		A: net.IPv4(8, 8, 8, 8),
		Hdr: dns.RR_Header{
			Name:   "google-public-dns-a.google.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    100,
		},
	})

	return resp
}

// createHostTestMessage creates a *dns.Msg with A request for the specified
// host name.
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

// requireResponse validates that the *dns.Msg is a valid response to the
// message created by createTestMessage.
func requireResponse(t require.TestingT, req, reply *dns.Msg) {
	require.NotNil(t, reply)
	require.Lenf(t, reply.Answer, 1, "wrong number of answers: %d", len(reply.Answer))
	require.Equal(t, req.Id, reply.Id)

	a, ok := reply.Answer[0].(*dns.A)
	require.Truef(t, ok, "wrong answer type: %v", reply.Answer[0])

	require.Equalf(t, net.IPv4(8, 8, 8, 8), a.A.To16(), "wrong answer: %v", a.A)
}

// createServerTLSConfig creates a test server TLS configuration. It returns
// a *tls.Config that can be used for both the server and the client and the
// root certificate pem-encoded.
// TODO(ameshkov): start using rootCAs in tests instead of InsecureVerify.
func createServerTLSConfig(
	tb testing.TB,
	tlsServerName string,
) (tlsConfig *tls.Config, rootCAs *x509.CertPool) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(tb, err)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(tb, err)

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * time.Hour * 24)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AdGuard Tests"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	template.DNSNames = append(template.DNSNames, tlsServerName)

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		publicKey(privateKey),
		privateKey,
	)
	require.NoError(tb, err)

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	cert, err := tls.X509KeyPair(certPem, keyPem)
	require.NoError(tb, err)

	rootCAs = x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(certPem)

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   tlsServerName,
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, rootCAs
}

// publicKey extracts the public key from the specified private key.
func publicKey(priv any) (pub any) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
