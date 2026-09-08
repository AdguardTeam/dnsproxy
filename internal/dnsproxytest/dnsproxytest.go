// Package dnsproxytest provides test utilities and mock implementations
// for the dnsproxy module interfaces.
package dnsproxytest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const (
	// Timeout is the common timeout for tests and contexts.
	Timeout = 1 * time.Second

	// CacheSize is the default size of the cache in bytes.
	CacheSize = 64 * 1024

	// MessageCount is the default number of messages used in tests requiring
	// multiple DNS requests.
	MessageCount = 10

	// TLSServerName is a common TLS server name value for tests.
	TLSServerName = "testdns.adguard.com"
)

// LocalhostAnyPort is a [netip.AddrPort] having a value of 127.0.0.1:0.
var LocalhostAnyPort = netip.AddrPortFrom(netutil.IPv4Localhost(), 0)

// DefaultTrustedProxies is a set of trusted proxies that includes all possible
// IP addresses.
var DefaultTrustedProxies = netutil.SliceSubnetSet{
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::0/0"),
}

// NewTestMessage returns common DNS message for tests.
func NewTestMessage() (msg *dns.Msg) {
	return NewHostTestMessage("google-public-dns-a.google.com")
}

// NewHostTestMessage returns DNS message with common values and given host.
func NewHostTestMessage(host string) (req *dns.Msg) {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   host + ".",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}

// RequireResponse is a test helper that makes sure that given DNS reply matches
// common expectations as well as the given request.
func RequireResponse(tb testing.TB, req, reply *dns.Msg) {
	tb.Helper()

	require.NotNil(tb, reply)
	require.Len(tb, reply.Answer, 1)
	require.Equal(tb, req.Id, reply.Id)

	a := testutil.RequireTypeAssert[*dns.A](tb, reply.Answer[0])

	require.Equal(tb, net.IPv4(8, 8, 8, 8), a.A.To16())
}

// NewTLSConfig is a test helper that generates new TLS config.
func NewTLSConfig(tb testing.TB) (conf *tls.Config, certPem []byte) {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(tb, err)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(tb, err)

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * time.Hour * 24)

	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"AdGuard Tests"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{TLSServerName},
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	require.NoError(tb, err)

	certPem = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	cert, err := tls.X509KeyPair(certPem, keyPem)
	require.NoError(tb, err)

	return &tls.Config{Certificates: []tls.Certificate{cert}, ServerName: TLSServerName}, certPem
}

// NewFreePort is a best-effort helper function that returns a free TCP port
// that can be used for testing.  Note that there is theoretically a TOCTTOU
// race here: the port may be reoccupied between the time it is released and the
// time the caller binds to it.
//
// TODO(m.kazantsev):  Move to the top-level dnsproxytest package.
func NewFreePort(tb testing.TB) (p uint) {
	tb.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(tb, err)

	p = uint(l.Addr().(*net.TCPAddr).Port)

	// Stop listening immediately.
	require.NoError(tb, l.Close())

	// Sleeping for some time may be necessary on Windows.
	if runtime.GOOS == "windows" {
		time.Sleep(100 * time.Millisecond)
	}

	return p
}
