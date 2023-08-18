package upstream

import (
	"context"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helpers

// dnsCryptHandlerFunc is a function-based implementation of the
// [dnscrypt.Handler] interface.
type dnsCryptHandlerFunc func(w dnscrypt.ResponseWriter, r *dns.Msg) (err error)

// ServeDNS implements the [dnscrypt.Handler] interface for DNSCryptHandlerFunc.
func (f dnsCryptHandlerFunc) ServeDNS(w dnscrypt.ResponseWriter, r *dns.Msg) (err error) {
	return f(w, r)
}

// startTestDNSCryptServer starts a test DNSCrypt server with the specified
// resolver config and handler.
func startTestDNSCryptServer(
	t testing.TB,
	rc dnscrypt.ResolverConfig,
	h dnscrypt.Handler,
) (stamp dnsstamps.ServerStamp) {
	t.Helper()

	cert, err := rc.CreateCert()
	require.NoError(t, err)

	s := &dnscrypt.Server{
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      h,
	}
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		return s.Shutdown(ctx)
	})

	localhost := netutil.IPv4Localhost().AsSlice()

	// Prepare TCP listener.
	tcpAddr := &net.TCPAddr{IP: localhost, Port: 0}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, tcpConn.Close)

	// Prepare UDP listener on the same port.
	port := testutil.RequireTypeAssert[*net.TCPAddr](t, tcpConn.Addr()).Port
	udpAddr := &net.UDPAddr{IP: localhost, Port: port}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, udpConn.Close)

	// Start the server.
	go func() {
		udpErr := s.ServeUDP(udpConn)
		require.ErrorIs(testutil.PanicT{}, udpErr, net.ErrClosed)
	}()

	go func() {
		tcpErr := s.ServeTCP(tcpConn)
		require.NoError(testutil.PanicT{}, tcpErr)
	}()

	stamp, err = rc.CreateStamp(udpConn.LocalAddr().String())
	require.NoError(t, err)

	_, err = net.Dial("tcp", udpAddr.String())
	require.NoError(t, err)

	return stamp
}

// Tests

func TestUpstreamDNSCrypt(t *testing.T) {
	// AdGuard DNS (DNSCrypt)
	address := "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	u, err := AddressToUpstream(address, &Options{Timeout: dialTimeout})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// Test that it responds properly
	for i := 0; i < 10; i++ {
		checkUpstream(t, u, address)
	}
}

func TestDNSCrypt_Exchange_truncated(t *testing.T) {
	// Prepare the test DNSCrypt server config
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil)
	require.NoError(t, err)

	var udpNum, tcpNum atomic.Uint32
	h := dnsCryptHandlerFunc(func(w dnscrypt.ResponseWriter, r *dns.Msg) (err error) {
		if w.RemoteAddr().Network() == networkUDP {
			udpNum.Add(1)
		} else {
			tcpNum.Add(1)
		}

		res := (&dns.Msg{}).SetReply(r)
		answer := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Ttl:    300,
				Class:  dns.ClassINET,
			},
		}
		res.Answer = append(res.Answer, answer)

		veryLongString := strings.Repeat("VERY LONG STRING", 7)
		for i := 0; i < 50; i++ {
			answer.Txt = append(answer.Txt, veryLongString)
		}

		return w.WriteMsg(res)
	})
	srvStamp := startTestDNSCryptServer(t, rc, h)

	u, err := AddressToUpstream(srvStamp.String(), &Options{Timeout: timeout})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	req := (&dns.Msg{}).SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)

	// Check that response is not truncated (even though it's huge).
	res, err := u.Exchange(req)
	require.NoError(t, err)

	assert.False(t, res.Truncated)
	assert.Equal(t, 1, int(udpNum.Load()))
	assert.Equal(t, 1, int(tcpNum.Load()))
}

func TestDNSCrypt_Exchange_deadline(t *testing.T) {
	// Prepare the test DNSCrypt server config
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil)
	require.NoError(t, err)

	h := dnsCryptHandlerFunc(func(w dnscrypt.ResponseWriter, r *dns.Msg) (err error) {
		return nil
	})

	srvStamp := startTestDNSCryptServer(t, rc, h)

	// Use a shorter timeout to speed up the test.
	u, err := AddressToUpstream(srvStamp.String(), &Options{Timeout: 100 * time.Millisecond})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	req := (&dns.Msg{}).SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)

	res, err := u.Exchange(req)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	assert.Nil(t, res)
}

func TestDNSCrypt_Exchange_dialFail(t *testing.T) {
	// Prepare the test DNSCrypt server config
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil)
	require.NoError(t, err)

	h := dnsCryptHandlerFunc(func(w dnscrypt.ResponseWriter, r *dns.Msg) (err error) {
		return nil
	})

	req := (&dns.Msg{}).SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)
	var u Upstream

	require.True(t, t.Run("run_and_shutdown", func(t *testing.T) {
		srvStamp := startTestDNSCryptServer(t, rc, h)

		// Use a shorter timeout to speed up the test.
		u, err = AddressToUpstream(srvStamp.String(), &Options{Timeout: 100 * time.Millisecond})
		require.NoError(t, err)
	}))

	require.True(t, t.Run("dial_fail", func(t *testing.T) {
		testutil.CleanupAndRequireSuccess(t, u.Close)

		var res *dns.Msg
		res, err = u.Exchange(req)
		require.Error(t, err)

		assert.Nil(t, res)
	}))

	t.Run("restart", func(t *testing.T) {
		const validationErr errors.Error = "bad cert"

		srvStamp := startTestDNSCryptServer(t, rc, h)

		// Use a shorter timeout to speed up the test.
		u, err = AddressToUpstream(srvStamp.String(), &Options{
			Timeout: 100 * time.Millisecond,
			VerifyDNSCryptCertificate: func(cert *dnscrypt.Cert) (err error) {
				return validationErr
			},
		})
		require.NoError(t, err)

		var res *dns.Msg
		res, err = u.Exchange(req)
		require.ErrorIs(t, err, validationErr)

		assert.Nil(t, res)
	})
}
