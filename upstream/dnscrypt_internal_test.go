package upstream

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dnsCryptHandlerFunc is a function-based implementation of the
// [dnscrypt.Handler] interface.
//
// TODO(d.kolyshev):  Move to dnscrypt.
type dnsCryptHandlerFunc func(
	ctx context.Context,
	w dnscrypt.ResponseWriter,
	r *dns.Msg,
) (err error)

// type check
var _ dnscrypt.Handler = dnsCryptHandlerFunc(nil)

// ServeDNS implements the [dnscrypt.Handler] interface for dnsCryptHandlerFunc.
func (f dnsCryptHandlerFunc) ServeDNS(
	ctx context.Context,
	w dnscrypt.ResponseWriter,
	r *dns.Msg,
) (err error) {
	return f(ctx, w, r)
}

// emptyDNSCryptHandler is a [dnscrypt.Handler] that does nothing and always
// returns nil error.  It can be used in tests when the server's response is
// not important.
//
// TODO(d.kolyshev):  Move to dnscrypt.
var emptyDNSCryptHandler = dnsCryptHandlerFunc(func(
	ctx context.Context,
	w dnscrypt.ResponseWriter,
	r *dns.Msg,
) (err error) {
	return nil
})

// startTestDNSCryptServer starts a test DNSCrypt server with the specified
// resolver config and handler.  rc and h must not be nil.
func startTestDNSCryptServer(
	tb testing.TB,
	rc dnscrypt.ResolverConfig,
	h dnscrypt.Handler,
) (stamp dnsstamps.ServerStamp) {
	tb.Helper()

	cert, err := rc.NewCert()
	require.NoError(tb, err)

	addr := netip.AddrPortFrom(netutil.IPv4Localhost(), 0)
	srvUDP, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
		Handler:      h,
		ResolverCert: cert,
		Logger:       testLogger,
		ProviderName: rc.ProviderName,
		Addr:         addr,
		Proto:        dnscrypt.ProtoUDP,
	})
	require.NoError(tb, err)

	servicetest.RequireRun(tb, srvUDP, testTimeout)

	addrStr := srvUDP.LocalAddr().String()
	stamp, err = rc.CreateStamp(addrStr)
	require.NoError(tb, err)

	srvTCP, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
		Handler:      h,
		ResolverCert: cert,
		Logger:       testLogger,
		ProviderName: rc.ProviderName,
		Addr:         netutil.NetAddrToAddrPort(srvUDP.LocalAddr()),
		Proto:        dnscrypt.ProtoTCP,
	})
	require.NoError(tb, err)
	servicetest.RequireRun(tb, srvTCP, testTimeout)

	return stamp
}

func TestUpstreamDNSCrypt(t *testing.T) {
	t.Parallel()

	// AdGuard DNS (DNSCrypt)
	address := "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	u, err := AddressToUpstream(address, &Options{
		Logger:  testLogger,
		Timeout: dialTimeout,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// Test that it responds properly
	for range 10 {
		checkUpstream(t, u, address)
	}
}

func TestDNSCrypt_Exchange_truncated(t *testing.T) {
	// Prepare the test DNSCrypt server config.
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)

	var udpNum, tcpNum atomic.Uint32
	h := dnsCryptHandlerFunc(func(
		ctx context.Context,
		w dnscrypt.ResponseWriter,
		r *dns.Msg,
	) (err error) {
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
		for range 50 {
			answer.Txt = append(answer.Txt, veryLongString)
		}

		return w.WriteMsg(ctx, res)
	})

	srvStamp := startTestDNSCryptServer(t, rc, h)
	u, err := AddressToUpstream(srvStamp.String(), &Options{
		Logger:  testLogger,
		Timeout: testTimeout,
	})
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
	t.Parallel()

	// Prepare the test DNSCrypt server config
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)

	srvStamp := startTestDNSCryptServer(t, rc, emptyDNSCryptHandler)

	// Use a shorter timeout to speed up the test.
	u, err := AddressToUpstream(srvStamp.String(), &Options{
		Logger: testLogger,
		// TODO(f.setrakov): Use stale context when [Upstream.Exchange] will
		// accept a context.
		Timeout: 1 * time.Nanosecond,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	req := (&dns.Msg{}).SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)

	res, err := u.Exchange(req)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	assert.Nil(t, res)
}

func TestDNSCrypt_Exchange_dialFail(t *testing.T) {
	// Prepare the test DNSCrypt server config.
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)

	req := (&dns.Msg{}).SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)
	var u Upstream

	require.True(t, t.Run("run_and_shutdown", func(t *testing.T) {
		srvStamp := startTestDNSCryptServer(t, rc, emptyDNSCryptHandler)

		// Use a shorter timeout to speed up the test.
		u, err = AddressToUpstream(srvStamp.String(), &Options{
			Logger:  testLogger,
			Timeout: 100 * time.Millisecond,
		})
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

		srvStamp := startTestDNSCryptServer(t, rc, emptyDNSCryptHandler)

		// Use a shorter timeout to speed up the test.
		u, err = AddressToUpstream(srvStamp.String(), &Options{
			Logger:  testLogger,
			Timeout: 100 * time.Millisecond,
			VerifyDNSCryptCertificate: func(cert *dnscrypt.Certificate) (err error) {
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
