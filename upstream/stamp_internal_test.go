package upstream

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStampCertHashMatches_tbs(t *testing.T) {
	t.Parallel()

	tlsConf, _ := createServerTLSConfig(t, "127.0.0.1")
	der := tlsConf.Certificates[0].Certificate[0]
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	tbs := sha256.Sum256(cert.RawTBSCertificate)
	full := sha256.Sum256(cert.Raw)

	assert.True(t, stampCertHashMatches([][]byte{der}, nil, [][]byte{tbs[:]}))
	assert.False(t, stampCertHashMatches([][]byte{der}, nil, [][]byte{full[:]}))
	assert.False(t, stampCertHashMatches([][]byte{der}, nil, [][]byte{make([]byte, sha256.Size)}))
}

func TestAddressToUpstream_stampCertPin(t *testing.T) {
	t.Parallel()

	srv := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(req)))
	})

	leaf, err := x509.ParseCertificate(srv.tlsConfig.Certificates[0].Certificate[0])
	require.NoError(t, err)

	sum := sha256.Sum256(leaf.RawTBSCertificate)
	bad := sum
	bad[0] ^= 0xff

	addr := netutil.JoinHostPort("127.0.0.1", uint16(srv.port))
	opts := &Options{
		Logger:             testLogger,
		Timeout:            testTimeout,
		InsecureSkipVerify: true,
	}

	goodStamp := (&dnsstamps.ServerStamp{
		ServerAddrStr: addr,
		Proto:         dnsstamps.StampProtoTypeTLS,
		ProviderName:  addr,
		Hashes:        [][]byte{sum[:]},
	}).String()
	u, err := AddressToUpstream(goodStamp, opts)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	checkUpstream(t, u, goodStamp, testTimeout)

	badStamp := (&dnsstamps.ServerStamp{
		ServerAddrStr: addr,
		Proto:         dnsstamps.StampProtoTypeTLS,
		ProviderName:  addr,
		Hashes:        [][]byte{bad[:]},
	}).String()
	pinned, err := AddressToUpstream(badStamp, opts)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, pinned.Close)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	_, err = pinned.Exchange(ctx, createTestMessage())
	require.Error(t, err)
	assert.ErrorContains(t, err, "stamp certificate hash mismatch")
}
