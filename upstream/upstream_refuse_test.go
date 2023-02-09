package upstream

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestUpstream_refuseDNS(t *testing.T) {
	u, err := AddressToUpstream("!", &Options{})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	req := createTestMessage()
	reply, err := u.Exchange(req)
	require.NoError(t, err)

	require.NotNil(t, reply)
	require.Equal(t, reply.Id, req.Id)
	require.Equal(t, reply.Rcode, dns.RcodeRefused)
}
