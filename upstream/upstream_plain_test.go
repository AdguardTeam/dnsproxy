package upstream

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TODO(ameshkov): make this test not depend on external resources.
func TestDNSTruncated(t *testing.T) {
	// AdGuard DNS
	address := "94.140.14.14:53"

	u, err := AddressToUpstream(address, &Options{Timeout: timeout})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	req := new(dns.Msg)
	req.SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)
	req.RecursionDesired = true

	res, err := u.Exchange(req)
	require.NoError(t, err)
	require.False(t, res.Truncated)
}
