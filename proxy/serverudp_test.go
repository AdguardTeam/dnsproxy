package proxy_test

import (
	"testing"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestProxy_HandleDNSRequest_udp(t *testing.T) {
	p := newTestProxy(t, nil)
	servicetest.RequireRun(t, p, testTimeout)

	addr := p.Addr(proxy.ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, conn.Close)

	subtestSendTestMessages(t, conn)
}
