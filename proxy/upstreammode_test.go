package proxy_test

import (
	"testing"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestUpstreamMode_encoding(t *testing.T) {
	t.Parallel()

	v := proxy.UpstreamModeLoadBalance

	testutil.AssertMarshalText(t, "load_balance", &v)
	testutil.AssertUnmarshalText(t, "load_balance", &v)
}
