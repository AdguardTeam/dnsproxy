package proxy_test

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/fcchbjm/dnsproxy/proxy"
)

func TestUpstreamMode_encoding(t *testing.T) {
	t.Parallel()

	v := proxy.UpstreamModeLoadBalance

	testutil.AssertMarshalText(t, "load_balance", &v)
	testutil.AssertUnmarshalText(t, "load_balance", &v)
}
