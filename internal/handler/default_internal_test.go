package handler

import (
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// TODO(e.burkov):  Add helpers to initialize [proxy.Proxy] to [dnsproxytest]
// and rewrite the tests.

// defaultTimeout is a default timeout for tests and contexts.
const defaultTimeout = 1 * time.Second

func TestDefault_haltAAAA(t *testing.T) {
	t.Parallel()

	reqA := (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeA)
	reqAAAA := (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeAAAA)

	nodataResp := (&dns.Msg{}).SetReply(reqA)

	messages := dnsproxytest.NewTestMessageConstructor()
	messages.OnNewMsgNODATA = func(_ *dns.Msg) (resp *dns.Msg) {
		return nodataResp
	}

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()

		hdlr := NewDefault(&DefaultConfig{
			Logger:             slogutil.NewDiscardLogger(),
			MessageConstructor: messages,
			HaltIPv6:           false,
		})

		ctx := testutil.ContextWithTimeout(t, defaultTimeout)

		assert.Nil(t, hdlr.haltAAAA(ctx, reqA))
		assert.Nil(t, hdlr.haltAAAA(ctx, reqAAAA))
	})

	t.Run("enabled", func(t *testing.T) {
		t.Parallel()

		hdlr := NewDefault(&DefaultConfig{
			Logger:             slogutil.NewDiscardLogger(),
			MessageConstructor: messages,
			HaltIPv6:           true,
		})

		ctx := testutil.ContextWithTimeout(t, defaultTimeout)

		assert.Nil(t, hdlr.haltAAAA(ctx, reqA))
		assert.Equal(t, nodataResp, hdlr.haltAAAA(ctx, reqAAAA))
	})
}
