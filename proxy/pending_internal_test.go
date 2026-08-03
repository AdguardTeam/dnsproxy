package proxy

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPendingRequests_ResponseAD(t *testing.T) {
	ctx := testutil.ContextWithTimeout(t, defaultTimeout)
	pr := newDefaultPendingRequests()
	first := &DNSContext{
		Req:        newHostTestMessage("example.com"),
		responseAD: true,
	}

	loaded, err := pr.queue(ctx, first)
	require.NoError(t, err)
	assert.False(t, loaded)

	key := string(msgToKey(first.Req))
	pending, ok := pr.storage.Load(key)
	require.True(t, ok)

	pr.done(ctx, first, nil)
	require.NotNil(t, pending.cloneDNSCtx)
	assert.True(t, pending.cloneDNSCtx.responseAD)

	pr.storage.Store(key, pending)
	second := &DNSContext{Req: first.Req.Copy()}
	loaded, err = pr.queue(ctx, second)
	require.NoError(t, err)
	assert.True(t, loaded)
	assert.True(t, second.ResponseAD())
}
