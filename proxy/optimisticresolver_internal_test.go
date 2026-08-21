package proxy

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

// testCachingResolver is a stub implementation of the cachingResolver interface
// to simplify testing.
type testCachingResolver struct {
	onReplyFromUpstream func(ctx context.Context, dctx *DNSContext) (ok bool, err error)
	onCacheResp         func(dctx *DNSContext)
}

// replyFromUpstream implements the cachingResolver interface for
// *testCachingResolver.
func (tcr *testCachingResolver) replyFromUpstream(
	ctx context.Context,
	dctx *DNSContext,
) (ok bool, err error) {
	return tcr.onReplyFromUpstream(ctx, dctx)
}

// cacheResp implements the cachingResolver interface for *testCachingResolver.
func (tcr *testCachingResolver) cacheResp(dctx *DNSContext) {
	tcr.onCacheResp(dctx)
}

func TestOptimisticResolver_ResolveOnce(t *testing.T) {
	in, out := make(chan unit), make(chan unit)
	var timesResolved, timesSet int

	tcr := &testCachingResolver{
		onReplyFromUpstream: func(_ context.Context, _ *DNSContext) (ok bool, err error) {
			timesResolved++

			return true, nil
		},
		onCacheResp: func(_ *DNSContext) {
			timesSet++

			// Pass the signal to begin running secondary goroutines.
			out <- unit{}
			// Block until all the secondary goroutines finish.
			<-in
		},
	}

	s := newOptimisticResolver(tcr)
	sameKey := []byte{1, 2, 3}

	// Start the primary goroutine.
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	go s.resolveOnce(ctx, nil, sameKey, testLogger)
	// Block until the primary goroutine reaches the resolve function.
	<-out

	wg := &sync.WaitGroup{}

	const secondaryNum = 10
	wg.Add(secondaryNum)
	for range secondaryNum {
		go func() {
			defer wg.Done()

			resolveCtx := testutil.ContextWithTimeout(t, testTimeout)
			s.resolveOnce(resolveCtx, nil, sameKey, testLogger)
		}()
	}

	// Wait until all the secondary goroutines are finished.
	wg.Wait()
	// Pass the signal to terminate the primary goroutine.
	in <- unit{}

	assert.Equal(t, 1, timesResolved)
	assert.Equal(t, 1, timesSet)
}

func TestOptimisticResolver_ResolveOnce_unsuccessful(t *testing.T) {
	key := []byte{1, 2, 3}

	t.Run("error", func(t *testing.T) {
		// TODO(d.kolyshev): Consider adding mock handler to golibs.
		logOutput := &bytes.Buffer{}
		l := slog.New(slog.NewTextHandler(logOutput, &slog.HandlerOptions{
			AddSource:   false,
			Level:       slog.LevelDebug,
			ReplaceAttr: nil,
		}))

		const rErr errors.Error = "sample resolving error"

		cached := false
		s := newOptimisticResolver(&testCachingResolver{
			onReplyFromUpstream: func(_ context.Context, _ *DNSContext) (ok bool, err error) {
				return true, rErr
			},
			onCacheResp: func(_ *DNSContext) { cached = true },
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		s.resolveOnce(ctx, nil, key, l)

		assert.True(t, cached)
		assert.Contains(t, logOutput.String(), rErr.Error())
	})

	t.Run("not_ok", func(t *testing.T) {
		cached := false
		s := newOptimisticResolver(&testCachingResolver{
			onReplyFromUpstream: func(_ context.Context, _ *DNSContext) (ok bool, err error) {
				return false, nil
			},
			onCacheResp: func(_ *DNSContext) { cached = true },
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		s.resolveOnce(ctx, nil, key, testLogger)

		assert.False(t, cached)
	})
}
