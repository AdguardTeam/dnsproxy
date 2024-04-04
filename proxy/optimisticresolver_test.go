package proxy

import (
	"bytes"
	"sync"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/stretchr/testify/assert"
)

// testCachingResolver is a stub implementation of the cachingResolver interface
// to simplify testing.
type testCachingResolver struct {
	onReplyFromUpstream func(dctx *DNSContext) (ok bool, err error)
	onCacheResp         func(dctx *DNSContext)
}

// replyFromUpstream implements the cachingResolver interface for
// *testCachingResolver.
func (tcr *testCachingResolver) replyFromUpstream(dctx *DNSContext) (ok bool, err error) {
	return tcr.onReplyFromUpstream(dctx)
}

// cacheResp implements the cachingResolver interface for *testCachingResolver.
func (tcr *testCachingResolver) cacheResp(dctx *DNSContext) {
	tcr.onCacheResp(dctx)
}

func TestOptimisticResolver_ResolveOnce(t *testing.T) {
	in, out := make(chan unit), make(chan unit)
	var timesResolved, timesSet int

	tcr := &testCachingResolver{
		onReplyFromUpstream: func(_ *DNSContext) (ok bool, err error) {
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
	go s.ResolveOnce(nil, sameKey)
	// Block until the primary goroutine reaches the resolve function.
	<-out

	wg := &sync.WaitGroup{}

	const secondaryNum = 10
	wg.Add(secondaryNum)
	for range secondaryNum {
		go func() {
			defer wg.Done()

			s.ResolveOnce(nil, sameKey)
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
		logOutput := &bytes.Buffer{}

		prevLevel := log.GetLevel()
		prevOutput := log.Writer()
		log.SetLevel(log.DEBUG)
		log.SetOutput(logOutput)
		t.Cleanup(func() {
			log.SetLevel(prevLevel)
			log.SetOutput(prevOutput)
		})

		const rerr errors.Error = "sample resolving error"
		s := newOptimisticResolver(&testCachingResolver{
			onReplyFromUpstream: func(_ *DNSContext) (ok bool, err error) { return true, rerr },
			onCacheResp:         func(_ *DNSContext) {},
		})
		s.ResolveOnce(nil, key)

		assert.Contains(t, logOutput.String(), rerr.Error())
	})

	t.Run("not_ok", func(t *testing.T) {
		cached := false
		s := newOptimisticResolver(&testCachingResolver{
			onReplyFromUpstream: func(_ *DNSContext) (ok bool, err error) { return false, nil },
			onCacheResp:         func(_ *DNSContext) { cached = true },
		})
		s.ResolveOnce(nil, key)

		assert.False(t, cached)
	})
}
