package proxy

import (
	"bytes"
	"sync"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/stretchr/testify/assert"
)

func TestOptimisticResolver_ResolveOnce(t *testing.T) {
	in, out := make(chan unit), make(chan unit)
	var timesResolved int
	testResolveFunc := func(_ *DNSContext) (ok bool, err error) {
		timesResolved++

		return true, nil
	}

	var timesSet int
	testSetFunc := func(_ *DNSContext) {
		timesSet++

		// Pass the signal to begin running secondary goroutines.
		out <- unit{}
		// Block until all the secondary goroutines finish.
		<-in
	}

	s := newOptimisticResolver(testResolveFunc, testSetFunc, nil)
	sameKey := []byte{1, 2, 3}

	// Start the primary goroutine.
	go s.ResolveOnce(nil, sameKey)
	// Block until the primary goroutine reaches the resolve function.
	<-out

	wg := &sync.WaitGroup{}

	const secondaryNum = 10
	wg.Add(secondaryNum)
	for i := 0; i < secondaryNum; i++ {
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

	noopSetFunc := func(_ *DNSContext) {}

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
		testResolveFunc := func(_ *DNSContext) (ok bool, err error) {
			return true, rerr
		}

		s := newOptimisticResolver(testResolveFunc, noopSetFunc, nil)
		s.ResolveOnce(nil, key)

		assert.Contains(t, logOutput.String(), rerr.Error())
	})

	t.Run("not_ok", func(t *testing.T) {
		testResolveFunc := func(_ *DNSContext) (ok bool, err error) {
			return false, nil
		}

		var deleteCalled bool
		testDeleteFunc := func(_ []byte) {
			deleteCalled = true
		}

		s := newOptimisticResolver(testResolveFunc, noopSetFunc, testDeleteFunc)
		s.ResolveOnce(nil, key)

		assert.True(t, deleteCalled)
	})
}
