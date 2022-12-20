package testutil

import (
	"time"

	"github.com/stretchr/testify/require"
)

// RequireSend waits until v is sent to ch or until the timeout is exceeded.  If
// the timeout is exceeded, the test is failed.
func RequireSend[T any](t require.TestingT, ch chan<- T, v T, timeout time.Duration) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case ch <- v:
		// Go on.
	case <-timer.C:
		t.Errorf("did not send after %s", timeout)
		t.FailNow()
	}
}

// RequireReceive waits until res is received from ch or until the timeout is
// exceeded.  If the timeout is exceeded, the test is failed.
func RequireReceive[T any](t require.TestingT, ch <-chan T, timeout time.Duration) (res T, ok bool) {
	if h, isHelper := t.(interface{ Helper() }); isHelper {
		h.Helper()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res, ok = <-ch:
		return res, ok
	case <-timer.C:
		t.Errorf("did not receive after %s", timeout)
		t.FailNow()

	}

	// Generally unreachable.
	return res, ok
}
