package proxy

import (
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

// Common errors for tests.
const (
	testErrA errors.Error = "foo"
	testErrB errors.Error = "bar"
)

// bindGood is a bind func that succeeds on every call.
func bindGood() (err error) {
	return nil
}

// bindBadOne is a bind func that returns [errA] on every call.
func bindBadOne() (err error) {
	return testErrA
}

// newBindBadBoth returns a bind func that fails with two different errors.
func newBindBadBoth() (f func() (err error)) {
	returnedA := false

	return func() (err error) {
		if !returnedA {
			returnedA = true

			return testErrA
		}

		return testErrB
	}
}

// newBindBadThenOK returns a bind func that fails on the first call and
// succeeds on the second.
func newBindBadThenOK() (f func() (err error)) {
	returnedErr := false

	return func() (err error) {
		if !returnedErr {
			returnedErr = true

			return assert.AnError
		}

		return nil
	}
}

func TestProxy_BindWithRetry(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		f       func() (err error)
		wantErr error
		name    string
	}{{
		f:       bindGood,
		wantErr: nil,
		name:    "no_error",
	}, {
		f:       bindBadOne,
		wantErr: testErrA,
		name:    "one_error",
	}, {
		f:       newBindBadBoth(),
		wantErr: testErrA,
		name:    "two_errors",
	}, {
		f:       newBindBadThenOK(),
		wantErr: nil,
		name:    "error_then_ok",
	}}

	p := &Proxy{
		logger:         testLogger,
		bindRetryCount: 1,
		bindRetryIvl:   0,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, dnsproxytest.Timeout)

			err := p.bindWithRetry(ctx, tc.f)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}
