package proxy

import (
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestWithRetry(t *testing.T) {
	t.Parallel()

	const (
		errA errors.Error = "error about a"
		errB errors.Error = "error about b"
	)

	var (
		good = func() (err error) {
			return nil
		}

		badOne = func() (err error) {
			return errA
		}

		// Don't protect against concurrent access since the closure is expected
		// to be used in a single case.
		returnedA = false
		badBoth   = func() (err error) {
			if !returnedA {
				returnedA = true

				return errA
			}

			return errB
		}

		// Don't protect against concurrent access since the closure is expected
		// to be used in a single case.
		returnedErr = false
		badThenOk   = func() (err error) {
			if !returnedErr {
				returnedErr = true

				return assert.AnError
			}

			return nil
		}
	)

	testCases := []struct {
		f       func() (err error)
		wantErr error
		name    string
	}{{
		f:       good,
		wantErr: nil,
		name:    "no_error",
	}, {
		f:       badOne,
		wantErr: errA,
		name:    "one_error",
	}, {
		f:       badBoth,
		wantErr: errA,
		name:    "two_errors",
	}, {
		f:       badThenOk,
		wantErr: nil,
		name:    "error_then_ok",
	}}

	p := &Proxy{
		logger:       slogutil.NewDiscardLogger(),
		bindRetryNum: 1,
		bindRetryIvl: 0,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, testTimeout)

			err := p.bindWithRetry(ctx, tc.f)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}
