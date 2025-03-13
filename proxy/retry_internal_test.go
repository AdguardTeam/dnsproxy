package proxy

import (
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestWithRetry(t *testing.T) {
	t.Parallel()

	const goodRes = "good"

	const (
		errA errors.Error = "error about a"
		errB errors.Error = "error about b"
	)

	var (
		good = func() (res any, err error) {
			return goodRes, nil
		}

		badOne = func() (res any, err error) {
			return nil, errA
		}

		returnedA = false
		badBoth   = func() (res any, err error) {
			if !returnedA {
				returnedA = true
				return nil, errA
			}

			return nil, errB
		}
	)

	testCases := []struct {
		name       string
		f          func() (res any, err error)
		want       any
		wantErrMsg string
	}{{
		name:       "no_error",
		f:          good,
		want:       goodRes,
		wantErrMsg: "",
	}, {
		name: "one_error",
		f:    badOne,
		want: nil,
		wantErrMsg: "attempt 1: error about a\n" +
			"attempt 2: error about a",
	}, {
		name: "two_errors",
		f:    badBoth,
		want: nil,
		wantErrMsg: "attempt 1: error about a\n" +
			"attempt 2: error about b",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := withRetry(tc.f, 0, 1)
			assert.Equal(t, tc.want, got)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
