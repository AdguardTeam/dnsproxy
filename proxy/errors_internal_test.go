//go:build !plan9
// +build !plan9

package proxy

import (
	"fmt"
	"syscall"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/stretchr/testify/assert"
)

func TestIsEPIPE(t *testing.T) {
	type testCase struct {
		err  error
		name string
		want bool
	}

	testCases := []testCase{{
		name: "nil",
		err:  nil,
		want: false,
	}, {
		name: "epipe",
		err:  syscall.EPIPE,
		want: true,
	}, {
		name: "not_epipe",
		err:  errors.Error("test error"),
		want: false,
	}, {
		name: "wrapped_epipe",
		err:  fmt.Errorf("test error: %w", syscall.EPIPE),
		want: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := isEPIPE(tc.err)
			assert.Equal(t, tc.want, got)
		})
	}
}
