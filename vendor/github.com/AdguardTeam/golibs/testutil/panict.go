package testutil

import (
	"fmt"

	"github.com/stretchr/testify/require"
)

// PanicT can be used with the helpers from package require in cases when
// testing.T and similar standard test helpers aren't safe for use, e.g. stub
// HTTP handlers and goroutines.
//
// While this type also implements assert.TestingT, prefer to use require helper
// functions, since this helper panics, which immediately fails the test.
type PanicT struct{}

// type check
var _ require.TestingT = PanicT{}

// Errorf implements the require.TestingT interface for PanicT.  It panics with
// an error with the given format.
func (PanicT) Errorf(format string, args ...any) {
	panic(fmt.Errorf(format, args...))
}

// FailNow implements the require.TestingT interface for PanicT.  It is assumed
// that it will never actually be called, since Errorf panics.
func (PanicT) FailNow() {
	panic("test failed")
}
