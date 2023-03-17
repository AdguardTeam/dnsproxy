//go:build go1.20

package errors

import stderrors "errors"

// TODO(a.garipov): Move to errors.go and add examples once golibs switches to
// Go 1.20.

// WrapperSlice is a copy of the hidden wrapper interface added to the Go standard
// library in Go 1.20.  It is added here for tests, linting, etc.
type WrapperSlice interface {
	Unwrap() []error
}

// Join returns an error that wraps the given errors.  Any nil error values are
// discarded.  Join returns nil if errs contains no non-nil values.  The error
// formats as the concatenation of the strings obtained by calling the Error
// method of each element of errs, with a newline between each string.
//
// It calls [errors.Join] from the Go standard library.
func Join(errs ...error) error {
	return stderrors.Join(errs...)
}
