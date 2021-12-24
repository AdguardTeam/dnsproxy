//go:build plan9
// +build plan9

package proxy

import "strings"

// isEPIPE checks if the underlying error is EPIPE.  Plan 9 relies on error
// strings instead of error codes.  I couldn't find the exact constant with the
// text returned by a write on a closed socket, but it seems to be "sys: write
// on closed pipe".  See Plan 9's "man 2 notify".
//
// We don't currently support Plan 9, so it's not critical, but when we do, this
// needs to be rechecked.
func isEPIPE(err error) (ok bool) {
	return strings.Contains(err.Error(), "write on closed pipe")
}
