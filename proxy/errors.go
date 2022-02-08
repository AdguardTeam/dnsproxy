//go:build !plan9
// +build !plan9

package proxy

import (
	"syscall"

	"github.com/AdguardTeam/golibs/errors"
)

// isEPIPE checks if the underlying error is EPIPE.  syscall.EPIPE exists on all
// OSes except for Plan 9.  Validate with:
//
//   $ for os in $(go tool dist list | cut -d / -f 1 | sort -u)
//   do
//           echo -n "$os"
//           env GOOS="$os" go doc syscall.EPIPE | grep -F -e EPIPE
//   done
//
// For the Plan 9 version see ./errors_plan9.go.
func isEPIPE(err error) (ok bool) {
	return errors.Is(err, syscall.EPIPE)
}
