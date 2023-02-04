//go:build darwin || freebsd || linux || openbsd || netbsd

package upstream

import (
	"github.com/AdguardTeam/golibs/errors"
	"golang.org/x/sys/unix"
)

// isConnBroken returns true if err means that a connection is broken.
func isConnBroken(err error) (ok bool) {
	return errors.Is(err, unix.EPIPE) || errors.Is(err, unix.ETIMEDOUT)
}
