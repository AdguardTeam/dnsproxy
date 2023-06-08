//go:build unix

package netutil

import (
	"fmt"
	"syscall"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"golang.org/x/sys/unix"
)

// defaultListenControl is used as a [net.ListenConfig.Control] function to set
// the SO_REUSEADDR and SO_REUSEPORT socket options on all sockets used by the
// DNS servers in this module.
func defaultListenControl(_, _ string, c syscall.RawConn) (err error) {
	var opErr error
	err = c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if opErr != nil {
			opErr = fmt.Errorf("setting SO_REUSEADDR: %w", opErr)

			return
		}

		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		if opErr != nil {
			if errors.Is(opErr, unix.ENOPROTOOPT) {
				// Some Linux OSs do not seem to support SO_REUSEPORT, including
				// some varieties of OpenWrt.  Issue a warning.
				log.Info("warning: SO_REUSEPORT not supported: %s", opErr)
				opErr = nil
			} else {
				opErr = fmt.Errorf("setting SO_REUSEPORT: %w", opErr)
			}
		}
	})

	return errors.WithDeferred(opErr, err)
}
