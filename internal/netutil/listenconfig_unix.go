//go:build unix

package netutil

import (
	"fmt"
	"syscall"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"golang.org/x/sys/unix"
)

// tcpFastOpenQueueLen is the maximum number of pending TFO requests allowed on
// the listen socket (Linux, and similar semantics on other Unix systems).
const tcpFastOpenQueueLen = 256

// applyCommonListenSocketOpts sets SO_REUSEADDR and SO_REUSEPORT on fd.
func (lc listenControl) applyCommonListenSocketOpts(fd uintptr) (opErr error) {
	opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if opErr != nil {
		return fmt.Errorf("setting SO_REUSEADDR: %w", opErr)
	}

	opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if opErr != nil {
		if errors.Is(opErr, unix.ENOPROTOOPT) {
			// Some Linux OSs do not seem to support SO_REUSEPORT, including
			// some varieties of OpenWrt.  Issue a warning.
			lc.logger.Warn("SO_REUSEPORT not supported", slogutil.KeyError, opErr)

			return nil
		}

		return fmt.Errorf("setting SO_REUSEPORT: %w", opErr)
	}

	return nil
}

// defaultListenControl is used as a [net.ListenConfig.Control] function to set
// the SO_REUSEADDR and SO_REUSEPORT socket options on all sockets used by the
// DNS servers in this module.
func (lc listenControl) defaultListenControl(_, _ string, c syscall.RawConn) (err error) {
	var opErr error
	err = c.Control(func(fd uintptr) {
		opErr = lc.applyCommonListenSocketOpts(fd)
	})

	return errors.WithDeferred(opErr, err)
}

// tlsListenControl is like [listenControl.defaultListenControl] but also tries
// to enable TCP Fast Open on the listening socket for DoT.
func (lc listenControl) tlsListenControl(_, _ string, c syscall.RawConn) (err error) {
	var opErr error
	err = c.Control(func(fd uintptr) {
		opErr = lc.applyCommonListenSocketOpts(fd)
		if opErr != nil {
			return
		}

		opErr = unix.SetsockoptInt(
			int(fd),
			unix.IPPROTO_TCP,
			unix.TCP_FASTOPEN,
			tcpFastOpenQueueLen,
		)
		if opErr != nil {
			switch {
			case errors.Is(opErr, unix.ENOPROTOOPT),
				errors.Is(opErr, unix.EINVAL),
				errors.Is(opErr, unix.EOPNOTSUPP):
				lc.logger.Debug("TCP_FASTOPEN not supported", slogutil.KeyError, opErr)
				opErr = nil
			default:
				opErr = fmt.Errorf("setting TCP_FASTOPEN: %w", opErr)
			}
		}
	})

	return errors.WithDeferred(opErr, err)
}
