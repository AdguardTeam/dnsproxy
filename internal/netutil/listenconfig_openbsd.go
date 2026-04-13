//go:build openbsd

package netutil

import (
	"fmt"
	"syscall"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"golang.org/x/sys/unix"
)

// applyCommonListenSocketOpts sets SO_REUSEADDR and SO_REUSEPORT on fd.
func (lc listenControl) applyCommonListenSocketOpts(fd uintptr) (opErr error) {
	opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if opErr != nil {
		return fmt.Errorf("setting SO_REUSEADDR: %w", opErr)
	}

	opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if opErr != nil {
		if errors.Is(opErr, unix.ENOPROTOOPT) {
			// Not all kernels support SO_REUSEPORT (e.g. some OpenWrt builds).
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

// tlsListenControl matches [listenControl.defaultListenControl] on OpenBSD.
// golang.org/x/sys/unix does not define TCP_FASTOPEN for this platform, so TFO
// is not applied here.
func (lc listenControl) tlsListenControl(network, addr string, c syscall.RawConn) (err error) {
	return lc.defaultListenControl(network, addr, c)
}
