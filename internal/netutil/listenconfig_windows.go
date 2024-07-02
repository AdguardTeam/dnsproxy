//go:build windows

package netutil

import "syscall"

// defaultListenControl is nil on Windows, because it doesn't support
// SO_REUSEPORT.
func (listenControl) defaultListenControl(_, _ string, _ syscall.RawConn) (err error) {
	return nil
}
