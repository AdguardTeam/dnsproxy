//go:build windows

package netutil

import "syscall"

// defaultListenControl is nil on Windows, because it doesn't support
// SO_REUSEPORT.
func (listenControl) defaultListenControl(_, _ string, _ syscall.RawConn) (err error) {
	return nil
}

// tlsListenControl matches [listenControl.defaultListenControl] on Windows;
// TCP Fast Open is not applied here.
func (listenControl) tlsListenControl(_, _ string, _ syscall.RawConn) (err error) {
	return nil
}
