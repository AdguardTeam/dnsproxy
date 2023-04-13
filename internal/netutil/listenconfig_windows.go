//go:build windows

package netutil

import "syscall"

// defaultListenControl is nil on Windows, because it doesn't support
// SO_REUSEPORT.
var defaultListenControl func(_, _ string, _ syscall.RawConn) (_ error)
