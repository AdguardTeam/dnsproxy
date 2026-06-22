// Package dnsproxytest provides a set of test utilities for the dnsproxy
// module.
package dnsproxytest

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// NewFreePort is a best-effort helper function that returns a free TCP port
// that can be used for testing.  Note that there is theoretically a TOCTTOU
// race here: the port may be reoccupied between the time it is released and the
// time the caller binds to it.
func NewFreePort(tb testing.TB) (p uint) {
	tb.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(tb, err)

	p = uint(l.Addr().(*net.TCPAddr).Port)

	// Stop listening immediately.
	require.NoError(tb, l.Close())

	// Sleeping for some time may be necessary on Windows.
	if runtime.GOOS == "windows" {
		time.Sleep(100 * time.Millisecond)
	}

	return p
}
