package netutil

import "net"

// ListenConfig returns the default [net.ListenConfig] used by the plain-DNS
// servers in this module.
//
// TODO(a.garipov): Add tests.
//
// TODO(a.garipov): DRY with AdGuard DNS when we can.
func ListenConfig() (lc *net.ListenConfig) {
	return &net.ListenConfig{
		Control: defaultListenControl,
	}
}
