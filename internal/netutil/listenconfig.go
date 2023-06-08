package netutil

import "net"

// ListenConfig returns the default [net.ListenConfig] used by the plain-DNS
// servers in this module.
//
// TODO(a.garipov): Add tests.
//
// TODO(a.garipov): Add an option to not set SO_REUSEPORT on Unix to prevent
// issues with OpenWrt.
//
// See https://github.com/AdguardTeam/AdGuardHome/issues/5872.
//
// TODO(a.garipov): DRY with AdGuard DNS when we can.
func ListenConfig() (lc *net.ListenConfig) {
	return &net.ListenConfig{
		Control: defaultListenControl,
	}
}
