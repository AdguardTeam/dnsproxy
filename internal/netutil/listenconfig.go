package netutil

import (
	"log/slog"
	"net"
)

// ListenConfig returns the default [net.ListenConfig] used by the plain-DNS
// servers in this module.  l must not be nil.
//
// TODO(a.garipov): Add tests.
//
// TODO(a.garipov): Add an option to not set SO_REUSEPORT on Unix to prevent
// issues with OpenWrt.
//
// See https://github.com/AdguardTeam/AdGuardHome/issues/5872.
//
// TODO(a.garipov): DRY with AdGuard DNS when we can.
func ListenConfig(l *slog.Logger) (lc *net.ListenConfig) {
	return &net.ListenConfig{
		Control: listenControl{logger: l}.defaultListenControl,
	}
}

// listenControl is a wrapper struct with logger.
type listenControl struct {
	logger *slog.Logger
}
