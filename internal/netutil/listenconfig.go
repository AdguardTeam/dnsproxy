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

// ListenConfigTLS is like [ListenConfig] but also enables TCP Fast Open on the
// listening socket where the OS supports it (Unix).  l must not be nil.
func ListenConfigTLS(l *slog.Logger) (lc *net.ListenConfig) {
	lc = &net.ListenConfig{
		Control: listenControl{logger: l}.tlsListenControl,
	}
	// Go 1.24+ may use Multipath TCP for listener sockets by default.  On several
	// kernels TCP_FASTOPEN on an MPTCP listen socket does not issue SYN-ACK
	// cookies (or setsockopt fails).  DoT uses plain TCP here so TFO works.
	lc.SetMultipathTCP(false)

	return lc
}

// listenControl is a wrapper struct with logger.
type listenControl struct {
	logger *slog.Logger
}
