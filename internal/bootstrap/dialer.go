package bootstrap

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// TODO(e.burkov):  !! Add tests

// Dialer is used to perform network connections to the IP addresses.  Note that
// the [net.Dialer] from standard library also implements this interface.
type Dialer interface {
	// DialContext connects to the address on the named network using the
	// provided context.  network should be one of [NetworkTCP] or [NetworkUDP].
	DialContext(ctx context.Context, network Network, addr string) (conn net.Conn, err error)
}

// type check
var _ Dialer = (*net.Dialer)(nil)

// NewDialer returns a Dialer that uses timeout for establishing connections.
func NewDialer(timeout time.Duration) (d Dialer) {
	return &net.Dialer{
		Timeout: timeout,
	}
}

// PortDialer is a [Dialer] that adds a port to the address before dialing.
type PortDialer struct {
	// Dialer is used to dial the address.
	Dialer

	// Port is added to the address before dialing.
	Port uint16
}

// type check
var _ Dialer = (*PortDialer)(nil)

// DialContext implements the [Dialer] interface for *PortDialer.  addr must not
// contain a port.
func (d *PortDialer) DialContext(
	ctx context.Context,
	network Network,
	addr string,
) (conn net.Conn, err error) {
	return d.Dialer.DialContext(ctx, network, netutil.JoinHostPort(addr, d.Port))
}

// DialFirst returns a connection to the first address that is successfully
// dialed using d.  If all addresses fail, the returned error will contain the
// errors from all dial attempts.  network should be one of [NetworkTCP] or
// [NetworkUDP].
func DialFirst(
	ctx context.Context,
	d Dialer,
	network Network,
	addrs ...netip.Addr,
) (conn net.Conn, err error) {
	l := len(addrs)
	if l == 0 {
		// TODO(e.burkov):  Export constant?
		return nil, errors.Error("no addresses")
	}

	var errs []error
	for i, addr := range addrs {
		log.Debug("bootstrap: dialing %s (%d/%d)", addr, i+1, l)

		start := time.Now()
		conn, err = d.DialContext(ctx, network, addr.String())
		elapsed := time.Since(start)
		if err == nil {
			log.Debug("bootstrap: connection to %s succeeded in %s", addr, elapsed)

			return conn, nil
		}

		log.Debug("bootstrap: connection to %s failed in %s: %s", addr, elapsed, err)
		errs = append(errs, err)
	}

	// TODO(e.burkov):  Use errors.Join in Go 1.20.
	return nil, fmt.Errorf("all dialers failed: %w", errors.Join(errs...))
}
