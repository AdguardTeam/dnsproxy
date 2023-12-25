package bootstrap

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// Dialer is used to perform network connections to the IP addresses.  Note that
// the [net.Dialer] from standard library also implements this interface.
type Dialer interface {
	// DialContext connects to the address on the named network using the
	// provided context.  network should be one of [NetworkTCP] or [NetworkUDP].
	DialContext(ctx context.Context, network Network, addr string) (conn net.Conn, err error)
}

// type check
var _ Dialer = (*net.Dialer)(nil)

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

// ResolvingDialer is a [Dialer] that resolves the hostname before dialing.  The
// addresses are resolved using the [NetworkIP].
type ResolvingDialer struct {
	Resolver
	Dialer
}

// type check
var _ Dialer = (*ResolvingDialer)(nil)

// DialContext implements the [Dialer] interface for *ResolvingDialer.
func (dr *ResolvingDialer) DialContext(
	ctx context.Context,
	network Network,
	addr string,
) (conn net.Conn, err error) {
	addrs, err := dr.LookupNetIP(ctx, NetworkIP, addr)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", addr, err)
	}

	l := len(addrs)
	if l == 0 {
		return nil, fmt.Errorf("no addresses resolved for %q", addr)
	}

	var errs []error

	// Return first succeeded connection.  Note that we're using addrs
	// instead of what's passed to the function.
	for i, addr := range addrs {
		log.Debug("bootstrap: dialing %s (%d/%d)", addr, i+1, l)

		start := time.Now()
		conn, err = dr.Dialer.DialContext(ctx, network, addr.String())
		elapsed := time.Since(start)
		if err == nil {
			log.Debug("bootstrap: connection to %s succeeded in %s", addr, elapsed)

			return conn, nil
		}

		log.Debug("bootstrap: connection to %s failed in %s: %s", addr, elapsed, err)
		errs = append(errs, err)
	}

	return nil, fmt.Errorf("all dials failed: %w", errors.Join(errs...))
}

// StaticDialer always dials the same addresses.
type StaticDialer struct {
	Dialer    Dialer
	Addresses []string
}

// type check
var _ Dialer = (*StaticDialer)(nil)

// DialContext implements the [Dialer] interface for *StaticDialer.
func (d *StaticDialer) DialContext(
	ctx context.Context,
	network Network,
	_ string,
) (conn net.Conn, err error) {
	l := len(d.Addresses)
	if l == 0 {
		return nil, fmt.Errorf("no addresses provided")
	}

	var errs []error

	// Return first succeeded connection.  Note that we're using d
	// instead of what's passed to the function.
	for i, addr := range d.Addresses {
		log.Debug("bootstrap: dialing %s (%d/%d)", addr, i+1, l)

		start := time.Now()
		conn, err = net.DialTimeout(network, addr, 5*time.Second)
		elapsed := time.Since(start)
		if err == nil {
			log.Debug("bootstrap: connection to %s succeeded in %s", addr, elapsed)

			return conn, nil
		}

		log.Debug("bootstrap: connection to %s failed in %s: %s", addr, elapsed, err)
		errs = append(errs, err)
	}

	return nil, fmt.Errorf("all dials failed: %w", errors.Join(errs...))
}
