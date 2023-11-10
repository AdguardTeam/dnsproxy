// Package bootstrap provides types and functions to resolve upstream hostnames
// and to dial retrieved addresses.
package bootstrap

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// DialHandler is a dial function for creating unencrypted network connections
// to the upstream server.  It establishes the connection to the server
// specified at initialization and ignores the addr.
type DialHandler func(ctx context.Context, network, addr string) (conn net.Conn, err error)

// ResolveDialContext returns a DialHandler that uses addresses resolved from u
// using resolver.  u must not be nil.
func ResolveDialContext(
	u *url.URL,
	timeout time.Duration,
	resolver Resolver,
	preferIPv6 bool,
) (h DialHandler, err error) {
	defer func() { err = errors.Annotate(err, "dialing %q: %w", u.Host) }()

	host, port, err := netutil.SplitHostPort(u.Host)
	if err != nil {
		// Don't wrap the error since it's informative enough as is and there is
		// already deferred annotation here.
		return nil, err
	}

	if resolver == nil {
		return nil, fmt.Errorf("resolver is nil: %w", ErrNoResolvers)
	}

	ctx := context.Background()
	if timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	ips, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolving hostname: %w", err)
	}

	proxynetutil.SortNetIPAddrs(ips, preferIPv6)

	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !ip.IsValid() {
			// All invalid addresses should be in the tail after sorting.
			break
		}

		addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)).String())
	}

	return NewDialContext(timeout, addrs...), nil
}

// NewDialContext returns a DialHandler that dials addrs and returns the first
// successful connection.  At least a single addr should be specified.
//
// TODO(e.burkov):  Consider using [Resolver] instead of
// [upstream.Options.Bootstrap] and [upstream.Options.ServerIPAddrs].
func NewDialContext(timeout time.Duration, addrs ...string) (h DialHandler) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	l := len(addrs)
	if l == 0 {
		log.Debug("bootstrap: no addresses to dial")

		return func(_ context.Context, _, _ string) (conn net.Conn, err error) {
			return nil, errors.Error("no addresses")
		}
	}

	// TODO(e.burkov):  Check IPv6 preference here.

	return func(ctx context.Context, network, _ string) (conn net.Conn, err error) {
		var errs []error

		// Return first succeeded connection.  Note that we're using addrs
		// instead of what's passed to the function.
		for i, addr := range addrs {
			log.Debug("bootstrap: dialing %s (%d/%d)", addr, i+1, l)

			start := time.Now()
			conn, err = dialer.DialContext(ctx, network, addr)
			elapsed := time.Since(start)
			if err == nil {
				log.Debug("bootstrap: connection to %s succeeded in %s", addr, elapsed)

				return conn, nil
			}

			log.Debug("bootstrap: connection to %s failed in %s: %s", addr, elapsed, err)
			errs = append(errs, err)
		}

		// TODO(e.burkov):  Use errors.Join in Go 1.20.
		return nil, errors.List("all dialers failed", errs...)
	}
}
