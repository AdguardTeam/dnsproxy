package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// Resolver resolves the hostnames to IP addresses.  Note, that [net.Resolver]
// from standard library also implements this interface.
type Resolver interface {
	// LookupNetIP looks up the IP addresses for the given host.  network should
	// be one of [NetworkIP], [NetworkIP4] or [NetworkIP6].  The response may be
	// empty even if err is nil.  All the addrs must be valid.
	LookupNetIP(ctx context.Context, network Network, host string) (addrs []netip.Addr, err error)
}

// type check
var _ Resolver = &net.Resolver{}

// ParallelResolver is a slice of resolvers that are queried concurrently.  The
// first successful response is returned.
type ParallelResolver []Resolver

// type check
var _ Resolver = ParallelResolver(nil)

// LookupNetIP implements the [Resolver] interface for ParallelResolver.
func (r ParallelResolver) LookupNetIP(
	ctx context.Context,
	network Network,
	host string,
) (addrs []netip.Addr, err error) {
	resolversNum := len(r)
	switch resolversNum {
	case 0:
		return nil, ErrNoResolvers
	case 1:
		return r[0].LookupNetIP(ctx, network, host)
	default:
		// Go on.
	}

	// Size of channel must accommodate results of lookups from all resolvers,
	// sending into channel will block otherwise.
	ch := make(chan any, resolversNum)
	for _, rslv := range r {
		go lookupAsync(ctx, rslv, network, host, ch)
	}

	var errs []error
	for range r {
		switch result := <-ch; result := result.(type) {
		case error:
			errs = append(errs, result)
		case []netip.Addr:
			return result, nil
		}
	}

	return nil, errors.Join(errs...)
}

// recoverAndLog is a deferred helper that recovers from a panic and logs the
// panic value with the logger from context or with a default logger.  Sends the
// recovered value into resCh.
//
// TODO(a.garipov): Move this helper to golibs.
func recoverAndLog(ctx context.Context, resCh chan<- any) {
	v := recover()
	if v == nil {
		return
	}

	err, ok := v.(error)
	if !ok {
		err = fmt.Errorf("error value: %v", v)
	}

	l, ok := slogutil.LoggerFromContext(ctx)
	if !ok {
		l = slog.Default()
	}

	l.ErrorContext(ctx, "recovered panic", slogutil.KeyError, err)
	slogutil.PrintStack(ctx, l, slog.LevelError)

	resCh <- err
}

// lookupAsync performs a lookup for ip of host with r and sends the result into
// resCh.  It is intended to be used as a goroutine.
func lookupAsync(ctx context.Context, r Resolver, network, host string, resCh chan<- any) {
	// TODO(d.kolyshev): Propose better solution to recover without requiring
	// logger in the context.
	defer recoverAndLog(ctx, resCh)

	addrs, err := r.LookupNetIP(ctx, network, host)
	if err != nil {
		resCh <- err
	} else {
		resCh <- addrs
	}
}

// ConsequentResolver is a slice of resolvers that are queried in order until
// the first successful non-empty response, as opposed to just successful
// response requirement in [ParallelResolver].
type ConsequentResolver []Resolver

// type check
var _ Resolver = ConsequentResolver(nil)

// LookupNetIP implements the [Resolver] interface for ConsequentResolver.
func (resolvers ConsequentResolver) LookupNetIP(
	ctx context.Context,
	network Network,
	host string,
) (addrs []netip.Addr, err error) {
	if len(resolvers) == 0 {
		return nil, ErrNoResolvers
	}

	var errs []error
	for _, r := range resolvers {
		addrs, err = r.LookupNetIP(ctx, network, host)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}

		errs = append(errs, err)
	}

	return nil, errors.Join(errs...)
}

// StaticResolver is a resolver which always responds with an underlying slice
// of IP addresses regardless of host and network.
type StaticResolver []netip.Addr

// type check
var _ Resolver = StaticResolver(nil)

// LookupNetIP implements the [Resolver] interface for StaticResolver.
func (r StaticResolver) LookupNetIP(
	_ context.Context,
	_ Network,
	_ string,
) (addrs []netip.Addr, err error) {
	return slices.Clone(r), nil
}
