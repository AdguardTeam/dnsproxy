package bootstrap

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"golang.org/x/exp/slices"
)

// Resolver resolves the hostnames to IP addresses.  Note, that the
// [net.Resolver] from standard library also implements this interface.
type Resolver interface {
	// LookupNetIP looks up the IP addresses for the given host.  network should
	// be one of [NetworkIP], [NetworkIP4] or [NetworkIP6].  The response may be
	// empty even if err is nil.
	LookupNetIP(ctx context.Context, network Network, host string) (addrs []netip.Addr, err error)
}

// type check
var _ Resolver = (*net.Resolver)(nil)

// ParallelResolver is a slice of resolvers that are queried concurrently until
// the first successful response is returned, as opposed to all resolvers being
// queried in order in [ConsequentResolver].
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
		return lookup(ctx, r[0], network, host)
	default:
		// Go on.
	}

	// Size of channel must accommodate results of lookups from all resolvers,
	// sending into channel will be block otherwise.
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

// lookupAsync performs a lookup for ip of host with r and sends the result into
// resCh.  It is intended to be used as a goroutine.
func lookupAsync(ctx context.Context, r Resolver, network, host string, resCh chan<- any) {
	defer log.OnPanic("parallel lookup")

	addrs, err := lookup(ctx, r, network, host)
	if err != nil {
		resCh <- err
	} else {
		resCh <- addrs
	}
}

// lookup tries to lookup ip of host with r.
//
// TODO(e.burkov):  Get rid of this function?  It only wraps the actual lookup
// with dubious logging.
func lookup(ctx context.Context, r Resolver, network, host string) (addrs []netip.Addr, err error) {
	start := time.Now()
	addrs, err = r.LookupNetIP(ctx, network, host)
	elapsed := time.Since(start)

	if err != nil {
		log.Debug("parallel lookup: lookup for %s failed in %s: %s", host, elapsed, err)
	} else {
		log.Debug("parallel lookup: lookup for %s succeeded in %s: %s", host, elapsed, addrs)
	}

	return addrs, err
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
// of IP addresses.
type StaticResolver []netip.Addr

// type check
var _ Resolver = StaticResolver(nil)

// LookupNetIP implements the [Resolver] interface for StaticResolver.
func (r StaticResolver) LookupNetIP(
	ctx context.Context,
	network Network,
	host string,
) (addrs []netip.Addr, err error) {
	return slices.Clone(r), nil
}

// SortResolver sorts resolved addresses according to the preferred family.
type SortResolver struct {
	// Resolver is the underlying resolver that retrieves the actual addresses.
	Resolver

	// SortFunc is the function that sorts the addresses.  It must not be nil.
	SortFunc func(a, b netip.Addr) (res int)
}

// type check
var _ Resolver = (*SortResolver)(nil)

// LookupNetIP implements the [Resolver] interface for *FamilyResolver.
func (r *SortResolver) LookupNetIP(
	ctx context.Context,
	network Network,
	host string,
) (addrs []netip.Addr, err error) {
	addrs, err = r.Resolver.LookupNetIP(ctx, network, host)
	slices.SortFunc(addrs, r.SortFunc)

	return addrs, err
}
