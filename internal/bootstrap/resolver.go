package bootstrap

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// Resolver resolves the hostnames to IP addresses.
type Resolver interface {
	// LookupNetIP looks up the IP addresses for the given host.  network must
	// be one of "ip", "ip4" or "ip6".  The response may be empty even if err is
	// nil.
	LookupNetIP(ctx context.Context, network, host string) (addrs []netip.Addr, err error)
}

// type check
var _ Resolver = &net.Resolver{}

// ErrNoResolvers is returned when zero resolvers specified.
const ErrNoResolvers errors.Error = "no resolvers specified"

// ParallelResolver is a slice of resolvers that are queried concurrently.  The
// first successful response is returned.
type ParallelResolver []Resolver

// type check
var _ Resolver = ParallelResolver(nil)

// LookupNetIP implements the [Resolver] interface for ParallelResolver.
func (r ParallelResolver) LookupNetIP(
	ctx context.Context,
	network string,
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
