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
	// be one of "ip", "ip4" or "ip6".
	LookupNetIP(ctx context.Context, network, host string) (addrs []netip.Addr, err error)
}

// type check
var _ Resolver = &net.Resolver{}

// ErrNoResolvers is returned when zero resolvers specified.
const ErrNoResolvers errors.Error = "no resolvers specified"

// LookupParallel performs lookup for IP address of host with all resolvers
// concurrently.
func LookupParallel(
	ctx context.Context,
	resolvers []Resolver,
	host string,
) (addrs []netip.Addr, err error) {
	resolversNum := len(resolvers)
	switch resolversNum {
	case 0:
		return nil, ErrNoResolvers
	case 1:
		return lookup(ctx, resolvers[0], host)
	default:
		// Go on.
	}

	// Size of channel must accommodate results of lookups from all resolvers,
	// sending into channel will be block otherwise.
	ch := make(chan *lookupResult, resolversNum)
	for _, res := range resolvers {
		go lookupAsync(ctx, res, host, ch)
	}

	var errs []error
	for range resolvers {
		result := <-ch
		if result.err == nil {
			return result.addrs, nil
		}

		errs = append(errs, result.err)
	}

	// TODO(e.burkov):  Use [errors.Join] in Go 1.20.
	return nil, errors.List("all resolvers failed", errs...)
}

// lookupResult is a structure that represents the result of a lookup.
type lookupResult struct {
	err   error
	addrs []netip.Addr
}

// lookupAsync tries to lookup for ip of host with r and sends the result into
// resCh.  It's inteneded to be used as a goroutine.
func lookupAsync(ctx context.Context, r Resolver, host string, resCh chan<- *lookupResult) {
	defer log.OnPanic("parallel lookup")

	addrs, err := lookup(ctx, r, host)
	resCh <- &lookupResult{
		err:   err,
		addrs: addrs,
	}
}

// lookup tries to lookup ip of host with r.
func lookup(ctx context.Context, r Resolver, host string) (addrs []netip.Addr, err error) {
	start := time.Now()
	addrs, err = r.LookupNetIP(ctx, "ip", host)
	elapsed := time.Since(start)
	if err != nil {
		log.Debug("parallel lookup: lookup for %s failed in %s: %s", host, elapsed, err)
	} else {
		log.Debug("parallel lookup: lookup for %s succeeded in %s: %s", host, elapsed, addrs)
	}

	return addrs, err
}
