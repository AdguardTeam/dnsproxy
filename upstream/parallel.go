package upstream

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/hmage/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

// exchangeResult is a structure that represents result of exchange
type exchangeResult struct {
	reply   *dns.Msg      // Result of DNS request execution
	elapsed time.Duration // Elapsed time
	err     error         // Error
}

// ExchangeParallel function is called to parallel exchange dns request by many upstreams
// First answer without error will be returned
// We will return nil and error if count of errors equals count of upstreams
func ExchangeParallel(u []Upstream, req *dns.Msg) (*dns.Msg, error) {
	size := len(u)

	if size == 0 {
		return nil, errors.New("no upstream specified")
	}

	if size == 1 {
		return u[0].Exchange(req)
	}

	// Size of channel must accommodate results of exchange from all upstreams
	// Otherwise sending in channel will be locked
	ch := make(chan *exchangeResult, size)

	for _, f := range u {
		go exchange(f, req, ch)
	}

	errs := []error{}
	for {
		select {
		case rep := <-ch:
			reply := rep.reply
			err := rep.err
			if err != nil {
				errs = append(errs, err)
			}

			if len(errs) == size {
				return nil, errorx.DecorateMany("all upstreams failed to exchange", errs...)
			}

			if reply != nil && err == nil {
				return reply, nil
			}
		}
	}
}

// exchange tries to resolve DNS request with one upstream and send result to resp channel
func exchange(u Upstream, req *dns.Msg, resp chan *exchangeResult) {
	start := time.Now()
	reply, err := u.Exchange(req)
	elapsed := time.Since(start) / time.Millisecond
	if err == nil {
		log.Tracef("upstream %s succesfully finished exchange of %s. Elapsed %d ms.", u.Address(), req.Question[0].String(), elapsed)
	} else {
		log.Tracef("upstream %s failed to exchange %s in %d milliseconds. Cause: %s", u.Address(), req.Question[0].String(), elapsed, err)
	}

	resp <- &exchangeResult{
		reply:   reply,
		elapsed: elapsed,
		err:     err,
	}
}

// lookupResult is a structure that represents result of lookup
type lookupResult struct {
	address []net.IPAddr // List of IP addresses
	err     error        // Error
}

// LookupParallel starts parallel lookup for host ip with many Resolvers
// First answer without error will be returned
// Return nil and error if count of errors equals count of resolvers
func LookupParallel(ctx context.Context, resolvers []*Resolver, host string) ([]net.IPAddr, error) {
	size := len(resolvers)

	if size == 0 {
		return nil, errors.New("no resolvers specified")
	}
	if size == 1 {
		return resolvers[0].resolver.LookupIPAddr(ctx, host)
	}

	// Size of channel must accommodate results of lookups from all resolvers
	// Otherwise sending in channel will be locked
	ch := make(chan *lookupResult, size)

	for _, res := range resolvers {
		go lookup(ctx, res, host, ch)
	}

	errs := []error{}
	for {
		select {
		case result := <-ch:
			addr := result.address
			err := result.err
			if err != nil {
				errs = append(errs, err)
			}

			if len(errs) == size {
				return nil, errorx.DecorateMany("all resolvers failed to lookup", errs...)
			}

			if addr != nil && err == nil {
				return addr, nil
			}
		}
	}
}

// lookup tries to lookup for host ip with one Resolver and sends lookupResult to res channel
func lookup(ctx context.Context, r *Resolver, host string, res chan *lookupResult) {
	start := time.Now()
	address, err := r.LookupIPAddr(ctx, host)
	elapsed := time.Since(start) / time.Millisecond
	if err != nil {
		log.Tracef("failed to lookup for %s in %d milliseconds using %s: %s", host, elapsed, r.address, err)
	} else {
		log.Tracef("successfully finish lookup for %s in %d milliseconds using %s. Result : %s", host, elapsed, r.address, address)
	}

	res <- &lookupResult{
		err:     err,
		address: address,
	}
}
