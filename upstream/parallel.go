package upstream

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// exchangeResult is a structure that represents result of exchangeAsync
type exchangeResult struct {
	reply    *dns.Msg // Result of DNS request execution
	upstream Upstream // Upstream that successfully resolved request
	err      error    // Error
}

// ErrNoUpstreams is returned from the methods that expect at least a single
// upstream to work with when no upstreams specified.
const ErrNoUpstreams errors.Error = "no upstream specified"

// ExchangeParallel function is called to parallel exchange dns request by many upstreams
// First answer without error will be returned
// We will return nil and error if count of errors equals count of upstreams
func ExchangeParallel(u []Upstream, req *dns.Msg) (*dns.Msg, Upstream, error) {
	size := len(u)

	if size == 0 {
		return nil, nil, ErrNoUpstreams
	}

	if size == 1 {
		reply, err := exchange(u[0], req)
		return reply, u[0], err
	}

	// Size of channel must accommodate results of exchangeAsync from all upstreams
	// Otherwise sending in channel will be locked
	ch := make(chan *exchangeResult, size)

	for _, f := range u {
		go exchangeAsync(f, req, ch)
	}

	errs := []error{}
	for n := 0; n < len(u); n++ {
		rep := <-ch
		if rep.err != nil {
			errs = append(errs, rep.err)
		} else if rep.reply != nil {
			return rep.reply, rep.upstream, nil
		}
	}

	if len(errs) == 0 {
		// All responses had nil replies.
		return nil, nil, fmt.Errorf("none of upstream servers responded")
	}

	return nil, nil, errors.List("all upstreams failed to respond", errs...)
}

// ExchangeAllResult - result of ExchangeAll()
type ExchangeAllResult struct {
	Resp     *dns.Msg // response
	Upstream Upstream // upstream server
}

// ExchangeAll receives a response from each of ups.
func ExchangeAll(ups []Upstream, req *dns.Msg) (res []ExchangeAllResult, err error) {
	upsl := len(ups)
	if upsl == 0 {
		return nil, ErrNoUpstreams
	}

	res = make([]ExchangeAllResult, 0, upsl)
	errs := make([]error, 0, upsl)
	resCh := make(chan *exchangeResult, upsl)

	// Start exchanging concurrently.
	for _, u := range ups {
		go exchangeAsync(u, req, resCh)
	}

	// Wait for all exchanges to finish.
	for i := 0; i < upsl; i++ {
		rep := <-resCh
		if rep.err != nil {
			errs = append(errs, rep.err)

			continue
		}

		if rep.reply == nil {
			errs = append(errs, errors.Error("no reply"))

			continue
		}

		res = append(res, ExchangeAllResult{
			Resp:     rep.reply,
			Upstream: rep.upstream,
		})
	}
	if len(errs) == upsl {
		return res, errors.List("all upstreams failed to exchange", errs...)
	}

	return res, nil
}

// exchangeAsync tries to resolve DNS request with one upstream and send result to resp channel
func exchangeAsync(u Upstream, req *dns.Msg, respCh chan *exchangeResult) {
	resp, err := u.Exchange(req.Copy())
	respCh <- &exchangeResult{
		reply:    resp,
		upstream: u,
		err:      err,
	}
}

func exchange(u Upstream, req *dns.Msg) (*dns.Msg, error) {
	start := time.Now()
	reply, err := u.Exchange(req)
	elapsed := time.Since(start)
	if err == nil {
		log.Tracef(
			"upstream %s successfully finished exchange of %s. Elapsed %s.",
			u.Address(),
			req.Question[0].String(),
			elapsed,
		)
	} else {
		log.Tracef(
			"upstream %s failed to exchange %s in %s. Cause: %s",
			u.Address(),
			req.Question[0].String(),
			elapsed,
			err,
		)
	}
	return reply, err
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
		return nil, errors.Error("no resolvers specified")
	}
	if size == 1 {
		address, err := lookup(ctx, resolvers[0], host)
		return address, err
	}

	// Size of channel must accommodate results of lookups from all resolvers
	// Otherwise sending in channel will be locked
	ch := make(chan *lookupResult, size)

	for _, res := range resolvers {
		go lookupAsync(ctx, res, host, ch)
	}

	var errs []error
	for n := 0; n < size; n++ {
		result := <-ch

		if result.err != nil {
			errs = append(errs, result.err)

			continue
		}

		return result.address, nil
	}

	return nil, errors.List("all resolvers failed", errs...)
}

// lookupAsync tries to lookup for host ip with one Resolver and sends lookupResult to res channel
func lookupAsync(ctx context.Context, r *Resolver, host string, res chan *lookupResult) {
	address, err := lookup(ctx, r, host)
	res <- &lookupResult{
		err:     err,
		address: address,
	}
}

func lookup(ctx context.Context, r *Resolver, host string) ([]net.IPAddr, error) {
	start := time.Now()
	address, err := r.LookupIPAddr(ctx, host)
	elapsed := time.Since(start)
	if err != nil {
		log.Tracef(
			"failed to lookup for %s in %s using %s: %s",
			host,
			elapsed,
			r.resolverAddress,
			err,
		)
	} else {
		log.Tracef(
			"successfully finished lookup for %s in %s using %s. Result : %s",
			host,
			elapsed,
			r.resolverAddress,
			address,
		)
	}
	return address, err
}
