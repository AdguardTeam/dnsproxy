package upstream

import (
	"context"
	"net"
	"time"

	"github.com/hmage/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

// exchangeResult is a structure that represents result of exchange
type exchangeResult struct {
	reply   *dns.Msg
	elapsed time.Duration
	err     error
}

// ExchangeParallel function is called to parallel exchange dns request by many upstreams
// First answer without error will be returned
// We will return nil and error if count of errors equals count of upstreams
func ExchangeParallel(u []Upstream, req *dns.Msg) (*dns.Msg, error) {
	size := len(u)

	// Size of channel must accommodate results of exchange from all upstreams
	// Otherwise sending in channel will be locked
	ch := make(chan *exchangeResult, size)

	for _, f := range u {
		go exchange(f, req, ch)
	}

	var count int
	for {
		select {
		case rep := <-ch:
			reply := rep.reply
			err := rep.err
			if err != nil {
				count++
			}

			if count == size {
				return nil, errorx.Decorate(err, "all upstreams failed to exchange")
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
	elapsed := time.Since(start)
	if err == nil {
		log.Tracef("upstream %s succesfully finished exchange of %s. Elapsed %d ms.", u.Address(), req.Question[0].String(), elapsed)
	} else {
		log.Tracef("upstream %s failed to exchange %s in %s milliseconds. Cause: %s", u.Address(), req.Question[0].String(), elapsed, err)
	}

	resp <- &exchangeResult{
		reply:   reply,
		elapsed: elapsed,
		err:     err,
	}
}

// lookupResult is a structure that represents result of lookup
type lookupResult struct {
	err     error
	address []net.IPAddr
}

// LookupParallel starts parallel lookup for host ip with many resolvers
// First answer without error will be returned
// Return nil and error if count of errors equals count of resolvers
func LookupParallel(ctx context.Context, resolvers []resolverWithAddress, host string) ([]net.IPAddr, error) {
	size := len(resolvers)

	// Size of channel must accommodate results of lookups from all resolvers
	// Otherwise sending in channel will be locked
	ch := make(chan *lookupResult, size)

	for _, res := range resolvers {
		go lookup(ctx, res, host, ch)
	}

	var count int
	for {
		select {
		case result := <-ch:
			addr := result.address
			err := result.err
			if err != nil {
				count++
			}

			if count == size {
				return nil, errorx.Decorate(err, "all resolvers failed to lookup for %s", host)
			}

			if addr != nil && err == nil {
				return addr, nil
			}
		}
	}
}

// lookup tries to lookup for host ip with one resolver and sends lookupResult to res channel
func lookup(ctx context.Context, r resolverWithAddress, host string, res chan *lookupResult) {
	address, err := r.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		log.Tracef("failed to lookup for %s using %s: %s", host, r.address, err)
	} else {
		log.Tracef("successfully finish lookup for %s. Result : %s", host, address)
	}

	res <- &lookupResult{
		err:     err,
		address: address,
	}
}
