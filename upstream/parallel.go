package upstream

import (
	"context"
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

const (
	// ErrNoUpstreams is returned from the methods that expect at least a single
	// upstream to work with when no upstreams specified.
	ErrNoUpstreams errors.Error = "no upstream specified"

	// ErrNoReply is returned from [ExchangeAll] when no upstreams replied.
	ErrNoReply errors.Error = "no reply"
)

// ExchangeParallel returns the dirst successful response from one of u.  It
// returns an error if all upstreams failed to exchange the request.
func ExchangeParallel(u []Upstream, req *dns.Msg) (reply *dns.Msg, resolved Upstream, err error) {
	upsNum := len(u)
	switch upsNum {
	case 0:
		return nil, nil, ErrNoUpstreams
	case 1:
		reply, err = exchangeAndLog(u[0], req)

		return reply, u[0], err
	default:
		// Go on.
	}

	resCh := make(chan *ExchangeAllResult)
	errCh := make(chan error)
	for _, f := range u {
		go exchangeAsync(f, req, resCh, errCh)
	}

	errs := []error{}
	for range u {
		select {
		case excErr := <-errCh:
			errs = append(errs, excErr)
		case rep := <-resCh:
			if rep.Resp != nil {
				return rep.Resp, rep.Upstream, nil
			}
		}
	}

	if len(errs) == 0 {
		return nil, nil, errors.Error("none of upstream servers responded")
	}

	return nil, nil, errors.Join(errs...)
}

// ExchangeAllResult is the successful result of [ExchangeAll] for a single
// upstream.
type ExchangeAllResult struct {
	// Resp is the response DNS request resolved into.
	Resp *dns.Msg

	// Upstream is the upstream that successfully resolved the request.
	Upstream Upstream
}

// ExchangeAll returns the responses from all of u.  It returns an error only if
// all upstreams failed to exchange the request.
func ExchangeAll(ups []Upstream, req *dns.Msg) (res []ExchangeAllResult, err error) {
	upsl := len(ups)
	switch upsl {
	case 0:
		return nil, ErrNoUpstreams
	case 1:
		var reply *dns.Msg
		reply, err = exchangeAndLog(ups[0], req)
		if err != nil {
			return nil, err
		} else if reply == nil {
			return nil, ErrNoReply
		}

		return []ExchangeAllResult{{Upstream: ups[0], Resp: reply}}, nil
	default:
		// Go on.
	}

	res = make([]ExchangeAllResult, 0, upsl)
	var errs []error

	resCh := make(chan *ExchangeAllResult)
	errCh := make(chan error)

	// Start exchanging concurrently.
	for _, u := range ups {
		go exchangeAsync(u, req, resCh, errCh)
	}

	// Wait for all exchanges to finish.
	for range ups {
		var r *ExchangeAllResult
		r, err = receiveAsyncResult(resCh, errCh)
		if err != nil {
			errs = append(errs, err)
		} else {
			res = append(res, *r)
		}
	}

	if len(errs) == upsl {
		// TODO(e.burkov):  Use [errors.Join] in Go 1.20.
		return res, errors.List("all upstreams failed to exchange", errs...)
	}

	return res, nil
}

// receiveAsyncResult receives a single result from resCh or an error from
// errCh.  It returns either a non-nil result or an error.
func receiveAsyncResult(
	resCh chan *ExchangeAllResult,
	errCh chan error,
) (res *ExchangeAllResult, err error) {
	select {
	case err = <-errCh:
		return nil, err
	case rep := <-resCh:
		if rep.Resp == nil {
			return nil, ErrNoReply
		}

		return rep, nil
	}
}

// exchangeAsync tries to resolve DNS request with one upstream and sends the
// result to respCh.
func exchangeAsync(u Upstream, req *dns.Msg, respCh chan *ExchangeAllResult, errCh chan error) {
	reply, err := exchangeAndLog(u, req)
	if err != nil {
		errCh <- err
	} else {
		respCh <- &ExchangeAllResult{Resp: reply, Upstream: u}
	}
}

// exchangeAndLog wraps the [Upstream.Exchange] method with logging.
func exchangeAndLog(u Upstream, req *dns.Msg) (resp *dns.Msg, err error) {
	addr := u.Address()
	req = req.Copy()

	start := time.Now()
	reply, err := u.Exchange(req)
	elapsed := time.Since(start)

	if q := &req.Question[0]; err == nil {
		log.Debug("dnsproxy: upstream %s exchanged %s successfully in %s", addr, q, elapsed)
	} else {
		log.Debug("dnsproxy: upstream %s failed to exchange %s in %s: %s", addr, q, elapsed, err)
	}

	return reply, err
}

// LookupParallel tries to lookup for ip of host with all resolvers
// concurrently.
//
// Deprecated:  Use [ParallelResolver] instead.
func LookupParallel(
	ctx context.Context,
	resolvers []Resolver,
	host string,
) (addrs []netip.Addr, err error) {
	return ParallelResolver(resolvers).LookupNetIP(ctx, "ip", host)
}
