package upstream

import (
	"fmt"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

const (
	// ErrNoUpstreams is returned from the methods that expect at least a single
	// upstream to work with when no upstreams specified.
	ErrNoUpstreams errors.Error = "no upstream specified"

	// ErrNoReply is returned from [ExchangeAll] when no upstreams replied.
	ErrNoReply errors.Error = "no reply"
)

// ExchangeParallel returns the first successful response from one of u.  It
// returns an error if all upstreams failed to exchange the request.
func ExchangeParallel(ups []Upstream, req *dns.Msg) (reply *dns.Msg, resolved Upstream, err error) {
	upsNum := len(ups)
	switch upsNum {
	case 0:
		return nil, nil, ErrNoUpstreams
	case 1:
		reply, err = ups[0].Exchange(req)

		return reply, ups[0], err
	default:
		// Go on.
	}

	resCh := make(chan any, upsNum)
	for _, f := range ups {
		go exchangeAsync(f, req, resCh)
	}

	errs := []error{}
	for range ups {
		var r *ExchangeAllResult
		r, err = receiveAsyncResult(resCh)
		if err != nil {
			if !errors.Is(err, ErrNoReply) {
				errs = append(errs, err)
			}
		} else {
			return r.Resp, r.Upstream, nil
		}
	}

	// TODO(e.burkov):  Probably it's better to return the joined error from
	// each upstream that returned no response, and get rid of multiple
	// [errors.Is] calls.  This will change the behavior though.
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
	upsNum := len(ups)
	switch upsNum {
	case 0:
		return nil, ErrNoUpstreams
	case 1:
		var reply *dns.Msg
		reply, err = ups[0].Exchange(req)
		if err != nil {
			return nil, err
		} else if reply == nil {
			return nil, ErrNoReply
		}

		return []ExchangeAllResult{{Upstream: ups[0], Resp: reply}}, nil
	default:
		// Go on.
	}

	res = make([]ExchangeAllResult, 0, upsNum)
	var errs []error

	resCh := make(chan any, upsNum)

	// Start exchanging concurrently.
	for _, u := range ups {
		go exchangeAsync(u, req, resCh)
	}

	// Wait for all exchanges to finish.
	for range ups {
		var r *ExchangeAllResult
		r, err = receiveAsyncResult(resCh)
		if err != nil {
			errs = append(errs, err)
		} else {
			res = append(res, *r)
		}
	}

	if len(errs) == upsNum {
		return res, fmt.Errorf("all upstreams failed: %w", errors.Join(errs...))
	}

	return slices.Clip(res), nil
}

// receiveAsyncResult receives a single result from resCh or an error from
// errCh.  It returns either a non-nil result or an error.
func receiveAsyncResult(resCh chan any) (res *ExchangeAllResult, err error) {
	switch res := (<-resCh).(type) {
	case error:
		return nil, res
	case *ExchangeAllResult:
		if res.Resp == nil {
			return nil, ErrNoReply
		}

		return res, nil
	default:
		return nil, fmt.Errorf("unexpected type %T of result", res)
	}
}

// exchangeAsync tries to resolve DNS request with one upstream and sends the
// result to respCh.
func exchangeAsync(u Upstream, req *dns.Msg, resCh chan any) {
	reply, err := u.Exchange(req)
	if err != nil {
		resCh <- err
	} else {
		resCh <- &ExchangeAllResult{Resp: reply, Upstream: u}
	}
}
