package upstream

import (
	"context"
	"fmt"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// TODO(e.burkov):  Consider using wrapped [errors.ErrNoValue] and
// [errors.ErrEmptyValue] instead.
const (
	// ErrNoUpstreams is returned from the methods that expect at least a single
	// upstream to work with when no upstreams specified.
	ErrNoUpstreams errors.Error = "no upstream specified"

	// ErrNoReply is returned from [ExchangeAll] when no upstreams replied.
	ErrNoReply errors.Error = "no reply"
)

// ExchangeParallel returns the first successful response from one of u.  It
// returns an error if all upstreams failed to exchange the request.  Each
// element of ups must not be nil, req must not be nil.
//
// A response with the SERVFAIL code is not considered successful.  Such a
// response is returned only if all upstreams respond with SERVFAIL, in which
// case the first received one is returned.
//
// See https://www.rfc-editor.org/rfc/rfc9520#section-2.1.
func ExchangeParallel(
	ctx context.Context,
	ups []Upstream,
	req *dns.Msg,
) (reply *dns.Msg, resolved Upstream, err error) {
	upsNum := len(ups)
	switch upsNum {
	case 0:
		return nil, nil, ErrNoUpstreams
	case 1:
		return exchangeSingle(ctx, ups[0], req)
	default:
		// Go on.
	}

	resCh := make(chan any, upsNum)
	for _, f := range ups {
		// Use a copy to prevent data races, as [dns.Client] can modify the DNS
		// request during the exchange.
		//
		// TODO(s.chzhen):  Consider using buffer pool.
		copyReq := req.Copy()
		go exchangeAsync(ctx, f, copyReq, resCh)
	}

	return receiveParallelResult(upsNum, resCh)
}

// receiveParallelResult waits for the first successful response from resCh.  A
// SERVFAIL response is returned only if all upstreams respond with SERVFAIL, in
// which case the first received one is returned.  See [ExchangeParallel].
func receiveParallelResult(
	upsNum int,
	resCh <-chan any,
) (reply *dns.Msg, resolved Upstream, err error) {
	var errs []error
	var firstServFail *ExchangeAllResult
	for range upsNum {
		var r *ExchangeAllResult
		r, err = receiveAsyncResult(resCh)
		if err != nil {
			errs = appendResultErr(errs, err)

			continue
		}

		if r.Resp.Rcode != dns.RcodeServerFailure {
			return r.Resp, r.Upstream, nil
		}

		// Save the first SERVFAIL response and keep waiting for a successful
		// response.
		if firstServFail == nil {
			firstServFail = r
		}
	}

	if firstServFail != nil {
		return firstServFail.Resp, firstServFail.Upstream, nil
	}

	// TODO(e.burkov):  Probably it's better to return the joined error from
	// each upstream that returned no response, and get rid of multiple
	// [errors.Is] calls.  This will change the behavior though.
	if len(errs) == 0 {
		return nil, nil, errors.Error("none of upstream servers responded")
	}

	return nil, nil, errors.Join(errs...)
}

// appendResultErr appends err to errs if err is not [ErrNoReply].
func appendResultErr(orig []error, err error) (errs []error) {
	errs = orig

	if !errors.Is(err, ErrNoReply) {
		errs = append(errs, err)
	}

	return errs
}

// exchangeSingle returns a successful response and resolver if a DNS lookup was
// successful.  ups, req must not be nil.
func exchangeSingle(
	ctx context.Context,
	ups Upstream,
	req *dns.Msg,
) (resp *dns.Msg, resolved Upstream, err error) {
	resp, err = ups.Exchange(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	return resp, ups, err
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
func ExchangeAll(
	ctx context.Context,
	ups []Upstream,
	req *dns.Msg,
) (res []ExchangeAllResult, err error) {
	upsNum := len(ups)
	switch upsNum {
	case 0:
		return nil, ErrNoUpstreams
	case 1:
		var reply *dns.Msg
		reply, err = ups[0].Exchange(ctx, req)
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
		// Use a copy to prevent data races, as [dns.Client] can modify the DNS
		// request during the exchange.
		//
		// TODO(s.chzhen):  Consider using buffer pool.
		copyReq := req.Copy()
		go exchangeAsync(ctx, u, copyReq, resCh)
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
func receiveAsyncResult(resCh <-chan any) (res *ExchangeAllResult, err error) {
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
func exchangeAsync(ctx context.Context, u Upstream, req *dns.Msg, resCh chan any) {
	reply, err := u.Exchange(ctx, req)
	if err != nil {
		resCh <- err
	} else {
		resCh <- &ExchangeAllResult{Resp: reply, Upstream: u}
	}
}
