package proxy

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
)

// pendingRequests handles identical requests that are in progress.  It is used
// to avoid sending the same request multiple times to the upstream server.  The
// implementations are:
//   - [defaultPendingRequests].
//   - [emptyPendingRequests].
type pendingRequests interface {
	// queue is called for each request.  It returns false if there are no
	// identical requests in progress.  Otherwise it blocks until the first
	// request is completed and returns the error that occurred during its
	// resolution.
	queue(ctx context.Context, dctx *DNSContext) (loaded bool, err error)

	// done must be called after the request is completed, if queue returned
	// false for it.
	done(ctx context.Context, dctx *DNSContext, err error)
}

// defaultPendingRequests is a default implementation of the [pendingRequests]
// interface.  It must be created with [newDefaultPendingRequests].
type defaultPendingRequests struct {
	storage *syncutil.Map[string, *pendingRequest]
}

// pendingRequest is a structure that stores the query state and result.
type pendingRequest struct {
	// finish is a channel that is closed when the request is completed.  It is
	// used to block request processing for any but the first one.
	finish chan struct{}

	// resolveErr is the error that occurred during the request processing.  It
	// may be nil.  It must only be accessed for reading after the finish
	// channel is closed.
	resolveErr error

	// cloneDNSCtx is a clone of the DNSContext that was used to create the
	// pendingRequest and store its result.  It must only be accessed for
	// reading after the finish channel is closed.
	cloneDNSCtx *DNSContext
}

// newDefaultPendingRequests creates a new instance of DefaultPendingRequests.
func newDefaultPendingRequests() (pr *defaultPendingRequests) {
	return &defaultPendingRequests{
		storage: syncutil.NewMap[string, *pendingRequest](),
	}
}

// type check
var _ pendingRequests = (*defaultPendingRequests)(nil)

// queue implements the [pendingRequests] interface for
// [defaultPendingRequests].
func (pr *defaultPendingRequests) queue(
	ctx context.Context,
	dctx *DNSContext,
) (loaded bool, err error) {
	var key []byte
	if dctx.ReqECS != nil {
		ones, _ := dctx.ReqECS.Mask.Size()
		key = msgToKeyWithSubnet(dctx.Req, dctx.ReqECS.IP, ones)
	} else {
		key = msgToKey(dctx.Req)
	}

	req := &pendingRequest{
		finish: make(chan struct{}),
	}

	pending, loaded := pr.storage.LoadOrStore(string(key), req)
	if !loaded {
		return false, nil
	}

	<-pending.finish

	origDNSCtx := pending.cloneDNSCtx

	// TODO(a.garipov):  Perhaps, statistics should be calculated separately for
	// each request.
	dctx.queryStatistics = origDNSCtx.queryStatistics
	dctx.Upstream = origDNSCtx.Upstream
	if origDNSCtx.Res != nil {
		// TODO(e.burkov):  Add cloner for DNS messages.
		dctx.Res = origDNSCtx.Res.Copy().SetReply(dctx.Req)
	}

	return loaded, pending.resolveErr
}

// done implements the [pendingRequests] interface for [defaultPendingRequests].
func (pr *defaultPendingRequests) done(ctx context.Context, dctx *DNSContext, err error) {
	var key []byte
	if dctx.ReqECS != nil {
		ones, _ := dctx.ReqECS.Mask.Size()
		key = msgToKeyWithSubnet(dctx.Req, dctx.ReqECS.IP, ones)
	} else {
		key = msgToKey(dctx.Req)
	}

	pending, ok := pr.storage.Load(string(key))
	if !ok {
		panic(fmt.Errorf("loading pending request: key %x: %w", key, errors.ErrNoValue))
	}

	pending.resolveErr = err

	cloneCtx := &DNSContext{
		Upstream:        dctx.Upstream,
		queryStatistics: dctx.queryStatistics,
	}

	if dctx.Res != nil {
		cloneCtx.Res = dctx.Res.Copy()
	}

	pending.cloneDNSCtx = cloneCtx

	pr.storage.Delete(string(key))
	close(pending.finish)
}

// emptyPendingRequests is a no-op implementation of PendingRequests.  It is
// used when pending requests are not needed.
type emptyPendingRequests struct{}

// type check
var _ pendingRequests = emptyPendingRequests{}

// queue implements the [pendingRequests] interface for [emptyPendingRequests].
// It always returns false and does not block.
func (emptyPendingRequests) queue(_ context.Context, _ *DNSContext) (loaded bool, err error) {
	return false, nil
}

// done implements the [pendingRequests] interface for [emptyPendingRequests].
func (emptyPendingRequests) done(_ context.Context, _ *DNSContext, _ error) {}
