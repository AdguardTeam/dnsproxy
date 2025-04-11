package proxy

import (
	"context"
	"fmt"
	"sync"

	"github.com/AdguardTeam/golibs/errors"
)

// PendingRequests handles identical requests that are in progress.  It is used
// to avoid sending the same request multiple times to the upstream server.  The
// implementations are:
//   - [DefaultPendingRequests].
//   - [EmptyPendingRequests].
type PendingRequests interface {
	// queue is called for each request.  It returns false if there are no
	// identical requests in progress.  Otherwise it blocks until the first
	// request is completed and returns the error that occurred during its
	// resolution.
	queue(ctx context.Context, dctx *DNSContext) (exists bool, err error)

	// done must be called after the request is completed, if queue returned
	// false for it.
	done(ctx context.Context, dctx *DNSContext, err error)
}

// DefaultPendingRequests is a default implementation of the [PendingRequests]
// interface.  It must be created with [NewDefaultPendingRequests].
type DefaultPendingRequests struct {
	storage *sync.Map
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

// NewDefaultPendingRequests creates a new instance of DefaultPendingRequests.
func NewDefaultPendingRequests() (pr *DefaultPendingRequests) {
	return &DefaultPendingRequests{
		storage: &sync.Map{},
	}
}

// type check
var _ PendingRequests = (*DefaultPendingRequests)(nil)

// queue implements the [PendingRequests] interface for
// [DefaultPendingRequests].
func (pr *DefaultPendingRequests) queue(
	ctx context.Context,
	dctx *DNSContext,
) (exists bool, err error) {
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

	pendingVal, exists := pr.storage.LoadOrStore(string(key), req)
	if !exists {
		return false, nil
	}

	pending := pendingVal.(*pendingRequest)
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

	return exists, pending.resolveErr
}

// done implements the [PendingRequests] interface for [DefaultPendingRequests].
func (pr *DefaultPendingRequests) done(ctx context.Context, dctx *DNSContext, err error) {
	var key []byte
	if dctx.ReqECS != nil {
		ones, _ := dctx.ReqECS.Mask.Size()
		key = msgToKeyWithSubnet(dctx.Req, dctx.ReqECS.IP, ones)
	} else {
		key = msgToKey(dctx.Req)
	}

	pendingVal, ok := pr.storage.Load(string(key))
	if !ok {
		panic(fmt.Errorf("loading pending request: key %x: %w", key, errors.ErrNoValue))
	}

	pending := pendingVal.(*pendingRequest)
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

// EmptyPendingRequests is a no-op implementation of PendingRequests.  It is
// used when pending requests are not needed.
type EmptyPendingRequests struct{}

// type check
var _ PendingRequests = EmptyPendingRequests{}

// queue implements the [PendingRequests] interface for [EmptyPendingRequests].
// It always returns false and does not block.
func (EmptyPendingRequests) queue(_ context.Context, _ *DNSContext) (exists bool, err error) {
	return false, nil
}

// done implements the [PendingRequests] interface for [EmptyPendingRequests].
func (EmptyPendingRequests) done(_ context.Context, _ *DNSContext, _ error) {}
