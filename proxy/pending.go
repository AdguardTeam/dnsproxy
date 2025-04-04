package proxy

import (
	"context"
	"fmt"
	"sync"
)

// PendingRequests handles identical requests that are in progress.  It is used
// to avoid sending the same request multiple times to the upstream server.  The
// implementations are:
//   - [DefaultPendingRequests].
//   - [EmptyPendingRequests].
type PendingRequests interface {
	// Queue is called for each request.  It returns false if there are no
	// identical requests in progress.  Otherwise it blocks until the first
	// request is completed and returns the error that occurred during its
	// resolution.
	Queue(ctx context.Context, dctx *DNSContext) (exists bool, err error)

	// Done must be called after the request is completed, if queue returned
	// false for it.
	Done(ctx context.Context, dctx *DNSContext, err error)
}

// TODO(e.burkov):  !! doc

// type check
var _ PendingRequests = (*DefaultPendingRequests)(nil)

// DefaultPendingRequests is a default implementation of the [PendingRequests]
// interface.
type DefaultPendingRequests struct {
	storage *sync.Map

	// TODO(e.burkov):  !! add logger
}

// pendingRequest is a structure that stores the request and response results.
type pendingRequest struct {
	finish chan struct{}

	// resolveErr is the error that occurred during the request processing.  It
	// may be nil.  It must only be accessed for reading after the finish
	// channel is closed.
	resolveErr error

	// cloneCtx is a clone of the DNSContext that was used to create the
	// pendingRequest.  It is used to store the response message.  It must only
	// be accessed for reading after the finish channel is closed.
	cloneCtx *DNSContext
}

// NewDefaultPendingRequests creates a new instance of DefaultPendingRequests.
func NewDefaultPendingRequests() (pr *DefaultPendingRequests) {
	return &DefaultPendingRequests{
		storage: &sync.Map{},
	}
}

// Queue implements the [PendingRequests] interface for
// [DefaultPendingRequests].
func (pr *DefaultPendingRequests) Queue(ctx context.Context, dctx *DNSContext) (exists bool, err error) {
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
	if exists {
		pending := pendingVal.(*pendingRequest)
		<-pending.finish

		if pending.cloneCtx != nil {
			dctx.Res = pending.cloneCtx.Res.Copy()
			dctx.Res.Id = dctx.Req.Id
		}

		return exists, pending.resolveErr
	}

	return false, nil
}

// Done implements the [PendingRequests] interface for [DefaultPendingRequests].
func (pr *DefaultPendingRequests) Done(ctx context.Context, dctx *DNSContext, err error) {
	var key []byte
	if dctx.ReqECS != nil {
		ones, _ := dctx.ReqECS.Mask.Size()
		key = msgToKeyWithSubnet(dctx.Req, dctx.ReqECS.IP, ones)
	} else {
		key = msgToKey(dctx.Req)
	}

	pendingVal, ok := pr.storage.Load(string(key))
	if !ok {
		// TODO(e.burkov):  !! debug log
		panic(fmt.Errorf("pending request not found for key %x", key))
	}

	pending := pendingVal.(*pendingRequest)
	pending.resolveErr = err
	if dctx.Res != nil {
		// TODO(e.burkov):  !! clone properly
		pending.cloneCtx = &DNSContext{
			Res: dctx.Res.Copy(),
		}
	}

	pr.storage.Delete(string(key))
	close(pending.finish)
}

// EmptyPendingRequests is a no-op implementation of PendingRequests.  It is
// used when pending requests are not needed.
type EmptyPendingRequests struct{}

// type check
var _ PendingRequests = EmptyPendingRequests{}

// Queue implements the [PendingRequests] interface for [EmptyPendingRequests].
// It always returns false and does not block.
func (EmptyPendingRequests) Queue(_ context.Context, _ *DNSContext) (exists bool, err error) {
	return false, nil
}

// Done implements the [PendingRequests] interface for [EmptyPendingRequests].
func (EmptyPendingRequests) Done(_ context.Context, _ *DNSContext, _ error) {}
