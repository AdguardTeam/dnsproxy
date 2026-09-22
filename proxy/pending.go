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
	// resolution.  dctx must not be nil.
	queue(ctx context.Context, dctx *DNSContext) (loaded bool, err error)

	// done must be called after the request is completed, if queue returned
	// false for it.  dctx must not be nil.
	done(ctx context.Context, dctx *DNSContext, err error)
}

// defaultPendingRequests is a default implementation of the [pendingRequests]
// interface.  It must be created with [newDefaultPendingRequests].
type defaultPendingRequests struct {
	storage *syncutil.Map[pendingRequestKey, *pendingRequest]
}

// pendingRequestKey is the key for an in-progress request.  The custom
// upstream configuration is part of the key since identical queries using
// different upstream configurations must be resolved independently.
type pendingRequestKey struct {
	customUpstreamConfig *CustomUpstreamConfig
	msg                  string
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
		storage: syncutil.NewMap[pendingRequestKey, *pendingRequest](),
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
	key := newPendingRequestKey(dctx)

	req := &pendingRequest{
		finish: make(chan struct{}),
	}

	pending, loaded := pr.storage.LoadOrStore(key, req)
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
	key := newPendingRequestKey(dctx)

	pending, ok := pr.storage.Load(key)
	if !ok {
		panic(fmt.Errorf("loading pending request: key %q: %w", key.msg, errors.ErrNoValue))
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

	pr.storage.Delete(key)
	close(pending.finish)
}

// newPendingRequestKey returns the pending request key for dctx.  dctx must not
// be nil.
func newPendingRequestKey(dctx *DNSContext) (key pendingRequestKey) {
	var msgKey []byte
	if dctx.ReqECS != nil {
		ones, _ := dctx.ReqECS.Mask.Size()
		msgKey = msgToKeyWithSubnet(dctx.Req, dctx.ReqECS.IP, ones)
	} else {
		msgKey = msgToKey(dctx.Req)
	}

	return pendingRequestKey{
		customUpstreamConfig: dctx.CustomUpstreamConfig,
		msg:                  string(msgKey),
	}
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
