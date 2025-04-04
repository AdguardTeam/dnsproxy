package proxy

import "context"

// TestPendingRequests is a mock implementation of [proxy.PendingRequests] for
// tests.
//
// TODO(e.burkov):  Think of a better way to test [PendingRequests].
type TestPendingRequests struct {
	OnQueue func(ctx context.Context, dctx *DNSContext) (exists bool, err error)
	OnDone  func(ctx context.Context, dctx *DNSContext, err error)
}

// type check
var _ PendingRequests = (*TestPendingRequests)(nil)

// Queue implements the [proxy.PendingRequests] interface for
// *testPendingRequests.
func (p *TestPendingRequests) Queue(
	ctx context.Context,
	dctx *DNSContext,
) (exists bool, err error) {
	return p.OnQueue(ctx, dctx)
}

// Done implements the [proxy.PendingRequests] interface for
// *testPendingRequests.
func (p *TestPendingRequests) Done(ctx context.Context, dctx *DNSContext, err error) {
	p.OnDone(ctx, dctx, err)
}
