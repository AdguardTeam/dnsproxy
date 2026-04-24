package proxy

import "context"

// TestHandler is a mock request handler implementation to simplify
// testing.
//
// TODO(d.kolyshev):  Move to internal/dnsproxytest.
type TestHandler struct {
	OnHandle func(ctx context.Context, p *Proxy, dctx *DNSContext) (err error)
}

// type check
var _ Handler = (*TestHandler)(nil)

// ServeDNS implements the [Handler] interface for *TestHandler.
func (h *TestHandler) ServeDNS(ctx context.Context, p *Proxy, dctx *DNSContext) (err error) {
	return h.OnHandle(ctx, p, dctx)
}
