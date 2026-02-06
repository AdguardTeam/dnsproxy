package proxy

// TestRequestHandler is a mock request handler implementation to simplify
// testing.
//
// TODO(d.kolyshev):  Move to internal/dnsproxytest.
type TestRequestHandler struct {
	OnHandle func(p *Proxy, dctx *DNSContext) (err error)
}

// type check
var _ RequestHandler = (*TestRequestHandler)(nil)

// Handle implements the [RequestHandler] interface for *TestRequestHandler.
func (h *TestRequestHandler) Handle(p *Proxy, dctx *DNSContext) (err error) {
	return h.OnHandle(p, dctx)
}
