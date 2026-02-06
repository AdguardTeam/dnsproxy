package proxy

// RequestHandler is an interface for handling DNS requests.
//
// TODO(d.kolyshev): Rename.
type RequestHandler interface {
	// Handle resolves the DNS request within *DNSContext.
	//
	// TODO(e.burkov):  Use the [context.Context] instead of [*DNSContext].
	Handle(p *Proxy, dctx *DNSContext) (err error)
}

// DefaultRequestHandler implements [RequestHandler] by calling [Proxy.Resolve].
type DefaultRequestHandler struct{}

// type check
var _ RequestHandler = DefaultRequestHandler{}

// Handle implements the [RequestHandler] interface for DefaultRequestHandler.
func (DefaultRequestHandler) Handle(p *Proxy, proxyCtx *DNSContext) (err error) {
	return p.Resolve(proxyCtx)
}
