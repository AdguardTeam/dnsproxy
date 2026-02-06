package proxy

// RequestHandler is an interface for handling DNS requests.
type RequestHandler interface {
	// Handle resolves the DNS request within *DNSContext.
	//
	// TODO(e.burkov):  Use the [context.Context] instead of [*DNSContext] when
	//  the interface-based handler is implemented.
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
