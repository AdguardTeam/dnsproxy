package proxy

// Handler is an interface for handling DNS requests.
type Handler interface {
	// ServeDNS resolves the DNS request within *DNSContext.
	//
	// TODO(e.burkov):  Use the [context.Context] instead of [*DNSContext].
	ServeDNS(p *Proxy, dctx *DNSContext) (err error)
}

// DefaultHandler implements [Handler] by calling [Proxy.Resolve].
type DefaultHandler struct{}

// type check
var _ Handler = DefaultHandler{}

// ServeDNS implements the [Handler] interface for DefaultHandler.
func (DefaultHandler) ServeDNS(p *Proxy, proxyCtx *DNSContext) (err error) {
	return p.Resolve(proxyCtx)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions
// as Handler.  If f is a function with the appropriate signature,
// HandlerFunc(f) is a Handler that calls f.
type HandlerFunc func(p *Proxy, dctx *DNSContext) (err error)

// type check
var _ Handler = HandlerFunc(nil)

// ServeDNS implements the [Handler] interface for HandlerFunc.
func (f HandlerFunc) ServeDNS(p *Proxy, dctx *DNSContext) (err error) {
	return f(p, dctx)
}

// Middleware is a common middleware interface.
type Middleware interface {
	// Wrap returns a new handler that wraps the specified handler.
	Wrap(handler Handler) (wrapped Handler)
}

// MiddlewareFunc is a function that implements the [Middleware] interface.
type MiddlewareFunc func(h Handler) (wrapped Handler)

// type check
var _ Middleware = MiddlewareFunc(nil)

// Wrap implements the [Middleware] interface for MiddlewareFunc.
func (f MiddlewareFunc) Wrap(h Handler) (wrapped Handler) {
	return f(h)
}

// type check
var _ MiddlewareFunc = PassThrough

// PassThrough is a [MiddlewareFunc] that returns h as-is.
func PassThrough(h Handler) (wrapped Handler) {
	return h
}
