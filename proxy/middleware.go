package proxy

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
