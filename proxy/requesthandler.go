package proxy

import "github.com/AdguardTeam/golibs/errors"

// ErrDrop is returned by a [Handler] to signal that the proxy should not send
// any response to the client.
const ErrDrop errors.Error = "drop response"

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

// The HandlerFunc type is an adapter to allow the use of ordinary functions as
// [Handler].  If f is a function with the appropriate signature, HandlerFunc(f)
// is a [Handler] that calls f.
type HandlerFunc func(p *Proxy, dctx *DNSContext) (err error)

// type check
var _ Handler = HandlerFunc(nil)

// ServeDNS implements the [Handler] interface for HandlerFunc.
func (f HandlerFunc) ServeDNS(p *Proxy, dctx *DNSContext) (err error) {
	return f(p, dctx)
}
