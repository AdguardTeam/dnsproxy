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
