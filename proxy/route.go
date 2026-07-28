package proxy

import "net/http"

// Default path pattern constants.
const (
	// Deprecated: Use pathPatternDNSQuery instead.
	pathPatternRoot     = "/"
	pathPatternDNSQuery = "/dns-query"
)

// Default route pattern constants.
const (
	routePatternRootGet      = http.MethodGet + " " + pathPatternRoot
	routePatternRootPost     = http.MethodPost + " " + pathPatternRoot
	routePatternDNSQueryGet  = http.MethodGet + " " + pathPatternDNSQuery
	routePatternDNSQueryPost = http.MethodPost + " " + pathPatternDNSQuery
)

// routeDoH registers DoH handlers in mux.  p.HTTPConfig must not be nil.
// p.HTTPConfig.Routes must be valid, if p.HTTPConfig.Routes is empty, the
// default routes are registered.
func (p *Proxy) routeDoH(mux *http.ServeMux) {
	routes := p.HTTPConfig.Routes
	if len(routes) == 0 {
		mux.Handle(routePatternRootGet, p)
		mux.Handle(routePatternRootPost, p)
		mux.Handle(routePatternDNSQueryGet, p)
		mux.Handle(routePatternDNSQueryPost, p)

		return
	}

	for _, route := range routes {
		mux.Handle(route, p)
	}
}
