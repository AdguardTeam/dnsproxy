// Package middleware provides some customizable DNS request handling logic used
// in the proxy.
package middleware

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/hostsfile"
)

// Config is the configuration for [Default].
type Config struct {
	// HostsFiles is the index containing the records of the hosts files.  It
	// must not be nil.
	HostsFiles hostsfile.Storage

	// Logger is the logger.  It must not be nil.
	Logger *slog.Logger

	// MessageConstructor constructs DNS messages.  It must not be nil.
	MessageConstructor proxy.MessageConstructor

	// HaltIPv6 halts the processing of AAAA requests and makes the handler
	// reply with NODATA to them, if true.
	HaltIPv6 bool
}

// Default implements [proxy.Middleware] with default DNS request handling
// logic.
type Default struct {
	hosts    hostsfile.Storage
	logger   *slog.Logger
	messages messageConstructor
	haltIPv6 bool
}

// New creates a new [*Default].
func New(conf *Config) (mw *Default) {
	mc, ok := conf.MessageConstructor.(messageConstructor)
	if !ok {
		mc = defaultConstructor{
			MessageConstructor: conf.MessageConstructor,
		}
	}

	return &Default{
		hosts:    conf.HostsFiles,
		logger:   conf.Logger,
		messages: mc,
		haltIPv6: conf.HaltIPv6,
	}
}

// type check
var _ proxy.Middleware = (*Default)(nil)

// Wrap implements the [proxy.Middleware] interface for *Default.  It validates
// and resolves the DNS request within proxyCtx.  It only calls h if the request
// isn't handled by any of the internal handlers.
func (mw *Default) Wrap(h proxy.Handler) (wrapped proxy.Handler) {
	f := func(p *proxy.Proxy, proxyCtx *proxy.DNSContext) (err error) {
		ctx := context.TODO()

		mw.logger.DebugContext(ctx, "handling request", "req", &proxyCtx.Req.Question[0])

		if proxyCtx.Res = mw.haltAAAA(ctx, proxyCtx.Req); proxyCtx.Res != nil {
			return nil
		}

		if proxyCtx.Res = mw.resolveFromHosts(ctx, proxyCtx.Req); proxyCtx.Res != nil {
			return nil
		}

		return h.ServeDNS(p, proxyCtx)
	}

	return proxy.HandlerFunc(f)
}
