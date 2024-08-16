// Package handler provides some customizable DNS request handling logic used in
// the proxy.
package handler

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/miekg/dns"
)

// DefaultConfig is the configuration for [Default].
type DefaultConfig struct {
	// Logger is the logger.  It must not be nil.
	Logger *slog.Logger

	// MessageConstructor constructs DNS messages.  It must not be nil.
	MessageConstructor proxy.MessageConstructor

	// HaltIPv6 halts the processing of AAAA requests and makes the handler
	// reply with NODATA to them.
	HaltIPv6 bool
}

// Default implements the default configurable [proxy.RequestHandler].
type Default struct {
	logger             *slog.Logger
	messageConstructor proxy.MessageConstructor
	isIPv6Halted       bool
}

// NewDefault creates a new [Default] handler.
func NewDefault(conf *DefaultConfig) (d *Default) {
	return &Default{
		logger:             conf.Logger,
		isIPv6Halted:       conf.HaltIPv6,
		messageConstructor: conf.MessageConstructor,
	}
}

// HandleRequest checks the IPv6 configuration for current session before
// resolving.
func (h Default) HandleRequest(p *proxy.Proxy, proxyCtx *proxy.DNSContext) (err error) {
	// TODO(e.burkov):  Use the [*context.Context] instead of
	// [*proxy.DNSContext] when the interface-based handler is implemented.
	ctx := context.TODO()

	if proxyCtx.Res = h.haltAAAA(ctx, proxyCtx.Req); proxyCtx.Res != nil {
		return nil
	}

	return p.Resolve(proxyCtx)
}

// haltAAAA halts the processing of AAAA requests if IPv6 is disabled.  req must
// not be nil.
func (h *Default) haltAAAA(ctx context.Context, req *dns.Msg) (resp *dns.Msg) {
	if h.isIPv6Halted && req.Question[0].Qtype == dns.TypeAAAA {
		h.logger.DebugContext(
			ctx,
			"ipv6 is disabled; replying with empty response",
			"req", req.Question[0].Name,
		)

		return h.messageConstructor.NewMsgNODATA(req)
	}

	return nil
}
