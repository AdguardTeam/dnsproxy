// Package handler provides some customizable DNS request handling logic used in
// the proxy.
package handler

import (
	"context"
	"io/fs"
	"log/slog"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/hostsfile"
)

// DefaultConfig is the configuration for [Default].
type DefaultConfig struct {
	// MessageConstructor constructs DNS messages.  It must not be nil.
	MessageConstructor proxy.MessageConstructor

	// FileSystem is the file system for reading files from.  It must not be
	// nil.
	FileSystem fs.FS

	// Logger is the logger.  It must not be nil.
	Logger *slog.Logger

	// HostsFiles is the list of paths to the hosts files.  The hosts files
	// aren't used if the list is empty.
	//
	// TODO(e.burkov):  Consider passing just a [hostsfile.Storage].
	HostsFiles []string

	// HaltIPv6 halts the processing of AAAA requests and makes the handler
	// reply with NODATA to them.
	HaltIPv6 bool
}

// Default implements the default configurable [proxy.RequestHandler].
type Default struct {
	messages     messageConstructor
	hosts        hostsfile.Storage
	logger       *slog.Logger
	isIPv6Halted bool
}

// NewDefault creates a new [Default] handler.
func NewDefault(conf *DefaultConfig) (d *Default, err error) {
	hosts, err := readHosts(conf.FileSystem, conf.HostsFiles)
	if err != nil {
		return nil, err
	}

	mc, ok := conf.MessageConstructor.(messageConstructor)
	if !ok {
		mc = defaultConstructor{
			MessageConstructor: conf.MessageConstructor,
		}
	}

	return &Default{
		logger:       conf.Logger,
		isIPv6Halted: conf.HaltIPv6,
		messages:     mc,
		hosts:        hosts,
	}, nil
}

// HandleRequest resolves the DNS request within proxyCtx.  It only calls
// [proxy.Proxy.Resolve] if the request isn't handled by any of the internal
// handlers.
func (h *Default) HandleRequest(p *proxy.Proxy, proxyCtx *proxy.DNSContext) (err error) {
	// TODO(e.burkov):  Use the [*context.Context] instead of
	// [*proxy.DNSContext] when the interface-based handler is implemented.
	ctx := context.TODO()

	h.logger.DebugContext(ctx, "handling request", "req", &proxyCtx.Req.Question[0])

	if proxyCtx.Res = h.haltAAAA(ctx, proxyCtx.Req); proxyCtx.Res != nil {
		return nil
	}

	if proxyCtx.Res = h.resolveFromHosts(ctx, proxyCtx.Req); proxyCtx.Res != nil {
		return nil
	}

	return p.Resolve(proxyCtx)
}
