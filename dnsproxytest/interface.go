package dnsproxytest

import (
	"context"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
)

// Upstream is a mock [upstream.Upstream] implementation for tests.
type Upstream struct {
	OnAddress  func() (addr string)
	OnExchange func(req *dns.Msg) (resp *dns.Msg, err error)
	OnClose    func() (err error)
}

// type check
var _ upstream.Upstream = (*Upstream)(nil)

// Address implements the [upstream.Upstream] interface for *Upstream.
func (u *Upstream) Address() (addr string) {
	return u.OnAddress()
}

// Exchange implements the [upstream.Upstream] interface for *Upstream.
func (u *Upstream) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	return u.OnExchange(req)
}

// Close implements the [upstream.Upstream] interface for *Upstream.
func (u *Upstream) Close() (err error) {
	return u.OnClose()
}

// Handler is a mock [proxy.Handler] implementation for tests.
type Handler struct {
	OnHandle func(ctx context.Context, p *proxy.Proxy, dctx *proxy.DNSContext) (err error)
}

// type check
var _ proxy.Handler = (*Handler)(nil)

// ServeDNS implements the [proxy.Handler] interface for *Handler.
func (h *Handler) ServeDNS(ctx context.Context, p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
	return h.OnHandle(ctx, p, dctx)
}

// Middleware is a mock [proxy.Middleware] implementation for tests.
type Middleware struct {
	OnWrap func(h proxy.Handler) (wrapped proxy.Handler)
}

// type check
var _ proxy.Middleware = (*Middleware)(nil)

// Wrap implements the [proxy.Middleware] interface for *Middleware.
func (m *Middleware) Wrap(h proxy.Handler) (wrapped proxy.Handler) {
	return m.OnWrap(h)
}

// QUICTracer is a mock [upstream.QUICTracer] implementation for tests.
type QUICTracer struct {
	OnTraceForConnection func(
		ctx context.Context,
		isClient bool,
		connID quic.ConnectionID,
	) (trace qlogwriter.Trace)
}

// type check
var _ upstream.QUICTracer = (*QUICTracer)(nil)

// TraceForConnection implements the [upstream.QUICTracer] interface for
// *QUICTracer.
func (t *QUICTracer) TraceForConnection(
	ctx context.Context,
	isClient bool,
	connID quic.ConnectionID,
) (trace qlogwriter.Trace) {
	return t.OnTraceForConnection(ctx, isClient, connID)
}

// MessageConstructor is a mock [proxy.MessageConstructor] implementation for
// tests.
type MessageConstructor struct {
	OnNewMsgNXDOMAIN       func(req *dns.Msg) (resp *dns.Msg)
	OnNewMsgSERVFAIL       func(req *dns.Msg) (resp *dns.Msg)
	OnNewMsgNOTIMPLEMENTED func(req *dns.Msg) (resp *dns.Msg)
	OnNewMsgNODATA         func(req *dns.Msg) (resp *dns.Msg)
	OnNewMsgFORMERR        func(req *dns.Msg) (resp *dns.Msg)
}

// NewMessageConstructor creates a new *MessageConstructor with all its methods
// set to panic.
func NewMessageConstructor() (c *MessageConstructor) {
	return &MessageConstructor{
		OnNewMsgNXDOMAIN: func(req *dns.Msg) (_ *dns.Msg) {
			panic(testutil.UnexpectedCall(req))
		},
		OnNewMsgSERVFAIL: func(req *dns.Msg) (_ *dns.Msg) {
			panic(testutil.UnexpectedCall(req))
		},
		OnNewMsgNOTIMPLEMENTED: func(req *dns.Msg) (_ *dns.Msg) {
			panic(testutil.UnexpectedCall(req))
		},
		OnNewMsgNODATA: func(req *dns.Msg) (_ *dns.Msg) {
			panic(testutil.UnexpectedCall(req))
		},
		OnNewMsgFORMERR: func(req *dns.Msg) (_ *dns.Msg) {
			panic(testutil.UnexpectedCall(req))
		},
	}
}

// type check
var _ proxy.MessageConstructor = (*MessageConstructor)(nil)

// NewMsgNXDOMAIN implements the [proxy.MessageConstructor] interface for
// *MessageConstructor.
func (c *MessageConstructor) NewMsgNXDOMAIN(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNXDOMAIN(req)
}

// NewMsgSERVFAIL implements the [proxy.MessageConstructor] interface for
// *MessageConstructor.
func (c *MessageConstructor) NewMsgSERVFAIL(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgSERVFAIL(req)
}

// NewMsgNOTIMPLEMENTED implements the [proxy.MessageConstructor] interface for
// *MessageConstructor.
func (c *MessageConstructor) NewMsgNOTIMPLEMENTED(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNOTIMPLEMENTED(req)
}

// NewMsgNODATA implements the [proxy.MessageConstructor] interface for
// *MessageConstructor.
func (c *MessageConstructor) NewMsgNODATA(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNODATA(req)
}

// NewMsgFORMERR implements the [proxy.MessageConstructor] interface for
// *MessageConstructor.
func (c *MessageConstructor) NewMsgFORMERR(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgFORMERR(req)
}
