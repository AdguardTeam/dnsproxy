package dnsproxytest

import (
	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
)

// Upstream is a mock [upstream.Upstream] implementation for tests.
//
// TODO(e.burkov):  Move to golibs.
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

// MessageConstructor is a mock [dnsmsg.MessageConstructor] implementation for
// tests.
type MessageConstructor struct {
	OnNewMsgNXDOMAIN       func(req *dns.Msg) (resp *dns.Msg)
	OnNewMsgSERVFAIL       func(req *dns.Msg) (resp *dns.Msg)
	OnNewMsgNOTIMPLEMENTED func(req *dns.Msg) (resp *dns.Msg)
	OnNewMsgNODATA         func(req *dns.Msg) (resp *dns.Msg)
}

// NewMessageConstructor creates a new *TestMessageConstructor with all it's
// methods set to panic.
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
	}
}

// type check
var _ dnsmsg.MessageConstructor = (*MessageConstructor)(nil)

// NewMsgNXDOMAIN implements the [proxy.MessageConstructor] interface for
// *TestMessageConstructor.
func (c *MessageConstructor) NewMsgNXDOMAIN(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNXDOMAIN(req)
}

// NewMsgSERVFAIL implements the [proxy.MessageConstructor] interface for
// *TestMessageConstructor.
func (c *MessageConstructor) NewMsgSERVFAIL(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgSERVFAIL(req)
}

// NewMsgNOTIMPLEMENTED implements the [proxy.MessageConstructor] interface for
// *TestMessageConstructor.
func (c *MessageConstructor) NewMsgNOTIMPLEMENTED(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNOTIMPLEMENTED(req)
}

// NewMsgNODATA implements the [MessageConstructor] interface for
// *TestMessageConstructor.
func (c *MessageConstructor) NewMsgNODATA(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNODATA(req)
}
