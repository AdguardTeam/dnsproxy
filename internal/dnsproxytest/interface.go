package dnsproxytest

import (
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
)

// Upstream is a fake [proxy.Upstream] implementation for tests.
//
// TODO(e.burkov):  Move this to the golibs some time later.
type Upstream struct {
	OnAddress  func() (addr string)
	OnExchange func(req *dns.Msg) (resp *dns.Msg, err error)
	OnClose    func() (err error)
}

// Address implements the [proxy.Upstream] interface for *FakeUpstream.
func (u *Upstream) Address() (addr string) {
	return u.OnAddress()
}

// Exchange implements the [proxy.Upstream] interface for *FakeUpstream.
func (u *Upstream) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	return u.OnExchange(req)
}

// Close implements the [proxy.Upstream] interface for *FakeUpstream.
func (u *Upstream) Close() (err error) {
	return u.OnClose()
}

// TestMessageConstructor is a fake [proxy.MessageConstructor] implementation
// for tests.
type TestMessageConstructor struct {
	OnNewMsgNXDOMAIN       func(req *dns.Msg) (resp *dns.Msg)
	OnNewMsgSERVFAIL       func(req *dns.Msg) (resp *dns.Msg)
	OnNewMsgNOTIMPLEMENTED func(req *dns.Msg) (resp *dns.Msg)
	OnNewMsgNODATA         func(req *dns.Msg) (resp *dns.Msg)
}

// NewTestMessageConstructor creates a new *TestMessageConstructor with all it's
// methods set to panic.
func NewTestMessageConstructor() (c *TestMessageConstructor) {
	return &TestMessageConstructor{
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

// NewMsgNXDOMAIN implements the [proxy.MessageConstructor] interface for
// *TestMessageConstructor.
func (c *TestMessageConstructor) NewMsgNXDOMAIN(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNXDOMAIN(req)
}

// NewMsgSERVFAIL implements the [proxy.MessageConstructor] interface for
// *TestMessageConstructor.
func (c *TestMessageConstructor) NewMsgSERVFAIL(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgSERVFAIL(req)
}

// NewMsgNOTIMPLEMENTED implements the [proxy.MessageConstructor] interface for
// *TestMessageConstructor.
func (c *TestMessageConstructor) NewMsgNOTIMPLEMENTED(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNOTIMPLEMENTED(req)
}

// NewMsgNODATA implements the [MessageConstructor] interface for
// *TestMessageConstructor.
func (c *TestMessageConstructor) NewMsgNODATA(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNODATA(req)
}
