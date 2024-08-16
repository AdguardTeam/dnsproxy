package dnsproxytest

import (
	"github.com/miekg/dns"
)

// FakeUpstream is a fake [Upstream] implementation for tests.
//
// TODO(e.burkov):  Move this to the golibs some time later.
type FakeUpstream struct {
	OnAddress  func() (addr string)
	OnExchange func(req *dns.Msg) (resp *dns.Msg, err error)
	OnClose    func() (err error)
}

// Address implements the [Upstream] interface for *FakeUpstream.
func (u *FakeUpstream) Address() (addr string) {
	return u.OnAddress()
}

// Exchange implements the [Upstream] interface for *FakeUpstream.
func (u *FakeUpstream) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	return u.OnExchange(req)
}

// Close implements the [Upstream] interface for *FakeUpstream.
func (u *FakeUpstream) Close() (err error) {
	return u.OnClose()
}

// TestMessageConstructor is a fake [dnsmsg.MessageConstructor] implementation
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
		OnNewMsgNXDOMAIN: func(_ *dns.Msg) (_ *dns.Msg) {
			panic("unexpected call of TestMessageConstructor.NewMsgNXDOMAIN")
		},
		OnNewMsgSERVFAIL: func(_ *dns.Msg) (_ *dns.Msg) {
			panic("unexpected call of TestMessageConstructor.NewMsgSERVFAIL")
		},
		OnNewMsgNOTIMPLEMENTED: func(_ *dns.Msg) (_ *dns.Msg) {
			panic("unexpected call of TestMessageConstructor.NewMsgNOTIMPLEMENTED")
		},
		OnNewMsgNODATA: func(_ *dns.Msg) (_ *dns.Msg) {
			panic("unexpected call of TestMessageConstructor.NewMsgNODATA")
		},
	}
}

// NewMsgNXDOMAIN implements the [MessageConstructor] interface for
// *TestMessageConstructor.
func (c *TestMessageConstructor) NewMsgNXDOMAIN(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNXDOMAIN(req)
}

// NewMsgSERVFAIL implements the [MessageConstructor] interface for
// *TestMessageConstructor.
func (c *TestMessageConstructor) NewMsgSERVFAIL(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgSERVFAIL(req)
}

// NewMsgNOTIMPLEMENTED implements the [MessageConstructor] interface for
// *TestMessageConstructor.
func (c *TestMessageConstructor) NewMsgNOTIMPLEMENTED(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNOTIMPLEMENTED(req)
}

// NewMsgNODATA implements the [MessageConstructor] interface for
// *TestMessageConstructor.
func (c *TestMessageConstructor) NewMsgNODATA(req *dns.Msg) (resp *dns.Msg) {
	return c.OnNewMsgNODATA(req)
}
