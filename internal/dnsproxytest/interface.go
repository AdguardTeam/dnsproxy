package dnsproxytest

import (
	"github.com/miekg/dns"
)

// FakeUpstream is a fake [Upstream] implementation for tests.
//
// TODO(e.burkov):  Move this to the golibs?
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
