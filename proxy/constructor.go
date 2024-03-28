package proxy

import "github.com/miekg/dns"

// MessageConstructor creates DNS messages.
type MessageConstructor interface {
	// NewMsgNXDOMAIN creates a new response message replying to req with the
	// NXDOMAIN code.
	NewMsgNXDOMAIN(req *dns.Msg) (resp *dns.Msg)

	// NewMsgSERVFAIL creates a new response message replying to req with the
	// SERVFAIL code.
	NewMsgSERVFAIL(req *dns.Msg) (resp *dns.Msg)

	// NewMsgNOTIMPLEMENTED creates a new response message replying to req with
	// the NOTIMPLEMENTED code.
	NewMsgNOTIMPLEMENTED(req *dns.Msg) (resp *dns.Msg)
}

// defaultMessageConstructor is a default implementation of MessageConstructor.
type defaultMessageConstructor struct{}

// type check
var _ MessageConstructor = defaultMessageConstructor{}

// NewMsgNXDOMAIN implements the [MessageConstructor] interface for
// defaultMessageConstructor.
func (defaultMessageConstructor) NewMsgNXDOMAIN(req *dns.Msg) (resp *dns.Msg) {
	return reply(req, dns.RcodeNameError)
}

// NewMsgSERVFAIL implements the [MessageConstructor] interface for
// defaultMessageConstructor.
func (defaultMessageConstructor) NewMsgSERVFAIL(req *dns.Msg) (resp *dns.Msg) {
	return reply(req, dns.RcodeServerFailure)
}

// NewMsgNOTIMPLEMENTED implements the [MessageConstructor] interface for
// defaultMessageConstructor.
func (defaultMessageConstructor) NewMsgNOTIMPLEMENTED(req *dns.Msg) (resp *dns.Msg) {
	resp = reply(req, dns.RcodeNotImplemented)

	// Most of the Internet and especially the inner core has an MTU of at least
	// 1500 octets.  Maximum DNS/UDP payload size for IPv6 on MTU 1500 ethernet
	// is 1452 (1500 minus 40 (IPv6 header size) minus 8 (UDP header size)).
	//
	// See appendix A of https://datatracker.ietf.org/doc/draft-ietf-dnsop-avoid-fragmentation/17.
	const maxUDPPayload = 1452

	// NOTIMPLEMENTED without EDNS is treated as 'we don't support EDNS', so
	// explicitly set it.
	resp.SetEdns0(maxUDPPayload, false)

	return resp
}

// reply creates a new response message replying to req with the given code.
func reply(req *dns.Msg, code int) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetRcode(req, code)
	resp.RecursionAvailable = true

	return resp
}
