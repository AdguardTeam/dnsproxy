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

// NewMsgSERVFAIL implements the [MessageConstructor] interface for
// defaultMessageConstructor.
func (c defaultMessageConstructor) NewMsgSERVFAIL(req *dns.Msg) (resp *dns.Msg) {
	return c.reply(req, dns.RcodeServerFailure)
}

// NewMsgNOTIMPLEMENTED implements the [MessageConstructor] interface for
// defaultMessageConstructor.
func (c defaultMessageConstructor) NewMsgNOTIMPLEMENTED(req *dns.Msg) (resp *dns.Msg) {
	resp = c.reply(req, dns.RcodeNotImplemented)
	// NOTIMPLEMENTED without EDNS is treated as 'we don't support EDNS', so
	// explicitly set it.
	resp.SetEdns0(1452, false)

	return resp
}

// NewMsgNXDOMAIN implements the [MessageConstructor] interface for
// defaultMessageConstructor.
func (c defaultMessageConstructor) NewMsgNXDOMAIN(req *dns.Msg) (resp *dns.Msg) {
	resp = c.reply(req, dns.RcodeNameError)

	return resp
}

// reply creates a new response message replying to req with the given code.
func (defaultMessageConstructor) reply(req *dns.Msg, code int) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetRcode(req, code)
	resp.RecursionAvailable = true

	return resp
}
