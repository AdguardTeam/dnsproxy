package proxy

import (
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// BeforeRequestError is an error that signals that the request should be
// responded with the given response message.
type BeforeRequestError struct {
	// Err is the error that caused the response.  It must not be nil.
	Err error

	// Response is the response message to be sent to the client.  It must be a
	// valid response message.
	Response *dns.Msg
}

// type check
var _ error = (*BeforeRequestError)(nil)

// Error implements the [error] interface for *BeforeRequestError.
func (e *BeforeRequestError) Error() (msg string) {
	return fmt.Sprintf("%s; respond with %s", e.Err, dns.RcodeToString[e.Response.Rcode])
}

// type check
var _ errors.Wrapper = (*BeforeRequestError)(nil)

// Unwrap implements the [errors.Wrapper] interface for *BeforeRequestError.
func (e *BeforeRequestError) Unwrap() (unwrapped error) {
	return e.Err
}

// BeforeRequestHandler is an object that can handle the request before it's
// processed by [Proxy].
type BeforeRequestHandler interface {
	// HandleBefore is called before each DNS request is started processing.
	// The passed [DNSContext] contains the Req, Addr, and IsLocalClient fields
	// set accordingly.
	//
	// If returned err is a [BeforeRequestError], the given response message is
	// used.  If err is nil, the request is processed further.  [Proxy] assumes
	// a handler itself doesn't set the [DNSContext.Res] field.
	HandleBefore(p *Proxy, dctx *DNSContext) (err error)
}

// noopRequestHandler is a no-op implementation of [BeforeRequestHandler] that
// always returns nil.
type noopRequestHandler struct{}

// type check
var _ BeforeRequestHandler = noopRequestHandler{}

// HandleBefore implements the [BeforeRequestHandler] interface for
// noopRequestHandler.
func (noopRequestHandler) HandleBefore(_ *Proxy, _ *DNSContext) (err error) {
	return nil
}

// handleBefore calls the [BeforeRequestHandler] if it's set.  If the returned
// error is nil, it returns true and the request is processed further.  If the
// returned error has type [BeforeRequestError], the specified response is sent
// to the client.  Otherwise, the request just ignored.
func (p *Proxy) handleBefore(d *DNSContext) (cont bool) {
	err := p.beforeRequestHandler.HandleBefore(p, d)
	if err == nil {
		return true
	}

	p.logger.Debug("handling before request", slogutil.KeyError, err)

	if befReqErr := (&BeforeRequestError{}); errors.As(err, &befReqErr) {
		d.Res = befReqErr.Response

		p.logDNSMessage(d.Res)
		p.respond(d)
	}

	return false
}
