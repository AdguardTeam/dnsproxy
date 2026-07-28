package middleware

import (
	"context"

	"github.com/miekg/dns"
)

// haltAAAA halts the processing of AAAA requests if IPv6 is disabled.  req must
// not be nil.
func (mw *Default) haltAAAA(ctx context.Context, req *dns.Msg) (resp *dns.Msg) {
	if mw.haltIPv6 && req.Question[0].Qtype == dns.TypeAAAA {
		mw.logger.DebugContext(
			ctx,
			"ipv6 is disabled; replying with empty response",
			"req", req.Question[0].Name,
		)

		return mw.messages.NewMsgNODATA(req)
	}

	return nil
}
