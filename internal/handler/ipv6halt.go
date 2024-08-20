package handler

import (
	"context"

	"github.com/miekg/dns"
)

// haltAAAA halts the processing of AAAA requests if IPv6 is disabled.  req must
// not be nil.
func (h *Default) haltAAAA(ctx context.Context, req *dns.Msg) (resp *dns.Msg) {
	if h.isIPv6Halted && req.Question[0].Qtype == dns.TypeAAAA {
		h.logger.DebugContext(
			ctx,
			"ipv6 is disabled; replying with empty response",
			"req", req.Question[0].Name,
		)

		return h.messages.NewMsgNODATA(req)
	}

	return nil
}
