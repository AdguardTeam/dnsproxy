package handler

import (
	"context"

	"github.com/miekg/dns"
)

// haltA halts the processing of A requests if IPv4 is disabled.  req must
// not be nil.
func (h *Default) haltA(ctx context.Context, req *dns.Msg) (resp *dns.Msg) {
	if h.isIPv4Halted && req.Question[0].Qtype == dns.TypeA {
		h.logger.DebugContext(
			ctx,
			"ipv4 is disabled; replying with empty response",
			"req", req.Question[0].Name,
		)

		return h.messages.NewMsgNODATA(req)
	}

	return nil
}
