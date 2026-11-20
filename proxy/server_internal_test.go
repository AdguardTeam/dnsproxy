package proxy

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestProxy_logDNSMessage_noDebug(t *testing.T) {
	p := &Proxy{
		logger: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	}

	req := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeA)
	resp := (&dns.Msg{}).SetReply(req)
	ctx := context.Background()

	allocs := testing.AllocsPerRun(100, func() {
		p.logDNSMessage(ctx, req)
		p.logDNSMessage(ctx, resp)
	})

	assert.Zero(t, allocs)
}
