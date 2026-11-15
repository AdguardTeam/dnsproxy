package proxy

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPendingRequests_preservesRcode(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		rcode int
	}{{
		name:  "nxdomain",
		rcode: dns.RcodeNameError,
	}, {
		name:  "servfail",
		rcode: dns.RcodeServerFailure,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pr := newDefaultPendingRequests()

			leaderReq := (&dns.Msg{}).SetQuestion("does-not-exist.example.", dns.TypeA)
			leaderResp := (&dns.Msg{}).SetRcode(leaderReq, tc.rcode)
			leaderResp.Ns = []dns.RR{&dns.SOA{
				Hdr: dns.RR_Header{
					Name:   "example.",
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Ns:   "ns.example.",
				Mbox: "hostmaster.example.",
			}}

			key := string(msgToKey(leaderReq))
			finish := make(chan struct{})
			close(finish)
			pr.storage.LoadOrStore(key, &pendingRequest{
				finish: finish,
				cloneDNSCtx: &DNSContext{
					Res: leaderResp,
				},
			})

			waiterReq := leaderReq.Copy()
			waiterReq.Id = 42
			waiter := &DNSContext{
				Req: waiterReq,
			}

			loaded, err := pr.queue(context.Background(), waiter)
			require.NoError(t, err)
			require.True(t, loaded)
			require.NotNil(t, waiter.Res)

			assert.Equal(t, tc.rcode, waiter.Res.Rcode)
			assert.Equal(t, waiterReq.Id, waiter.Res.Id)
			assert.Equal(t, waiterReq.Question, waiter.Res.Question)
			require.Len(t, waiter.Res.Ns, 1)
			assert.Equal(t, dns.TypeSOA, waiter.Res.Ns[0].Header().Rrtype)
		})
	}
}
