package proxy

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBeforeRequestHandler is a mock before request handler implementation to
// simplify testing.
type testBeforeRequestHandler struct {
	onHandleBefore func(p *Proxy, dctx *DNSContext) (err error)
}

// type check
var _ BeforeRequestHandler = (*testBeforeRequestHandler)(nil)

// HandleBefore implements the [BeforeRequestHandler] interface for
// *testBeforeRequestHandler.
func (h *testBeforeRequestHandler) HandleBefore(p *Proxy, dctx *DNSContext) (err error) {
	return h.onHandleBefore(p, dctx)
}

func TestProxy_HandleDNSRequest_beforeRequestHandler(t *testing.T) {
	t.Parallel()

	const (
		allowedID = iota
		droppedID
		errorID
	)

	allowedRequest := (&dns.Msg{}).SetQuestion("allowed.", dns.TypeA)
	allowedRequest.Id = allowedID
	allowedResponse := (&dns.Msg{}).SetReply(allowedRequest)

	droppedRequest := (&dns.Msg{}).SetQuestion("dropped.", dns.TypeA)
	droppedRequest.Id = droppedID

	errorRequest := (&dns.Msg{}).SetQuestion("error.", dns.TypeA)
	errorRequest.Id = errorID
	errorResponse := (&dns.Msg{}).SetReply(errorRequest)

	p := mustNew(t, &Config{
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{&fakeUpstream{
				onExchange: func(m *dns.Msg) (resp *dns.Msg, err error) {
					return allowedResponse.Copy(), nil
				},
				onAddress: func() (addr string) { return "general" },
				onClose:   func() (err error) { return nil },
			}},
		},
		TrustedProxies: defaultTrustedProxies,
		PrivateSubnets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
		BeforeRequestHandler: &testBeforeRequestHandler{
			onHandleBefore: func(p *Proxy, dctx *DNSContext) (err error) {
				switch dctx.Req.Id {
				case allowedID:
					return nil
				case droppedID:
					return errors.Error("just drop")
				case errorID:
					return &BeforeRequestError{
						Err:      errors.Error("just error"),
						Response: errorResponse,
					}
				default:
					panic(fmt.Sprintf("unexpected request id: %d", dctx.Req.Id))
				}
			},
		},
	})
	ctx := context.Background()
	require.NoError(t, p.Start(ctx))
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return p.Shutdown(ctx) })

	client := &dns.Client{
		Net:     string(ProtoTCP),
		Timeout: 200 * time.Millisecond,
	}
	addr := p.Addr(ProtoTCP).String()

	t.Run("allowed", func(t *testing.T) {
		t.Parallel()

		resp, _, err := client.Exchange(allowedRequest, addr)
		require.NoError(t, err)
		assert.Equal(t, allowedResponse, resp)
	})

	t.Run("dropped", func(t *testing.T) {
		t.Parallel()

		resp, _, err := client.Exchange(droppedRequest, addr)

		wantErr := &net.OpError{}
		require.ErrorAs(t, err, &wantErr)
		assert.True(t, wantErr.Timeout())

		assert.Nil(t, resp)
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()

		resp, _, err := client.Exchange(errorRequest, addr)
		require.NoError(t, err)
		assert.Equal(t, errorResponse, resp)
	})
}
