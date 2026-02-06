package ratelimit_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/ratelimit"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Subnet lengths used in tests.
const (
	subnetLenIPv4 = 24
	subnetLenIPv6 = 64
)

// testLogger is a test logger used in tests.
var testLogger = slogutil.NewDiscardLogger()

func TestHandler_Handle(t *testing.T) {
	t.Parallel()

	testAddr := netip.MustParseAddrPort("192.0.2.0:53")

	testCases := []struct {
		config *ratelimit.Config
		dctx   *proxy.DNSContext
		want   error
		name   string
	}{{
		name: "disabled_ratelimit",
		config: &ratelimit.Config{
			Logger:        testLogger,
			Ratelimit:     0,
			SubnetLenIPv4: subnetLenIPv4,
			SubnetLenIPv6: subnetLenIPv6,
		},
		dctx: &proxy.DNSContext{
			Addr:  testAddr,
			Proto: proxy.ProtoUDP,
		},
		want: nil,
	}, {
		name: "tcp_not_ratelimited",
		config: &ratelimit.Config{
			Logger:        testLogger,
			Ratelimit:     1,
			SubnetLenIPv4: subnetLenIPv4,
			SubnetLenIPv6: subnetLenIPv6,
		},
		dctx: &proxy.DNSContext{
			Addr:  testAddr,
			Proto: proxy.ProtoTCP,
		},
		want: nil,
	}, {
		name: "ratelimited",
		config: &ratelimit.Config{
			Logger:        testLogger,
			Ratelimit:     1,
			SubnetLenIPv4: subnetLenIPv4,
			SubnetLenIPv6: subnetLenIPv6,
		},
		dctx: &proxy.DNSContext{
			Addr:  testAddr,
			Proto: proxy.ProtoUDP,
		},
		want: proxy.ErrDrop,
	}}

	mock := &TestRequestHandler{
		OnHandle: func(p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
			return nil
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wrapped := ratelimit.NewRatelimitedRequestHandler(mock, tc.config)

			err := wrapped.Handle(nil, tc.dctx)
			require.NoError(t, err, "first request should not be ratelimited")

			err = wrapped.Handle(nil, tc.dctx)
			assert.Equal(t, tc.want, err)
		})
	}
}

func TestHandler_Handle_allowlist(t *testing.T) {
	t.Parallel()

	var (
		addrAllow     = netip.MustParseAddr("192.0.2.0")
		addrPortAllow = netip.AddrPortFrom(addrAllow, 53)
		addrPortDrop  = netip.MustParseAddrPort("192.0.2.1:53")
	)

	conf := &ratelimit.Config{
		Logger:        testLogger,
		Ratelimit:     1,
		SubnetLenIPv4: subnetLenIPv4,
		SubnetLenIPv6: subnetLenIPv6,
		AllowlistAddrs: []netip.Addr{
			addrAllow,
		},
	}

	mock := &TestRequestHandler{
		OnHandle: func(p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
			return nil
		},
	}
	handler := ratelimit.NewRatelimitedRequestHandler(mock, conf)

	t.Run("block", func(t *testing.T) {
		dctx := &proxy.DNSContext{
			Addr:  addrPortDrop,
			Proto: proxy.ProtoUDP,
		}

		err := handler.Handle(nil, dctx)
		require.NoError(t, err, "first request should not be ratelimited")

		err = handler.Handle(nil, dctx)
		require.Error(t, err, "second request should be ratelimited")
		assert.Equal(t, proxy.ErrDrop, err)
	})

	t.Run("allow", func(t *testing.T) {
		dctx := &proxy.DNSContext{
			Addr:  addrPortAllow,
			Proto: proxy.ProtoUDP,
		}

		err := handler.Handle(nil, dctx)
		require.NoError(t, err, "first request should not be ratelimited")

		err = handler.Handle(nil, dctx)
		require.NoError(t, err, "second request should not be ratelimited due to whitelist")
	})
}

// TestRequestHandler is a mock request handler implementation to simplify
// testing.
//
// TODO(d.kolyshev):  Move to internal/dnsproxytest.
type TestRequestHandler struct {
	OnHandle func(p *proxy.Proxy, dctx *proxy.DNSContext) (err error)
}

// type check
var _ proxy.RequestHandler = (*TestRequestHandler)(nil)

// Handle implements the [RequestHandler] interface for *TestRequestHandler.
func (h *TestRequestHandler) Handle(p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
	return h.OnHandle(p, dctx)
}
