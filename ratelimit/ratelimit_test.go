package ratelimit_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/ratelimit"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Subnet lengths used in tests.
const (
	testSubnetLenIPv4 = 24
	testSubnetLenIPv6 = 64
)

// testLogger is a test logger used in tests.
var testLogger = slogutil.NewDiscardLogger()

func TestMiddleware_Wrap(t *testing.T) {
	t.Parallel()

	testAddr := netip.MustParseAddrPort("192.0.2.0:53")

	testCases := []struct {
		config  *ratelimit.Config
		dctx    *proxy.DNSContext
		wantErr error
		name    string
		want    int
	}{{
		name: "tcp_not_ratelimited",
		config: &ratelimit.Config{
			Logger:        testLogger,
			Ratelimit:     1,
			SubnetLenIPv4: testSubnetLenIPv4,
			SubnetLenIPv6: testSubnetLenIPv6,
		},
		dctx: &proxy.DNSContext{
			Addr:  testAddr,
			Proto: proxy.ProtoTCP,
		},
		want:    2,
		wantErr: nil,
	}, {
		name: "ratelimited",
		config: &ratelimit.Config{
			Logger:        testLogger,
			Ratelimit:     1,
			SubnetLenIPv4: testSubnetLenIPv4,
			SubnetLenIPv6: testSubnetLenIPv6,
		},
		dctx: &proxy.DNSContext{
			Addr:  testAddr,
			Proto: proxy.ProtoUDP,
		},
		want:    1,
		wantErr: proxy.ErrDrop,
	}}

	for _, tc := range testCases {
		called := 0
		mock := &TestHandler{
			OnHandle: func(p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
				called++

				return nil
			},
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mw := ratelimit.NewMiddleware(tc.config)
			wrapped := mw.Wrap(mock)

			err := wrapped.ServeDNS(nil, tc.dctx)
			require.NoError(t, err, "first request should not be ratelimited")

			err = wrapped.ServeDNS(nil, tc.dctx)
			assert.Equal(t, tc.wantErr, err)

			assert.Equal(t, tc.want, called)
		})
	}
}

func TestMiddleware_Wrap_allowlist(t *testing.T) {
	t.Parallel()

	var (
		addrAllow     = netip.MustParseAddr("192.0.2.0")
		addrPortAllow = netip.AddrPortFrom(addrAllow, 53)
		addrPortDrop  = netip.MustParseAddrPort("192.0.2.1:53")
	)

	conf := &ratelimit.Config{
		Logger:        testLogger,
		Ratelimit:     1,
		SubnetLenIPv4: testSubnetLenIPv4,
		SubnetLenIPv6: testSubnetLenIPv6,
		AllowlistAddrs: netutil.SliceSubnetSet{
			netip.PrefixFrom(addrAllow, netutil.IPv4BitLen),
		},
	}

	called := 0
	mock := &TestHandler{
		OnHandle: func(p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
			called++

			return nil
		},
	}
	mw := ratelimit.NewMiddleware(conf)
	handler := mw.Wrap(mock)

	t.Run("block", func(t *testing.T) {
		dctx := &proxy.DNSContext{
			Addr:  addrPortDrop,
			Proto: proxy.ProtoUDP,
		}

		err := handler.ServeDNS(nil, dctx)
		require.NoError(t, err, "first request should not be ratelimited")

		err = handler.ServeDNS(nil, dctx)
		require.Error(t, err, "second request should be ratelimited")
		assert.Equal(t, proxy.ErrDrop, err)

		assert.Equal(t, 1, called)
	})

	t.Run("allow", func(t *testing.T) {
		dctx := &proxy.DNSContext{
			Addr:  addrPortAllow,
			Proto: proxy.ProtoUDP,
		}

		err := handler.ServeDNS(nil, dctx)
		require.NoError(t, err, "first request should not be ratelimited")

		err = handler.ServeDNS(nil, dctx)
		require.NoError(t, err, "second request should not be ratelimited due to whitelist")

		assert.Equal(t, 3, called)
	})
}

// TestHandler is a mock request middleware implementation to simplify testing.
//
// TODO(d.kolyshev):  Move to internal/dnsproxytest.
type TestHandler struct {
	OnHandle func(p *proxy.Proxy, dctx *proxy.DNSContext) (err error)
}

// type check
var _ proxy.Handler = (*TestHandler)(nil)

// ServeDNS implements the [Handler] interface for *TestHandler.
func (h *TestHandler) ServeDNS(p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
	return h.OnHandle(p, dctx)
}
