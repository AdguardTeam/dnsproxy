package bootstrap_test

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is a common timeout used in tests of this package.
const testTimeout = 1 * time.Second

// newListener creates a new listener of zero address of the specified network
// type and returns it, adding it's closing to the test cleanup.  sig is used to
// send the address of each accepted connection and must be read properly.
func newListener(t testing.TB, network string, sig chan net.Addr) (ipp netip.AddrPort) {
	t.Helper()

	// TODO(e.burkov):  Listen IPv6 as well, when the CI adds IPv6 interfaces.
	l, err := net.Listen(network, "127.0.0.1:0")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, l.Close)

	go func() {
		pt := testutil.PanicT{}
		for c, lerr := l.Accept(); !errors.Is(lerr, net.ErrClosed); c, lerr = l.Accept() {
			require.NoError(pt, lerr)

			testutil.RequireSend(pt, sig, c.LocalAddr(), testTimeout)

			require.NoError(pt, c.Close())
		}
	}()

	ipp, err = netip.ParseAddrPort(l.Addr().String())
	require.NoError(t, err)

	return ipp
}

// See the details here: https://github.com/AdguardTeam/dnsproxy/issues/18
func TestResolveDialContext(t *testing.T) {
	sig := make(chan net.Addr, 1)

	ipp := newListener(t, "tcp", sig)
	port := ipp.Port()

	testCases := []struct {
		name       string
		addresses  []netip.Addr
		preferIPv6 bool
	}{{
		name:       "v4",
		addresses:  []netip.Addr{netutil.IPv4Localhost()},
		preferIPv6: false,
	}, {
		name:       "both_prefer_v6",
		addresses:  []netip.Addr{netutil.IPv4Localhost(), netutil.IPv6Localhost()},
		preferIPv6: true,
	}, {
		name:       "both_prefer_v4",
		addresses:  []netip.Addr{netutil.IPv6Localhost(), netutil.IPv4Localhost()},
		preferIPv6: false,
	}, {
		name:       "strip_invalid",
		addresses:  []netip.Addr{{}, netutil.IPv4Localhost(), {}, netutil.IPv6Localhost(), {}},
		preferIPv6: true,
	}}

	const hostname = "host.name"

	pt := testutil.PanicT{}

	for _, tc := range testCases {
		r := &testResolver{
			onLookupNetIP: func(
				_ context.Context,
				network string,
				host string,
			) (addrs []netip.Addr, err error) {
				require.Equal(pt, "ip", network)
				require.Equal(pt, hostname, host)

				return tc.addresses, nil
			},
		}

		t.Run(tc.name, func(t *testing.T) {
			dialContext, err := bootstrap.ResolveDialContext(
				&url.URL{Host: netutil.JoinHostPort(hostname, port)},
				testTimeout,
				bootstrap.ParallelResolver{r},
				tc.preferIPv6,
			)
			require.NoError(t, err)

			conn, err := dialContext(context.Background(), "tcp", "")
			require.NoError(t, err)

			expected, ok := testutil.RequireReceive(t, sig, testTimeout)
			require.True(t, ok)

			assert.Equal(t, expected.String(), conn.RemoteAddr().String())
		})
	}

	t.Run("no_addresses", func(t *testing.T) {
		r := &testResolver{
			onLookupNetIP: func(
				_ context.Context,
				network string,
				host string,
			) (addrs []netip.Addr, err error) {
				require.Equal(pt, "ip", network)
				require.Equal(pt, hostname, host)

				return nil, nil
			},
		}

		dialContext, err := bootstrap.ResolveDialContext(
			&url.URL{Host: netutil.JoinHostPort(hostname, port)},
			testTimeout,
			bootstrap.ParallelResolver{r},
			false,
		)
		require.NoError(t, err)

		_, err = dialContext(context.Background(), "tcp", "")
		testutil.AssertErrorMsg(t, "no addresses", err)
	})

	t.Run("bad_hostname", func(t *testing.T) {
		const errMsg = `dialing "bad hostname": address bad hostname: ` +
			`missing port in address`

		dialContext, err := bootstrap.ResolveDialContext(
			&url.URL{Host: "bad hostname"},
			testTimeout,
			nil,
			false,
		)
		testutil.AssertErrorMsg(t, errMsg, err)

		assert.Nil(t, dialContext)
	})

	t.Run("no_resolvers", func(t *testing.T) {
		dialContext, err := bootstrap.ResolveDialContext(
			&url.URL{Host: netutil.JoinHostPort(hostname, port)},
			testTimeout,
			nil,
			false,
		)
		assert.ErrorIs(t, err, bootstrap.ErrNoResolvers)
		assert.Nil(t, dialContext)
	})
}
