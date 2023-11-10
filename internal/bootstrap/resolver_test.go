package bootstrap_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testResolver is the [Resolver] interface implementation for testing purposes.
type testResolver struct {
	onLookupNetIP func(ctx context.Context, network, host string) (addrs []netip.Addr, err error)
}

// LookupNetIP implements the [Resolver] interface for *testResolver.
func (r *testResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) (addrs []netip.Addr, err error) {
	return r.onLookupNetIP(ctx, network, host)
}

func TestLookupParallel(t *testing.T) {
	const hostname = "host.name"

	t.Run("no_resolvers", func(t *testing.T) {
		addrs, err := bootstrap.ParallelResolver(nil).LookupNetIP(context.Background(), "ip", "")
		assert.ErrorIs(t, err, bootstrap.ErrNoResolvers)
		assert.Nil(t, addrs)
	})

	pt := testutil.PanicT{}
	hostAddrs := []netip.Addr{netutil.IPv4Localhost()}

	immediate := &testResolver{
		onLookupNetIP: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			require.Equal(pt, hostname, host)
			require.Equal(pt, "ip", network)

			return hostAddrs, nil
		},
	}

	t.Run("one_resolver", func(t *testing.T) {
		addrs, err := bootstrap.ParallelResolver{immediate}.LookupNetIP(
			context.Background(),
			"ip",
			hostname,
		)
		require.NoError(t, err)

		assert.Equal(t, hostAddrs, addrs)
	})

	t.Run("two_resolvers", func(t *testing.T) {
		delayCh := make(chan struct{}, 1)
		delayed := &testResolver{
			onLookupNetIP: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				require.Equal(pt, hostname, host)
				require.Equal(pt, "ip", network)

				testutil.RequireReceive(pt, delayCh, testTimeout)

				return []netip.Addr{netutil.IPv6Localhost()}, nil
			},
		}

		addrs, err := bootstrap.ParallelResolver{immediate, delayed}.LookupNetIP(
			context.Background(),
			"ip",
			hostname,
		)
		require.NoError(t, err)
		testutil.RequireSend(t, delayCh, struct{}{}, testTimeout)

		assert.Equal(t, hostAddrs, addrs)
	})

	t.Run("all_errors", func(t *testing.T) {
		err := assert.AnError
		errStr := err.Error()
		wantErrMsg := strings.Join([]string{errStr, errStr, errStr}, "\n")

		r := &testResolver{
			onLookupNetIP: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				return nil, assert.AnError
			},
		}

		addrs, err := bootstrap.ParallelResolver{r, r, r}.LookupNetIP(
			context.Background(),
			"ip",
			hostname,
		)
		testutil.AssertErrorMsg(t, wantErrMsg, err)
		assert.Nil(t, addrs)
	})
}
