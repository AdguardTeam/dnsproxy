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

// funcResolver is a function that implements the single-method [Resolver]
// interface.  It's used in testing purposes.
type funcResolver func(
	ctx context.Context,
	network bootstrap.Network,
	host string,
) (addrs []netip.Addr, err error)

// type check
var _ bootstrap.Resolver = funcResolver(nil)

// LookupNetIP implements the [Resolver] interface for funcResolver.
func (f funcResolver) LookupNetIP(
	ctx context.Context,
	network bootstrap.Network,
	host string,
) (addrs []netip.Addr, err error) {
	return f(ctx, network, host)
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

	immediate := funcResolver(func(
		_ context.Context,
		network bootstrap.Network,
		host string,
	) ([]netip.Addr, error) {
		require.Equal(pt, hostname, host)
		require.Equal(pt, "ip", network)

		return hostAddrs, nil
	})

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
		delayed := funcResolver(func(
			_ context.Context,
			network bootstrap.Network,
			host string,
		) ([]netip.Addr, error) {
			require.Equal(pt, hostname, host)
			require.Equal(pt, "ip", network)

			testutil.RequireReceive(pt, delayCh, testTimeout)

			return []netip.Addr{netutil.IPv6Localhost()}, nil
		})

		addrs, err := bootstrap.ParallelResolver{immediate, delayed}.LookupNetIP(
			context.Background(),
			bootstrap.NetworkIP,
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

		r := funcResolver(func(
			_ context.Context,
			network bootstrap.Network,
			host string,
		) ([]netip.Addr, error) {
			return nil, assert.AnError
		})

		addrs, err := bootstrap.ParallelResolver{r, r, r}.LookupNetIP(
			context.Background(),
			bootstrap.NetworkIP,
			hostname,
		)
		testutil.AssertErrorMsg(t, wantErrMsg, err)
		assert.Nil(t, addrs)
	})
}
