package bootstrap_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

// testTimeout is a common timeout used in tests of this package.
const testTimeout = 1 * time.Second

// funcDialer is a function that implements the single-method [Dialer]
// interface.  It's used in testing purposes.
type funcDialer func(
	ctx context.Context,
	network bootstrap.Network,
	addr string,
) (conn net.Conn, err error)

// type check
var _ bootstrap.Dialer = funcDialer(nil)

// DialContext implements the [Dialer] interface for funcDialer.
func (f funcDialer) DialContext(
	ctx context.Context,
	network bootstrap.Network,
	addr string,
) (conn net.Conn, err error) {
	return f(ctx, network, addr)
}

func TestResolvingDialer(t *testing.T) {
	const testHost = "example.com"

	errDialer := funcDialer(func(
		ctx context.Context,
		network bootstrap.Network,
		addr string,
	) (conn net.Conn, err error) {
		return nil, assert.AnError
	})

	testCases := []struct {
		resolver   bootstrap.Resolver
		dialer     bootstrap.Dialer
		name       string
		wantErrMsg string
	}{{
		resolver: funcResolver(func(
			ctx context.Context,
			network bootstrap.Network,
			host string,
		) (addrs []netip.Addr, err error) {
			return nil, assert.AnError
		}),
		dialer:     nil,
		name:       "resolver_error",
		wantErrMsg: fmt.Sprintf("resolving %q: %s", testHost, assert.AnError.Error()),
	}, {
		resolver:   bootstrap.StaticResolver{},
		dialer:     nil,
		name:       "no_addresses",
		wantErrMsg: fmt.Sprintf("no addresses resolved for %q", testHost),
	}, {
		resolver:   bootstrap.StaticResolver{netip.IPv4Unspecified()},
		dialer:     errDialer,
		name:       "dialer_error",
		wantErrMsg: fmt.Sprintf("all dials failed: %s", assert.AnError.Error()),
	}, {
		resolver:   bootstrap.StaticResolver{netip.IPv4Unspecified(), netip.IPv6Unspecified()},
		dialer:     errDialer,
		name:       "dialer_errors",
		wantErrMsg: fmt.Sprintf("all dials failed: %[1]s\n%[1]s", assert.AnError.Error()),
	}, {
		resolver: bootstrap.StaticResolver{netip.IPv4Unspecified()},
		dialer: funcDialer(func(
			ctx context.Context,
			network bootstrap.Network,
			addr string,
		) (conn net.Conn, err error) {
			return nil, nil
		}),
		name:       "success",
		wantErrMsg: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			boot := &bootstrap.ResolvingDialer{
				Resolver: tc.resolver,
				Dialer:   tc.dialer,
			}

			_, err := boot.DialContext(context.Background(), bootstrap.NetworkUDP, testHost)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
