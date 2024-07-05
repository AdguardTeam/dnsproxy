package upstream_test

import (
	"context"
	"net/netip"
	"testing"
	"testing/fstest"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/hostsfile"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostsResolver_LookupNetIP(t *testing.T) {
	const hostsData = `
1.2.3.4 host1 host2 ipv4.only
::1 host1 host2 ipv6.only
`

	var (
		v4Addr = netip.MustParseAddr("1.2.3.4")
		v6Addr = netip.MustParseAddr("::1")
	)

	paths, err := hostsfile.DefaultHostsPaths()
	require.NoError(t, err)
	require.NotEmpty(t, paths)

	fsys := fstest.MapFS{
		paths[0]: {
			Data: []byte(hostsData),
		},
	}

	hr, err := upstream.NewDefaultHostsResolver(fsys, slogutil.NewDiscardLogger())
	require.NoError(t, err)

	testCases := []struct {
		name      string
		host      string
		net       string
		wantAddrs []netip.Addr
	}{{
		name:      "canonical_any",
		host:      "host1",
		net:       "ip",
		wantAddrs: []netip.Addr{v4Addr, v6Addr},
	}, {
		name:      "canonical_v4",
		host:      "host1",
		net:       "ip4",
		wantAddrs: []netip.Addr{v4Addr},
	}, {
		name:      "canonical_v6",
		host:      "host1",
		net:       "ip6",
		wantAddrs: []netip.Addr{v6Addr},
	}, {
		name:      "alias_any",
		host:      "host2",
		net:       "ip",
		wantAddrs: []netip.Addr{v4Addr, v6Addr},
	}, {
		name:      "alias_v4",
		host:      "host2",
		net:       "ip4",
		wantAddrs: []netip.Addr{v4Addr},
	}, {
		name:      "alias_v6",
		host:      "host2",
		net:       "ip6",
		wantAddrs: []netip.Addr{v6Addr},
	}, {
		name:      "unknown_host",
		host:      "host3",
		net:       "ip",
		wantAddrs: nil,
	}, {
		name:      "family_mismatch_v4",
		host:      "ipv6.only",
		net:       "ip4",
		wantAddrs: nil,
	}, {
		name:      "family_mismatch_v6",
		host:      "ipv4.only",
		net:       "ip6",
		wantAddrs: nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var addrs []netip.Addr
			addrs, err = hr.LookupNetIP(context.Background(), tc.net, tc.host)
			require.NoError(t, err)

			assert.Equal(t, tc.wantAddrs, addrs)
		})
	}

	t.Run("unsupported_network", func(t *testing.T) {
		_, err = hr.LookupNetIP(context.Background(), "ip5", "host1")
		testutil.AssertErrorMsg(t, `unsupported network "ip5"`, err)
	})
}
