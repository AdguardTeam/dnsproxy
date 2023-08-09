package netutil_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func TestSortNetIPAddrs(t *testing.T) {
	var (
		aIPv4    = netip.MustParseAddr("1.2.3.4")
		bIPv4    = netip.MustParseAddr("4.3.2.1")
		aIPv6    = netip.MustParseAddr("2a00::1234")
		bIPv6    = netip.MustParseAddr("2a00::4321")
		badIP, _ = netip.ParseAddr("bad")
	)

	testCases := []struct {
		name       string
		addrs      []netip.Addr
		want       []netip.Addr
		preferIPv6 bool
	}{{
		name:       "v4_preferred",
		addrs:      []netip.Addr{aIPv6, bIPv6, badIP, aIPv4, bIPv4},
		want:       []netip.Addr{aIPv4, bIPv4, aIPv6, bIPv6, badIP},
		preferIPv6: false,
	}, {
		name:       "v6_preferred",
		addrs:      []netip.Addr{aIPv4, bIPv4, badIP, aIPv6, bIPv6},
		want:       []netip.Addr{aIPv6, bIPv6, aIPv4, bIPv4, badIP},
		preferIPv6: true,
	}, {
		name:       "shuffled_v4_preferred",
		addrs:      []netip.Addr{badIP, aIPv4, bIPv6, aIPv6, bIPv4},
		want:       []netip.Addr{aIPv4, bIPv4, aIPv6, bIPv6, badIP},
		preferIPv6: false,
	}, {
		name:       "shuffled_v6_preferred",
		addrs:      []netip.Addr{badIP, aIPv4, bIPv6, aIPv6, bIPv4},
		want:       []netip.Addr{aIPv6, bIPv6, aIPv4, bIPv4, badIP},
		preferIPv6: true,
	}, {
		name:       "empty",
		addrs:      []netip.Addr{},
		want:       []netip.Addr{},
		preferIPv6: false,
	}, {
		name:       "single",
		addrs:      []netip.Addr{aIPv4},
		want:       []netip.Addr{aIPv4},
		preferIPv6: false,
	}, {
		name:       "start_with_ipv4",
		addrs:      []netip.Addr{aIPv4, aIPv6, bIPv4, bIPv6},
		want:       []netip.Addr{aIPv6, bIPv6, aIPv4, bIPv4},
		preferIPv6: true,
	}, {
		name:       "start_with_ipv6",
		addrs:      []netip.Addr{aIPv6, aIPv4, bIPv6, bIPv4},
		want:       []netip.Addr{aIPv6, bIPv6, aIPv4, bIPv4},
		preferIPv6: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ips := slices.Clone(tc.addrs)
			netutil.SortNetIPAddrs(ips, tc.preferIPv6)
			assert.Equal(t, tc.want, ips)
		})
	}
}
