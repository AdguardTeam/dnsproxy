package proxyutil

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortIPAddrs(t *testing.T) {
	ipAddrs := []net.IPAddr{}
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("94.140.14.16").To4()})
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("2a10:50c0::bad1:ff")})
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("94.140.14.15")})
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("2a10:50c0::bad2:ff")})

	ipAddrs = SortIPAddrs(ipAddrs)

	assert.Equal(t, ipAddrs[0].String(), "94.140.14.15")
	assert.Equal(t, ipAddrs[1].String(), "94.140.14.16")
	assert.Equal(t, ipAddrs[2].String(), "2a10:50c0::bad1:ff")
	assert.Equal(t, ipAddrs[3].String(), "2a10:50c0::bad2:ff")
}

func TestContainsIP(t *testing.T) {
	nets := []*net.IPNet{{
		// IPv4.
		IP:   net.IP{1, 2, 3, 0},
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}, {
		// IPv6 from IPv4.
		IP:   net.IPv4(1, 2, 4, 0),
		Mask: net.CIDRMask(16, 32),
	}, {
		// IPv6.
		IP:   net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0},
		Mask: net.CIDRMask(120, net.IPv6len*8),
	}}

	testCases := []struct {
		name string
		want assert.BoolAssertionFunc
		ip   net.IP
	}{{
		name: "ipv4_yes",
		want: assert.True,
		ip:   net.IP{1, 2, 3, 255},
	}, {
		name: "ipv4_6_yes",
		want: assert.True,
		ip:   net.IPv4(1, 2, 4, 254),
	}, {
		name: "ipv6_yes",
		want: assert.True,
		ip:   net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}, {
		name: "ipv6_4_yes",
		want: assert.True,
		ip:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 0},
	}, {
		name: "ipv4_no",
		want: assert.False,
		ip:   net.IP{2, 1, 3, 255},
	}, {
		name: "ipv4_6_no",
		want: assert.False,
		ip:   net.IPv4(2, 1, 4, 254),
	}, {
		name: "ipv6_no",
		want: assert.False,
		ip:   net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 15},
	}, {
		name: "ipv6_4_no",
		want: assert.False,
		ip:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 2, 1, 4, 0},
	}, {
		name: "nil_no",
		want: assert.False,
		ip:   nil,
	}, {
		name: "bad_ip",
		want: assert.False,
		ip:   net.IP{42},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.want(t, ContainsIP(nets, tc.ip))
		})
	}
}
