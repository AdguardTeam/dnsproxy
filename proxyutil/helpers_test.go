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
	ips := []net.IP{}
	ips = append(ips, net.ParseIP("94.140.14.15"))
	ips = append(ips, net.ParseIP("2a10:50c0::bad1:ff"))

	ip := net.ParseIP("94.140.14.15")
	assert.True(t, ContainsIP(ips, ip))

	ip = net.ParseIP("2a10:50c0::bad1:ff")
	assert.True(t, ContainsIP(ips, ip))

	ip = net.ParseIP("2a10:50c0::bad1:ff1")
	assert.False(t, ContainsIP(ips, ip))

	ip = net.ParseIP("127.0.0.1")
	assert.False(t, ContainsIP(ips, ip))
}
