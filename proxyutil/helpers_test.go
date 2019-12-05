package proxyutil

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortIPAddrs(t *testing.T) {
	ipAddrs := []net.IPAddr{}
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("2a00:5a60::ad1:ff")})
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("2.2.2.2")})
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("1.1.1.1")})

	ipAddrs = SortIPAddrs(ipAddrs)

	assert.Equal(t, ipAddrs[0].String(), "1.1.1.1")
	assert.Equal(t, ipAddrs[1].String(), "2.2.2.2")
	assert.Equal(t, ipAddrs[2].String(), "2a00:5a60::ad1:ff")
}
