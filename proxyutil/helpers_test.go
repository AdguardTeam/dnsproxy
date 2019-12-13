package proxyutil

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortIPAddrs(t *testing.T) {
	ipAddrs := []net.IPAddr{}
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("176.103.130.134").To4()})
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("2a00:5a60::bad1:ff")})
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("176.103.130.132")})
	ipAddrs = append(ipAddrs, net.IPAddr{IP: net.ParseIP("2a00:5a60::bad2:ff")})

	ipAddrs = SortIPAddrs(ipAddrs)

	assert.Equal(t, ipAddrs[0].String(), "176.103.130.132")
	assert.Equal(t, ipAddrs[1].String(), "176.103.130.134")
	assert.Equal(t, ipAddrs[2].String(), "2a00:5a60::bad1:ff")
	assert.Equal(t, ipAddrs[3].String(), "2a00:5a60::bad2:ff")
}
