package fastip

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPingSuccess(t *testing.T) {
	// Listener that we're using for TCP checks
	listener, err := net.Listen("tcp", ":0")
	assert.Nil(t, err)
	ip := net.ParseIP("127.0.0.1")
	port := uint(listener.Addr().(*net.TCPAddr).Port)
	defer listener.Close()

	f := NewFastestAddr()
	f.tcpPorts = []uint{port}

	found, res := f.pingAll("test", []net.IP{ip})
	assert.True(t, found)
	assert.NotNil(t, res)
	assert.True(t, res.success)
	assert.Equal(t, ip, res.ip)

	// don't forget to check cache
	ce := f.cacheFind(ip)
	assert.NotNil(t, ce)
	assert.Equal(t, 0, ce.status)
}

func TestPingFail(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	port := uint(getFreePort())

	f := NewFastestAddr()
	f.tcpPorts = []uint{port}

	found, res := f.pingAll("test", []net.IP{ip})
	assert.False(t, found)
	assert.Nil(t, res)

	if runtime.GOOS != "windows" {
		// it appears that on Windows connectex has some strange behavior
		// when connection is refused, it still tries to connect for about a second
		// this breaks the logic of this test (we rely on immediate refusal)
		// so the cache check is simply disabled on Windows

		// don't forget to check cache
		ce := f.cacheFind(ip)
		assert.NotNil(t, ce)
		assert.Equal(t, 1, ce.status)
	}
}

func TestPingFastest(t *testing.T) {
	// Listener that we're using for TCP checks
	listener, err := net.Listen("tcp", ":0")
	assert.Nil(t, err)
	ip := net.ParseIP("127.0.0.1")
	port := uint(listener.Addr().(*net.TCPAddr).Port)
	defer listener.Close()

	f := NewFastestAddr()
	f.tcpPorts = []uint{port, 443}

	// test ips
	ips := []net.IP{ip}

	// 8.8.8.8 is slower than localhost
	// the test checks that 127.0.0.1 is returned
	ips = append(ips, net.ParseIP("8.8.8.8"))

	found, res := f.pingAll("test", ips)
	assert.True(t, found)
	assert.NotNil(t, res)
	assert.True(t, res.success)
	assert.Equal(t, ip, res.ip)

	// don't forget to check cache
	ce := f.cacheFind(ip)
	assert.NotNil(t, ce)
	assert.Equal(t, 0, ce.status)
}

func getFreePort() uint {
	l, _ := net.Listen("tcp", ":0")
	port := uint(l.Addr().(*net.TCPAddr).Port)

	// stop listening immediately
	_ = l.Close()

	// sleep for 100ms (may be necessary on Windows)
	time.Sleep(100 * time.Millisecond)
	return port
}
