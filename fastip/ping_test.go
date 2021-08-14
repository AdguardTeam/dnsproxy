package fastip

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPingSingleIP(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	f := NewFastestAddr()
	found, res := f.pingAll("test", []net.IP{ip})
	require.True(t, found)
	require.NotNil(t, res)
	require.True(t, res.success)
	require.Equal(t, ip, res.ip)

	// There was no ping so the port is zero
	require.Equal(t, uint(0), res.tcpPort)

	// Nothing in the cache since there was no ping
	ce := f.cacheFind(ip)
	require.Nil(t, ce)
}

func TestPingSuccess(t *testing.T) {
	// Listener that we're using for TCP checks
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	ip := net.ParseIP("127.0.0.1")
	port := uint(listener.Addr().(*net.TCPAddr).Port)
	defer listener.Close()

	f := NewFastestAddr()
	f.tcpPorts = []uint{port}

	// We need at least two IPs so adding a random remote IP here
	ips := []net.IP{ip, net.ParseIP("8.8.8.8")}
	found, res := f.pingAll("test", ips)
	require.True(t, found)
	require.NotNil(t, res)
	require.True(t, res.success)
	require.Equal(t, ip, res.ip)
	require.Equal(t, port, res.tcpPort)

	// don't forget to check the cache
	ce := f.cacheFind(ip)
	require.NotNil(t, ce)
	require.Equal(t, 0, ce.status)
}

func TestPingFail(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	ip2 := net.ParseIP("127.0.0.2")
	port := getFreePort()

	f := NewFastestAddr()
	f.tcpPorts = []uint{port}

	found, res := f.pingAll("test", []net.IP{ip, ip2})
	require.False(t, found)
	require.Nil(t, res)

	if runtime.GOOS != "windows" {
		// it appears that on Windows connectex has some strange behavior
		// when connection is refused, it still tries to connect for about a second
		// this breaks the logic of this test (we rely on immediate refusal)
		// so the cache check is simply disabled on Windows

		// don't forget to check cache
		ce := f.cacheFind(ip)
		require.NotNil(t, ce)
		require.Equal(t, 1, ce.status)
	}
}

func TestPingFastest(t *testing.T) {
	// Listener that we're using for TCP checks
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	ip := net.ParseIP("127.0.0.1")
	port := uint(listener.Addr().(*net.TCPAddr).Port)
	defer listener.Close()

	f := NewFastestAddr()
	f.tcpPorts = []uint{port, 443} // add 443 since it's definitely used by 8.8.8.8

	// test ips
	ips := []net.IP{ip}

	// 8.8.8.8 is slower than localhost
	// the test checks that 127.0.0.1 is returned
	ips = append(ips, net.ParseIP("8.8.8.8"))

	found, res := f.pingAll("test", ips)
	require.True(t, found)
	require.NotNil(t, res)
	require.True(t, res.success)
	require.Equal(t, ip, res.ip)
	require.Equal(t, port, res.tcpPort)

	// don't forget to check cache
	ce := f.cacheFind(ip)
	require.NotNil(t, ce)
	require.Equal(t, 0, ce.status)
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
