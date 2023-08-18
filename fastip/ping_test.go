package fastip

import (
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unit is the convenient alias for struct{}.
type unit = struct{}

func TestFastestAddr_PingAll_timeout(t *testing.T) {
	t.Run("isolated", func(t *testing.T) {
		f := NewFastestAddr()

		waitCh := make(chan unit)
		f.pinger.Control = func(_, _ string, _ syscall.RawConn) error {
			<-waitCh

			return nil
		}

		ip := netutil.IPv4Localhost()
		res := f.pingAll("", []netip.Addr{ip, ip})
		require.Nil(t, res)

		waitCh <- unit{}
	})

	t.Run("cached", func(t *testing.T) {
		f := NewFastestAddr()

		const lat uint = 42

		ip1 := netutil.IPv4Localhost()
		ip2 := netip.MustParseAddr("127.0.0.2")
		f.cacheAddSuccessful(ip1, lat)

		waitCh := make(chan unit)
		f.pinger.Control = func(_, _ string, _ syscall.RawConn) error {
			<-waitCh

			return nil
		}

		res := f.pingAll("", []netip.Addr{ip1, ip2})
		require.NotNil(t, res)

		assert.True(t, res.success)
		assert.Equal(t, lat, res.latency)

		waitCh <- unit{}
	})
}

// assertCaching checks the cache of f for containing a connection to ip with
// the specified status.
func assertCaching(t *testing.T, f *FastestAddr, ip netip.Addr, status int) {
	t.Helper()

	const tickDur = pingTCPTimeout / 16

	assert.Eventually(t, func() bool {
		ce := f.cacheFind(ip)

		return ce != nil && ce.status == status
	}, pingTCPTimeout, tickDur)
}

func TestFastestAddr_PingAll_cache(t *testing.T) {
	ip := netutil.IPv4Localhost()

	t.Run("cached_failed", func(t *testing.T) {
		f := NewFastestAddr()
		f.cacheAddFailure(ip)

		res := f.pingAll("", []netip.Addr{ip, ip})
		require.Nil(t, res)
	})

	t.Run("cached_successful", func(t *testing.T) {
		const lat uint = 1

		f := NewFastestAddr()
		f.cacheAddSuccessful(ip, lat)

		res := f.pingAll("", []netip.Addr{ip, ip})
		require.NotNil(t, res)
		assert.True(t, res.success)
		assert.Equal(t, lat, res.latency)
	})

	t.Run("not_cached", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, listener.Close)

		ip = netutil.IPv4Localhost()
		f := NewFastestAddr()

		f.pingPorts = []uint{uint(listener.Addr().(*net.TCPAddr).Port)}
		ips := []netip.Addr{ip, ip}

		wg := &sync.WaitGroup{}
		wg.Add(len(ips) * len(f.pingPorts))

		f.pinger.Control = func(_, address string, _ syscall.RawConn) (err error) {
			hostport, err := netutil.ParseHostPort(address)
			require.NoError(t, err)

			assert.Equal(t, ip.String(), hostport.Host)
			assert.Contains(t, f.pingPorts, uint(hostport.Port))

			wg.Done()

			return nil
		}

		res := f.pingAll("", ips)
		require.NotNil(t, res)

		assert.True(t, res.success)
		assertCaching(t, f, ip, 0)

		wg.Wait()
	})
}

// listen is a helper function that creates a new listener on ip for t.
func listen(t *testing.T, ip netip.Addr) (port uint) {
	t.Helper()

	l, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, l.Close)

	return uint(l.Addr().(*net.TCPAddr).Port)
}

func TestFastestAddr_PingAll(t *testing.T) {
	ip := netutil.IPv4Localhost()

	t.Run("single", func(t *testing.T) {
		f := NewFastestAddr()
		res := f.pingAll("", []netip.Addr{ip})
		require.NotNil(t, res)

		assert.True(t, res.success)
		assert.Equal(t, ip, res.addrPort.Addr())
		// There was no ping so the port is zero.
		assert.Zero(t, res.addrPort.Port())

		// Nothing in the cache since there was no ping.
		ce := f.cacheFind(res.addrPort.Addr())
		require.Nil(t, ce)
	})

	t.Run("fastest", func(t *testing.T) {
		fastPort := listen(t, ip)
		slowPort := listen(t, ip)

		ctrlCh := make(chan unit, 1)

		f := NewFastestAddr()
		f.pingPorts = []uint{
			fastPort,
			slowPort,
		}
		f.pinger.Control = func(_, address string, _ syscall.RawConn) error {
			addrPort := netip.MustParseAddrPort(address)
			require.Contains(t, []uint{fastPort, slowPort}, uint(addrPort.Port()))
			if addrPort.Port() == uint16(fastPort) {
				return nil
			}

			<-ctrlCh

			return nil
		}

		ips := []netip.Addr{ip, ip}
		res := f.pingAll("", ips)
		ctrlCh <- unit{}

		require.NotNil(t, res)

		assert.True(t, res.success)
		assert.Equal(t, ip, res.addrPort.Addr())
		assert.EqualValues(t, fastPort, res.addrPort.Port())

		assertCaching(t, f, ip, 0)
	})

	t.Run("zero", func(t *testing.T) {
		res := NewFastestAddr().pingAll("", nil)
		require.Nil(t, res)
	})

	t.Run("fail", func(t *testing.T) {
		port := getFreePort(t)

		f := NewFastestAddr()
		f.pingPorts = []uint{port}

		res := f.pingAll("test", []netip.Addr{ip, ip})
		require.Nil(t, res)

		assertCaching(t, f, ip, 1)
	})
}

// getFreePort returns the port number no one listens on.
//
// TODO(e.burkov):  The logic is underwhelming.  Find a more accurate way.
func getFreePort(t *testing.T) (port uint) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port = uint(l.Addr().(*net.TCPAddr).Port)

	// Stop listening immediately.
	require.NoError(t, l.Close())

	// Sleeping for some time may be necessary on Windows.
	if runtime.GOOS == "windows" {
		time.Sleep(100 * time.Millisecond)
	}

	return port
}
