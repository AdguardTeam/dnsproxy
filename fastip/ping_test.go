package fastip

import (
	"net"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/netutil"
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

		ip := net.IP{127, 0, 0, 1}
		res := f.pingAll("", []net.IP{ip, ip})
		require.Nil(t, res)

		waitCh <- unit{}
	})

	t.Run("cached", func(t *testing.T) {
		f := NewFastestAddr()

		const lat uint = 42

		ip1, ip2 := net.IP{127, 0, 0, 1}, net.IP{127, 0, 0, 2}
		f.cacheAddSuccessful(ip1, lat)

		waitCh := make(chan unit)
		f.pinger.Control = func(_, _ string, _ syscall.RawConn) error {
			<-waitCh

			return nil
		}

		res := f.pingAll("", []net.IP{ip1, ip2})
		require.NotNil(t, res)

		assert.True(t, res.success)
		assert.Equal(t, lat, res.latency)

		waitCh <- unit{}
	})
}

// assertCaching checks the cache of f for containing a connection to ip with
// the specified status.
func assertCaching(t *testing.T, f *FastestAddr, ip net.IP, status int) {
	t.Helper()

	const tickDur = pingTCPTimeout / 16

	assert.Eventually(t, func() bool {
		ce := f.cacheFind(ip)

		return ce != nil && ce.status == status
	}, pingTCPTimeout, tickDur)
}

func TestFastestAddr_PingAll_cache(t *testing.T) {
	ip := net.IP{127, 0, 0, 1}

	t.Run("cached_failed", func(t *testing.T) {
		f := NewFastestAddr()
		f.cacheAddFailure(ip)

		res := f.pingAll("", []net.IP{ip, ip})
		require.Nil(t, res)
	})

	t.Run("cached_succesfull", func(t *testing.T) {
		const lat uint = 1

		f := NewFastestAddr()
		f.cacheAddSuccessful(ip, lat)

		res := f.pingAll("", []net.IP{ip, ip})
		require.NotNil(t, res)
		assert.True(t, res.success)
		assert.Equal(t, lat, res.latency)
	})

	t.Run("not_cached", func(t *testing.T) {
		listener, err := net.Listen("tcp", ":0")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, listener.Close()) })

		ip := net.IP{127, 0, 0, 1}
		f := NewFastestAddr()

		f.pingPorts = []uint{uint(listener.Addr().(*net.TCPAddr).Port)}
		ips := []net.IP{ip, ip}

		wg := &sync.WaitGroup{}
		wg.Add(len(ips) * len(f.pingPorts))

		f.pinger.Control = func(_, address string, _ syscall.RawConn) error {
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
func listen(t *testing.T, ip net.IP) (port uint) {
	t.Helper()

	l, err := net.Listen("tcp", netutil.IPPort{IP: ip, Port: 0}.String())
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, l.Close()) })

	return uint(l.Addr().(*net.TCPAddr).Port)
}

func TestFastestAddr_PingAll(t *testing.T) {
	ip := net.IP{127, 0, 0, 1}

	t.Run("single", func(t *testing.T) {
		f := NewFastestAddr()
		res := f.pingAll("", []net.IP{ip})
		require.NotNil(t, res)

		assert.True(t, res.success)
		assert.True(t, ip.Equal(res.ipp.IP))
		// There was no ping so the port is zero.
		assert.Zero(t, res.ipp.Port)

		// Nothing in the cache since there was no ping.
		ce := f.cacheFind(res.ipp.IP)
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
			ipp, err := netutil.ParseIPPort(address)
			require.NoError(t, err)

			require.Contains(t, []uint{fastPort, slowPort}, uint(ipp.Port))
			if ipp.Port == int(fastPort) {
				return nil
			}

			<-ctrlCh

			return nil
		}

		ips := []net.IP{ip, ip}

		res := f.pingAll("", ips)
		ctrlCh <- unit{}

		require.NotNil(t, res)

		assert.True(t, res.success)
		assert.True(t, ip.Equal(res.ipp.IP))
		assert.EqualValues(t, fastPort, res.ipp.Port)

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

		res := f.pingAll("test", []net.IP{ip, ip})
		require.Nil(t, res)

		assertCaching(t, f, ip, 1)
	})
}

// getFreePort returns the port number no one listens on.
//
// TODO(e.burkov):  The logic is underwhelming.  Find a more accurate way.
func getFreePort(t *testing.T) (port uint) {
	t.Helper()

	l, err := net.Listen("tcp", ":0")
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
