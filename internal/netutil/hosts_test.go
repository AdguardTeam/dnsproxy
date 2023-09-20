package netutil_test

import (
	"io/fs"
	"net/netip"
	"os"
	"path"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// testdata is an [fs.FS] containing data for tests.
var testdata = os.DirFS("./testdata")

func TestHosts(t *testing.T) {
	t.Parallel()

	var h *netutil.Hosts
	var err error
	t.Run("good_file", func(t *testing.T) {
		var f fs.File
		f, err = testdata.Open(path.Join(t.Name(), "hosts"))
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		h, err = netutil.NewHosts(f)
	})
	require.NoError(t, err)

	// Variables mirroring the testdata/TestHosts/hosts file.
	var (
		v4Addr1 = netip.MustParseAddr("0.0.0.1")
		v4Addr2 = netip.MustParseAddr("0.0.0.2")

		mappedAddr1 = netip.MustParseAddr("::ffff:0.0.0.1")
		mappedAddr2 = netip.MustParseAddr("::ffff:0.0.0.2")

		v6Addr1 = netip.MustParseAddr("::1")
		v6Addr2 = netip.MustParseAddr("::2")

		wantHosts = map[string][]netip.Addr{
			"host.one":       {v4Addr1, mappedAddr1, v6Addr1},
			"host.two":       {v4Addr2, mappedAddr2, v6Addr2},
			"host.new":       {v4Addr2, v4Addr1, mappedAddr2, mappedAddr1, v6Addr2, v6Addr1},
			"again.host.two": {v4Addr2, mappedAddr2, v6Addr2},
		}

		wantAddrs = map[netip.Addr][]string{
			v4Addr1:     {"Host.One", "host.new"},
			v4Addr2:     {"Host.Two", "Host.New", "Again.Host.Two"},
			mappedAddr1: {"Host.One", "host.new"},
			mappedAddr2: {"Host.Two", "Host.New", "Again.Host.Two"},
			v6Addr1:     {"Host.One", "host.new"},
			v6Addr2:     {"Host.Two", "Host.New", "Again.Host.Two"},
		}
	)

	t.Run("Mappings", func(t *testing.T) {
		names, addrs := h.Mappings()
		assert.Equal(t, wantAddrs, names)
		assert.Equal(t, wantHosts, addrs)
	})

	t.Run("ByAddr", func(t *testing.T) {
		t.Parallel()

		// Sort keys to make the test deterministic.
		addrs := maps.Keys(wantAddrs)
		slices.SortFunc(addrs, netip.Addr.Compare)

		for _, addr := range addrs {
			addr := addr
			t.Run(addr.String(), func(t *testing.T) {
				t.Parallel()

				assert.Equal(t, wantAddrs[addr], h.ByAddr(addr))
			})
		}
	})

	t.Run("ByHost", func(t *testing.T) {
		t.Parallel()

		// Sort keys to make the test deterministic.
		hosts := maps.Keys(wantHosts)
		slices.Sort(hosts)

		for _, host := range hosts {
			host := host
			t.Run(host, func(t *testing.T) {
				t.Parallel()

				assert.Equal(t, wantHosts[host], h.ByName(host))
			})
		}
	})

	t.Run("bad_file", func(t *testing.T) {
		var f fs.File
		f, err = testdata.Open(path.Join(t.Name(), "hosts"))
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, f.Close)

		_, err = netutil.NewHosts(f)
		require.NoError(t, err)
	})

	t.Run("non-line_error", func(t *testing.T) {
		assert.NotPanics(t, func() {
			(&netutil.Hosts{}).HandleInvalid("test", nil, assert.AnError)
		})
	})
}
