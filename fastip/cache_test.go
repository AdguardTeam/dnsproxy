package fastip

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCacheAdd(t *testing.T) {
	f := NewFastestAddr()
	ent := cacheEntry{
		status:      0,
		latencyMsec: 111,
	}

	ip := netip.MustParseAddr("1.1.1.1")
	f.cacheAdd(&ent, ip, fastestAddrCacheTTLSec)

	// check that it's there
	assert.NotNil(t, f.cacheFind(ip))
}

func TestCacheTtl(t *testing.T) {
	f := NewFastestAddr()
	ent := cacheEntry{
		status:      0,
		latencyMsec: 111,
	}

	ip := netip.MustParseAddr("1.1.1.1")
	f.cacheAdd(&ent, ip, 1)

	// check that it's there
	assert.NotNil(t, f.cacheFind(ip))

	// wait for more than one second
	time.Sleep(time.Millisecond * 1001)

	// check that now it returns nil
	assert.Nil(t, f.cacheFind(ip))
}

func TestCacheAddSuccessfulOverwrite(t *testing.T) {
	f := NewFastestAddr()

	ip := netip.MustParseAddr("1.1.1.1")
	f.cacheAddFailure(ip)

	// check that it's there
	ent := f.cacheFind(ip)
	assert.NotNil(t, ent)
	assert.Equal(t, 1, ent.status)

	// check that it will overwrite existing rec
	f.cacheAddSuccessful(ip, 11)

	// check that it's there now
	ent = f.cacheFind(ip)
	assert.NotNil(t, ent)
	assert.Equal(t, 0, ent.status)
	assert.Equal(t, uint(11), ent.latencyMsec)
}

func TestCacheAddFailureNoOverwrite(t *testing.T) {
	f := NewFastestAddr()

	ip := netip.MustParseAddr("1.1.1.1")
	f.cacheAddSuccessful(ip, 11)

	// check that it's there
	ent := f.cacheFind(ip)
	assert.NotNil(t, ent)
	assert.Equal(t, 0, ent.status)

	// check that it will overwrite existing rec
	f.cacheAddFailure(ip)

	// check that the old record is still there
	ent = f.cacheFind(ip)
	assert.NotNil(t, ent)
	assert.Equal(t, 0, ent.status)
	assert.Equal(t, uint(11), ent.latencyMsec)
}

// TODO(ameshkov): Actually test something.
func TestCache(_ *testing.T) {
	f := NewFastestAddr()
	ent := cacheEntry{
		status:      0,
		latencyMsec: 111,
	}

	val := packCacheEntry(&ent, 1)
	f.ipCache.Set(net.ParseIP("1.1.1.1").To4(), val)
	ent = cacheEntry{
		status:      0,
		latencyMsec: 222,
	}

	f.cacheAdd(&ent, netip.MustParseAddr("2.2.2.2"), fastestAddrCacheTTLSec)
}
