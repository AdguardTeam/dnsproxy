package fastip

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// TODO(e.burkov):  Rewrite the cache using zero-values instead of storing
// useless boolean as an integer.

const (
	fastestAddrCacheTTLSec = 10 * 60 // cache TTL for IP addresses
)

type cacheEntry struct {
	status      int // 0:ok; 1:timed out
	latencyMsec uint
}

// packCacheEntry packs the cache entry and the TTL to bytes in the following
// order:
//
//	expire   [4]byte  (Unix time, seconds)
//	status   byte     (0 for ok, 1 for timed out)
//	latency  [2]byte  (milliseconds)
func packCacheEntry(ent *cacheEntry, ttl uint32) []byte {
	expire := uint32(time.Now().Unix()) + ttl

	d := make([]byte, 4+1+2)
	binary.BigEndian.PutUint32(d, expire)
	i := 4

	d[i] = byte(ent.status)
	i++

	binary.BigEndian.PutUint16(d[i:], uint16(ent.latencyMsec))
	// i += 2

	return d
}

// unpackCacheEntry - unpacks bytes to cache entry and checks TTL
// if the record is expired, returns nil
func unpackCacheEntry(data []byte) *cacheEntry {
	now := time.Now().Unix()
	expire := binary.BigEndian.Uint32(data[:4])
	if int64(expire) <= now {
		return nil
	}
	ent := cacheEntry{}
	i := 4

	ent.status = int(data[i])
	i++

	ent.latencyMsec = uint(binary.BigEndian.Uint16(data[i:]))
	// i += 2

	return &ent
}

// cacheFind - find entry in the cache for this IP
// returns null if nothing found or if the record for this ip is expired
func (f *FastestAddr) cacheFind(ip netip.Addr) *cacheEntry {
	val := f.ipCache.Get(ip.AsSlice())
	if val == nil {
		return nil
	}
	ent := unpackCacheEntry(val)
	if ent == nil {
		return nil
	}
	return ent
}

// cacheAddFailure - store unsuccessful attempt in cache
func (f *FastestAddr) cacheAddFailure(ip netip.Addr) {
	ent := cacheEntry{
		status: 1,
	}

	f.ipCacheLock.Lock()
	defer f.ipCacheLock.Unlock()

	if f.cacheFind(ip) == nil {
		f.cacheAdd(&ent, ip, fastestAddrCacheTTLSec)
	}
}

// store a successful ping result in cache
// replace previous result if our latency is lower
func (f *FastestAddr) cacheAddSuccessful(ip netip.Addr, latency uint) {
	ent := cacheEntry{
		latencyMsec: latency,
	}

	f.ipCacheLock.Lock()
	defer f.ipCacheLock.Unlock()

	entCached := f.cacheFind(ip)
	if entCached == nil || entCached.status != 0 || entCached.latencyMsec > latency {
		f.cacheAdd(&ent, ip, fastestAddrCacheTTLSec)
	}
}

// cacheAdd -- adds a new entry to the cache
func (f *FastestAddr) cacheAdd(ent *cacheEntry, ip netip.Addr, ttl uint32) {
	val := packCacheEntry(ent, ttl)
	f.ipCache.Set(ip.AsSlice(), val)
}
