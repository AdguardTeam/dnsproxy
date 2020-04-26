package fastip

import (
	"encoding/binary"
	"net"
	"time"
)

const (
	fastestAddrCacheTTLSec = 10 * 60 // cache TTL for IP addresses
)

type cacheEntry struct {
	status      int //0:ok; 1:timed out
	latencyMsec uint
}

// packCacheEntry - packss cache entry + ttl to bytes
//
// expire [4]byte
// status byte
// latency_msec [2]byte
func packCacheEntry(ent *cacheEntry, ttl uint32) []byte {
	expire := uint32(time.Now().Unix()) + ttl
	var d []byte
	d = make([]byte, 4+1+2)
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
func (f *FastestAddr) cacheFind(ip net.IP) *cacheEntry {
	k := getCacheKey(ip)
	val := f.cache.Get(k)
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
func (f *FastestAddr) cacheAddFailure(addr net.IP) {
	ent := cacheEntry{}
	ent.status = 1
	f.cacheLock.Lock()
	if f.cacheFind(addr) == nil {
		f.cacheAdd(&ent, addr, fastestAddrCacheTTLSec)
	}
	f.cacheLock.Unlock()
}

// store a successful ping result in cache
// replace previous result if our latency is lower
func (f *FastestAddr) cacheAddSuccessful(addr net.IP, latency uint) {
	ent := cacheEntry{}
	ent.status = 0
	ent.latencyMsec = latency
	f.cacheLock.Lock()
	entCached := f.cacheFind(addr)
	if entCached == nil || entCached.status != 0 || entCached.latencyMsec > latency {
		f.cacheAdd(&ent, addr, fastestAddrCacheTTLSec)
	}
	f.cacheLock.Unlock()
}

// cacheAdd -- adds a new entry to the cache
func (f *FastestAddr) cacheAdd(ent *cacheEntry, addr net.IP, ttl uint32) {
	ip := getCacheKey(addr)
	val := packCacheEntry(ent, ttl)
	f.cache.Set(ip, val)
}

// getCacheKey - gets cache key (compresses ipv4 to 4 bytes)
func getCacheKey(addr net.IP) net.IP {
	ip := addr.To4()
	if ip == nil {
		ip = addr
	}
	return ip
}
