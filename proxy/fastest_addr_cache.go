package proxy

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
)

const (
	fastestAddrCacheMinTTLSec = 2 * 60 // min. cache TTL in seconds
)

type cacheEntry struct {
	status      int //0:ok; 1:timed out
	latencyMsec uint
}

/*
expire [4]byte
status byte
latency_msec [2]byte
*/
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

// find in cache
func (f *FastestAddr) cacheFind(ip net.IP) *cacheEntry {
	val := f.cache.Get(ip)
	if val == nil {
		return nil
	}
	ent := unpackCacheEntry(val)
	if ent == nil {
		return nil
	}
	return ent
}

// store unsuccessful attempt in cache
func (f *FastestAddr) cacheAddFailure(addr net.IP, ttl uint32) {
	ent := cacheEntry{}
	ent.status = 1
	f.cacheLock.Lock()
	if f.cacheFind(addr) == nil {
		f.cacheAdd(&ent, addr, ttl)
	}
	f.cacheLock.Unlock()
}

// store a successul ping result in cache
// replace previous result if our latency is lower
func (f *FastestAddr) cacheAddSuccessful(addr net.IP, ttl uint32, latency uint) {
	ent := cacheEntry{}
	ent.status = 0
	ent.latencyMsec = latency
	f.cacheLock.Lock()
	entCached := f.cacheFind(addr)
	if entCached == nil || entCached.status != 0 || entCached.latencyMsec > latency {
		f.cacheAdd(&ent, addr, ttl)
	}
	f.cacheLock.Unlock()
}

// store in cache
func (f *FastestAddr) cacheAdd(ent *cacheEntry, addr net.IP, ttl uint32) {
	ip := addr.To4()
	if ip == nil {
		ip = addr
	}

	if ttl < fastestAddrCacheMinTTLSec {
		ttl = fastestAddrCacheMinTTLSec
	}

	val := packCacheEntry(ent, ttl)
	f.cache.Set(ip, val)
}

// Search in cache
func (f *FastestAddr) getFromCache(host string, replies []upstream.ExchangeAllResult) fastestAddrResult {
	result := fastestAddrResult{}
	var fastestIP net.IP
	var fastestRes *upstream.ExchangeAllResult
	var minLatency uint
	minLatency = 0xffff

	n := 0
	for _, r := range replies {
		for _, a := range r.Resp.Answer {
			ip := getIPFromDNSRecord(a)
			if ip == nil {
				continue
			}

			ent := f.cacheFind(ip)
			if ent != nil {
				n++
			}
			if ent != nil && ent.status == 0 && minLatency > ent.latencyMsec {
				fastestIP = ip
				fastestRes = &r
				minLatency = ent.latencyMsec
			}
		}
	}

	result.nCached = n

	if fastestRes != nil {
		result.res = fastestRes
		result.ip = fastestIP
		result.latency = minLatency
		return result
	}

	return result
}
