package proxy

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/miekg/dns"
)

// defaultCacheSize is the size of cache in bytes by default.
const defaultCacheSize = 64 * 1024

// cache is used to cache requests and used upstreams.
//
// TODO(a.garipov):  Add [timeutil.Clock] and make tests less flaky.
type cache struct {
	// itemsLock protects requests cache.
	itemsLock *sync.RWMutex

	// itemsWithSubnetLock protects requests cache.
	itemsWithSubnetLock *sync.RWMutex

	// items is the requests cache.
	items glcache.Cache

	// itemsWithSubnet is the requests cache.
	itemsWithSubnet glcache.Cache

	// optimistic defines if the cache should return expired items and resolve
	// those again.
	optimistic bool

	// optimisticTTL is the default TTL for expired cached responses.
	optimisticTTL time.Duration

	// optimisticMaxAge is the maximum time entries remain in the cache when
	// cache is optimistic.
	optimisticMaxAge time.Duration
}

// cacheItem is a single cache entry.  It's a helper type to aggregate the
// item-specific logic.
type cacheItem struct {
	m   *dns.Msg
	u   string
	ttl uint32
}

// respToItem converts the pair of the response and upstream resolved the one
// into item for storing it in cache.  l must not be nil.
func (c *cache) respToItem(m *dns.Msg, u upstream.Upstream, l *slog.Logger) (item *cacheItem) {
	ttl := dnsmsg.CacheTTL(m, l)
	if ttl == 0 {
		return nil
	}

	upsAddr := ""
	if u != nil {
		upsAddr = u.Address()
	}

	return &cacheItem{
		m:   m,
		u:   upsAddr,
		ttl: ttl,
	}
}

const (
	// packedMsgLenSz is the exact length of byte slice capable to store the
	// length of packed DNS message.  It's essentially the size of a uint16.
	packedMsgLenSz = 2
	// expTimeSz is the exact length of byte slice capable to store the
	// expiration time the response.  It's essentially the size of a uint32.
	expTimeSz = 4

	// minPackedLen is the minimum length of the packed cacheItem.
	minPackedLen = expTimeSz + packedMsgLenSz
)

// pack converts the ci into bytes slice.
func (ci *cacheItem) pack() (packed []byte) {
	pm, _ := ci.m.Pack()
	pmLen := len(pm)
	packed = make([]byte, minPackedLen, minPackedLen+pmLen+len(ci.u))

	// Put expiration time.
	binary.BigEndian.PutUint32(packed, uint32(time.Now().Unix())+ci.ttl)

	// Put the length of the packed message.
	binary.BigEndian.PutUint16(packed[expTimeSz:], uint16(pmLen))

	// Put the packed message itself.
	packed = append(packed, pm...)

	// Put the address of the upstream.
	packed = append(packed, ci.u...)

	return packed
}

// unpackItem converts the data into cacheItem using req as a request message.
// expired is true if the item exists but expired.  The expired cached items are
// only returned if c is optimistic and optimistic max age is not exceeded.  req
// must not be nil.
func (c *cache) unpackItem(data []byte, req *dns.Msg) (ci *cacheItem, expired bool) {
	if len(data) < minPackedLen {
		return nil, false
	}

	b := bytes.NewBuffer(data)
	expire := time.Unix(int64(binary.BigEndian.Uint32(b.Next(expTimeSz))), 0)
	now := time.Now()
	var ttl uint32
	if expired = now.After(expire); expired {
		optimisticExpire := expire.Add(c.optimisticMaxAge)
		if !c.optimistic || now.After(optimisticExpire) {
			return nil, expired
		}

		ttl = uint32(c.optimisticTTL.Seconds())
	} else {
		ttl = uint32(expire.Unix() - now.Unix())
	}

	l := int(binary.BigEndian.Uint16(b.Next(packedMsgLenSz)))
	if l == 0 {
		return nil, expired
	}

	m := &dns.Msg{}
	if m.Unpack(b.Next(l)) != nil {
		return nil, expired
	}

	res := (&dns.Msg{}).SetRcode(req, m.Rcode)
	res.AuthenticatedData = m.AuthenticatedData
	res.RecursionAvailable = m.RecursionAvailable

	var doBit bool
	if o := req.IsEdns0(); o != nil {
		doBit = o.Do()
	}

	// Don't return OPT records from cache since it's deprecated by RFC 6891.
	// If the request has DO bit set we only remove all the OPT RRs, and also
	// all DNSSEC RRs otherwise.
	filterMsg(res, m, req.AuthenticatedData, doBit, ttl)

	return &cacheItem{
		m: res,
		u: string(b.Next(b.Len())),
	}, expired
}

// initCache initializes cache if it's enabled.
func (p *Proxy) initCache() {
	if !p.cacheEnabled {
		p.logger.Info("cache disabled")

		return
	}

	size := p.cacheSizeBytes
	p.logger.Info("cache enabled", "size", size)
	p.cache = newCache(&cacheConfig{
		size:             size,
		optimisticTTL:    p.cacheOptimisticAnswerTTL,
		optimisticMaxAge: p.cacheOptimisticMaxAge,
		withECS:          p.enableEDNSClientSubnet,
		optimistic:       p.cacheOptimistic,
	})
	p.shortFlighter = newOptimisticResolver(p)
}

// cacheConfig is the configuration structure for [cache].
type cacheConfig struct {
	// size is the cache size in bytes.
	size int

	// optimisticTTL is the default TTL for expired cached responses when
	// optimistic is enabled.
	optimisticTTL time.Duration

	// optimisticMaxAge is the maximum time entries remain in the cache when
	// cache is optimistic.
	optimisticMaxAge time.Duration

	// withECS enables EDNS Client Subnet support for cache.
	withECS bool

	// optimistic defines if the cache should return expired items and resolve
	// those again.
	optimistic bool
}

// newCache returns a properly initialized cache.  logger must not be nil.
func newCache(conf *cacheConfig) (c *cache) {
	c = &cache{
		itemsLock:           &sync.RWMutex{},
		itemsWithSubnetLock: &sync.RWMutex{},
		items:               createCache(conf.size),
		optimistic:          conf.optimistic,
		optimisticTTL:       conf.optimisticTTL,
		optimisticMaxAge:    conf.optimisticMaxAge,
	}

	if conf.withECS {
		c.itemsWithSubnet = createCache(conf.size)
	}

	return c
}

// get returns cached item for the req if it's found.  expired is true if the
// item's TTL is expired.  key is the resulting key for req.  It's returned to
// avoid recalculating it afterwards.
func (c *cache) get(req *dns.Msg) (ci *cacheItem, expired bool, key []byte) {
	c.itemsLock.RLock()
	defer c.itemsLock.RUnlock()

	if !canLookUpInCache(c.items, req) {
		return nil, false, nil
	}

	key = msgToKey(req)
	data := c.items.Get(key)
	if data == nil {
		return nil, false, key
	}

	if ci, expired = c.unpackItem(data, req); ci == nil {
		c.items.Del(key)
	}

	return ci, expired, key
}

// getWithSubnet returns cached item for the req if it's found by n.  expired
// is true if the item's TTL is expired.  k is the resulting key for req.  It's
// returned to avoid recalculating it afterwards.
//
// Note that a slow longest-prefix-match algorithm is used, so cache searches
// are performed up to mask+1 times.
func (c *cache) getWithSubnet(req *dns.Msg, n *net.IPNet) (ci *cacheItem, expired bool, k []byte) {
	c.itemsWithSubnetLock.RLock()
	defer c.itemsWithSubnetLock.RUnlock()

	if !canLookUpInCache(c.itemsWithSubnet, req) {
		return nil, false, nil
	}

	ecsIP := n.IP.Mask(n.Mask)
	ipLen := len(ecsIP)
	m, _ := n.Mask.Size()

	k = msgToKeyWithSubnet(req, ecsIP, m)
	data := c.itemsWithSubnet.Get(k)

	// In order to reduce allocations we apply mask on bits level.  As the key
	// k has ecsIP in bytes slice representation, each iteration we can just
	// clear one bit in the end of it by applying the bitmask.
	for bitmask := ^byte(0); m >= 0 && data == nil; m-- {
		// Set mask identification byte in the key.
		k[keyMaskIndex] = byte(m)

		// In case mask is zero, the key doesn't have IP in it.
		if m == 0 {
			k = slices.Delete(k, keyIPIndex, keyIPIndex+ipLen)
			data = c.itemsWithSubnet.Get(k)

			continue
		}

		// Shift or renew bitmask.
		if m%8 == 0 {
			bitmask = ^byte(0)
		} else {
			bitmask <<= 1
		}

		// Clear the last non-zero bit in the byte of the IP address.
		k[keyIPIndex+m/8] &= bitmask

		data = c.itemsWithSubnet.Get(k)
	}

	if data == nil {
		return nil, false, k
	}

	if ci, expired = c.unpackItem(data, req); ci == nil {
		c.itemsWithSubnet.Del(k)
	}

	return ci, expired, k
}

// canLookUpInCache returns true if these parameters could be used to make a
// cache lookup.
func canLookUpInCache(cache glcache.Cache, req *dns.Msg) (ok bool) {
	return cache != nil && req != nil && len(req.Question) == 1
}

// createCache returns new Cache with the given cacheSize.
func createCache(cacheSize int) (glc glcache.Cache) {
	conf := glcache.Config{
		MaxSize:   defaultCacheSize,
		EnableLRU: true,
	}

	if cacheSize > 0 {
		conf.MaxSize = uint(cacheSize)
	}

	return glcache.New(conf)
}

// set stores response and upstream for req in the cache.  u and l must not be
// nil.
func (c *cache) set(req, m *dns.Msg, u upstream.Upstream, l *slog.Logger) {
	item := c.respToItem(m, u, l)
	if item == nil {
		return
	}

	key := msgToKey(req)
	packed := item.pack()

	c.itemsLock.Lock()
	defer c.itemsLock.Unlock()

	c.items.Set(key, packed)
}

// setWithSubnet stores response and upstream with subnet in the cache.  The
// given subnet mask and IP address are used to calculate the cache key.  u, n,
// and l must not be nil.
func (c *cache) setWithSubnet(req, m *dns.Msg, u upstream.Upstream, n *net.IPNet, l *slog.Logger) {
	item := c.respToItem(m, u, l)
	if item == nil {
		return
	}

	pref, _ := n.Mask.Size()
	key := msgToKeyWithSubnet(req, n.IP.Mask(n.Mask), pref)
	packed := item.pack()

	c.itemsWithSubnetLock.Lock()
	defer c.itemsWithSubnetLock.Unlock()

	c.itemsWithSubnet.Set(key, packed)
}

// clearItems empties the simple cache.
func (c *cache) clearItems() {
	c.itemsLock.Lock()
	defer c.itemsLock.Unlock()

	c.items.Clear()
}

// clearItemsWithSubnet empties the subnet cache, if any.
func (c *cache) clearItemsWithSubnet() {
	if c.itemsWithSubnet == nil {
		// ECS disabled, return immediately.
		return
	}

	c.itemsWithSubnetLock.Lock()
	defer c.itemsWithSubnetLock.Unlock()

	c.itemsWithSubnet.Clear()
}

// Updates a given TTL to fall within the range specified by the cacheMinTTL and
// cacheMaxTTL settings.
func respectTTLOverrides(ttl, cacheMinTTL, cacheMaxTTL uint32) uint32 {
	if ttl < cacheMinTTL {
		return cacheMinTTL
	}

	if cacheMaxTTL != 0 && ttl > cacheMaxTTL {
		return cacheMaxTTL
	}

	return ttl
}

// msgToKey constructs the cache key from type, class and question's name of m.
func msgToKey(m *dns.Msg) (b []byte) {
	q := m.Question[0]
	name := q.Name
	b = make([]byte, 1+packedMsgLenSz+packedMsgLenSz+len(name))

	// Put the DO flag.
	opt := m.IsEdns0()
	b[0] = mathutil.BoolToNumber[byte](opt != nil && opt.Do())

	// Put QTYPE, QCLASS, and QNAME.
	binary.BigEndian.PutUint16(b[1:], q.Qtype)
	binary.BigEndian.PutUint16(b[1+packedMsgLenSz:], q.Qclass)
	copy(b[1+2*packedMsgLenSz:], strings.ToLower(name))

	return b
}

const (
	// keyMaskIndex is the index of the byte with mask ones value.
	keyMaskIndex = 1 + 2*packedMsgLenSz

	// keyIPIndex is the start index of the IP address in the key.
	keyIPIndex = keyMaskIndex + 1
)

// msgToKeyWithSubnet constructs the cache key from DO bit, type, class, subnet
// mask, client's IP address and question's name of m.  ecsIP is expected to be
// masked already.
func msgToKeyWithSubnet(m *dns.Msg, ecsIP net.IP, mask int) (key []byte) {
	q := m.Question[0]
	keyLen := keyIPIndex + len(q.Name)
	masked := mask != 0
	if masked {
		keyLen += len(ecsIP)
	}

	// Initialize the slice.
	key = make([]byte, keyLen)

	// Put DO.
	opt := m.IsEdns0()
	key[0] = mathutil.BoolToNumber[byte](opt != nil && opt.Do())

	// Put Qtype.
	binary.BigEndian.PutUint16(key[1:], q.Qtype)

	// Put Qclass.
	binary.BigEndian.PutUint16(key[1+packedMsgLenSz:], q.Qclass)

	// Add mask.
	key[keyMaskIndex] = uint8(mask)
	k := keyIPIndex
	if masked {
		k += copy(key[keyIPIndex:], ecsIP)
	}

	copy(key[k:], strings.ToLower(q.Name))

	return key
}

// isDNSSEC returns true if r is a DNSSEC RR.  NSEC, NSEC3, DS, DNSKEY and
// RRSIG/SIG are DNSSEC records.
func isDNSSEC(r dns.RR) bool {
	switch r.Header().Rrtype {
	case
		dns.TypeNSEC,
		dns.TypeNSEC3,
		dns.TypeDS,
		dns.TypeRRSIG,
		dns.TypeSIG,
		dns.TypeDNSKEY:
		return true
	default:
		return false
	}
}

// filterRRSlice removes OPT RRs, DNSSEC RRs except the specified type if do is
// false, sets TTL if ttl is not equal to zero and returns the copy of the rrs.
// The except parameter defines RR of which type should not be filtered out.
func filterRRSlice(rrs []dns.RR, do bool, ttl uint32, except uint16) (filtered []dns.RR) {
	rrsLen := len(rrs)
	if rrsLen == 0 {
		return nil
	}

	j := 0
	rs := make([]dns.RR, rrsLen)
	for _, r := range rrs {
		if (!do && isDNSSEC(r) && r.Header().Rrtype != except) || r.Header().Rrtype == dns.TypeOPT {
			continue
		}

		if ttl != 0 {
			r.Header().Ttl = ttl
		}
		rs[j] = dns.Copy(r)
		j++
	}

	return rs[:j]
}

// filterMsg removes OPT RRs, DNSSEC RRs if do is false, sets TTL to ttl if it's
// not equal to 0 and puts the results to appropriate fields of dst.  It also
// filters the AD bit if both ad and do are false.
func filterMsg(dst, m *dns.Msg, ad, do bool, ttl uint32) {
	// As RFC 6840 says, validating resolvers should only set the AD bit when a
	// response both meets the conditions listed in RFC 4035, and the request
	// contained either a set DO bit or a set AD bit.
	dst.AuthenticatedData = dst.AuthenticatedData && (ad || do)

	// It's important to filter out only DNSSEC RRs that aren't explicitly
	// requested.
	//
	// See https://datatracker.ietf.org/doc/html/rfc4035#section-3.2.1 and
	// https://github.com/AdguardTeam/dnsproxy/issues/144.
	dst.Answer = filterRRSlice(m.Answer, do, ttl, m.Question[0].Qtype)
	dst.Ns = filterRRSlice(m.Ns, do, ttl, dns.TypeNone)
	dst.Extra = filterRRSlice(m.Extra, do, ttl, dns.TypeNone)
}
