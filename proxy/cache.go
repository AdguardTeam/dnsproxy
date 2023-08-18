package proxy

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// defaultCacheSize is the size of cache in bytes by default.
const defaultCacheSize = 64 * 1024

// cache is used to cache requests and used upstreams.
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
}

// cacheItem is a single cache entry.  It's a helper type to aggregate the
// item-specific logic.
type cacheItem struct {
	// m contains the cached response.
	m *dns.Msg

	// u contains an address of the upstream which resolved m.
	u string

	// ttl is the time-to-live value for the item.  Should be set before calling
	// [cacheItem.pack].
	ttl uint32
}

// respToItem converts the pair of the response and upstream resolved the one
// into item for storing it in cache.
func respToItem(m *dns.Msg, u upstream.Upstream) (item *cacheItem) {
	ttl := cacheTTL(m)
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

// optimisticTTL is the default TTL for expired cached responses in seconds.
const optimisticTTL = 10

// unpackItem converts the data into cacheItem using req as a request message.
// expired is true if the item exists but expired.  The expired cached items are
// only returned if c is optimistic.  req must not be nil.
func (c *cache) unpackItem(data []byte, req *dns.Msg) (ci *cacheItem, expired bool) {
	if len(data) < minPackedLen {
		return nil, false
	}

	b := bytes.NewBuffer(data)
	expire := int64(binary.BigEndian.Uint32(b.Next(expTimeSz)))
	now := time.Now().Unix()
	var ttl uint32
	if expired = expire <= now; expired {
		if !c.optimistic {
			return nil, expired
		}

		ttl = optimisticTTL
	} else {
		ttl = uint32(expire - now)
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
	if !p.CacheEnabled {
		log.Info("dnsproxy: cache: disabled")

		return
	}

	size := p.CacheSizeBytes
	log.Info("dnsproxy: cache: enabled, size %d b", size)

	p.cache = newCache(size, p.EnableEDNSClientSubnet, p.CacheOptimistic)
	p.shortFlighter = newOptimisticResolver(p)
}

// newCache returns a properly initialized cache.
func newCache(size int, withECS, optimistic bool) (c *cache) {
	c = &cache{
		itemsLock:           &sync.RWMutex{},
		itemsWithSubnetLock: &sync.RWMutex{},
		items:               createCache(size),
		optimistic:          optimistic,
	}

	if withECS {
		c.itemsWithSubnet = createCache(size)
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

// set tries to add the ci into cache.
func (c *cache) set(m *dns.Msg, u upstream.Upstream) {
	item := respToItem(m, u)
	if item == nil {
		return
	}

	key := msgToKey(m)
	packed := item.pack()

	c.itemsLock.Lock()
	defer c.itemsLock.Unlock()

	c.items.Set(key, packed)
}

// setWithSubnet tries to add the ci into cache with subnet and ip used to
// calculate the key.
func (c *cache) setWithSubnet(m *dns.Msg, u upstream.Upstream, subnet *net.IPNet) {
	item := respToItem(m, u)
	if item == nil {
		return
	}

	pref, _ := subnet.Mask.Size()
	key := msgToKeyWithSubnet(m, subnet.IP.Mask(subnet.Mask), pref)
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

// cacheTTL returns the number of seconds for which m is valid to be cached.
// For negative answers it follows RFC 2308 on how to cache NXDOMAIN and NODATA
// kinds of responses.
//
// See https://datatracker.ietf.org/doc/html/rfc2308#section-2.1,
// https://datatracker.ietf.org/doc/html/rfc2308#section-2.2.
func cacheTTL(m *dns.Msg) (ttl uint32) {
	switch {
	case m == nil:
		return 0
	case m.Truncated:
		log.Debug("dnsproxy: cache: truncated message; not caching")

		return 0
	case len(m.Question) != 1:
		log.Debug("dnsproxy: cache: message with wrong number of questions; not caching")

		return 0
	default:
		ttl = calculateTTL(m)
		if ttl == 0 {
			log.Debug("dnsproxy: cache: ttl calculated to be 0; not caching")

			return 0
		}
	}

	switch rcode := m.Rcode; rcode {
	case dns.RcodeSuccess:
		if isCacheableSucceded(m) {
			return ttl
		}

		log.Debug("dnsproxy: cache: not a cacheable noerror response; not caching")
	case dns.RcodeNameError:
		if isCacheableNegative(m) {
			return ttl
		}

		log.Debug("dnsproxy: cache: not a cacheable nxdomain response; not caching")
	case dns.RcodeServerFailure:
		return ttl
	default:
		log.Debug("dnsproxy: cache: response code %s; not caching", dns.RcodeToString[rcode])
	}

	return 0
}

// hasIPAns check the m for containing at least one A or AAAA RR in answer
// section.
func hasIPAns(m *dns.Msg) (ok bool) {
	for _, rr := range m.Answer {
		if t := rr.Header().Rrtype; t == dns.TypeA || t == dns.TypeAAAA {
			return true
		}
	}

	return false
}

// isCacheableSucceded returns true if m contains useful data to be cached
// treating it as a successful response.
func isCacheableSucceded(m *dns.Msg) (ok bool) {
	qType := m.Question[0].Qtype

	return (qType != dns.TypeA && qType != dns.TypeAAAA) || hasIPAns(m) || isCacheableNegative(m)
}

// isCacheableNegative returns true if m's header has at least a single SOA RR
// and no NS records so that it can be declared authoritative.
//
// See https://datatracker.ietf.org/doc/html/rfc2308#section-5 for the
// information on the responses from the authoritative server that should be
// cached by the forwarder.
func isCacheableNegative(m *dns.Msg) (ok bool) {
	for _, rr := range m.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			ok = true
		case dns.TypeNS:
			return false
		default:
			// Go on.
		}
	}

	return ok
}

// ServFailMaxCacheTTL is the maximum time-to-live value for caching
// SERVFAIL responses in seconds.  It's consistent with the upper constraint
// of 5 minutes given by RFC 2308.
//
// See https://datatracker.ietf.org/doc/html/rfc2308#section-7.1.
const ServFailMaxCacheTTL = 30

// calculateTTL returns the number of seconds for which m could be cached.  It's
// usually the lowest TTL among all m's resource records.  It returns 0 if m
// isn't cacheable according to it's contents.
func calculateTTL(m *dns.Msg) (ttl uint32) {
	// Use the maximum value as a guard value.  If the inner loop is entered,
	// it's going to be rewritten with an actual TTL value that is lower than
	// MaxUint32.  If the inner loop isn't entered, catch that and return zero.
	ttl = math.MaxUint32
	for _, rrset := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range rrset {
			ttl = minTTL(rr.Header(), ttl)
			if ttl == 0 {
				return 0
			}
		}
	}

	switch {
	case m.Rcode == dns.RcodeServerFailure && ttl > ServFailMaxCacheTTL:
		return ServFailMaxCacheTTL
	case ttl == math.MaxUint32:
		return 0
	default:
		return ttl
	}
}

// minTTL returns the minimum of h's ttl and the passed ttl.
func minTTL(h *dns.RR_Header, ttl uint32) uint32 {
	switch {
	case h.Rrtype == dns.TypeOPT:
		return ttl
	case h.Ttl < ttl:
		return h.Ttl
	default:
		return ttl
	}
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
	b = make([]byte, packedMsgLenSz+packedMsgLenSz+len(name))

	// Put QTYPE, QCLASS, and QNAME.
	binary.BigEndian.PutUint16(b, q.Qtype)
	binary.BigEndian.PutUint16(b[packedMsgLenSz:], q.Qclass)
	copy(b[2*packedMsgLenSz:], strings.ToLower(name))

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
	//
	// TODO(d.kolyshev): We should put Qtype in key[1:].
	binary.BigEndian.PutUint16(key[:], q.Qtype)

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
