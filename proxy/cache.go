package proxy

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// defaultCacheSize is the size of cache in bytes by default.
const defaultCacheSize = 64 * 1024

// cache is used to cache requests and used upstreams.
type cache struct {
	// items is the requests cache.
	items glcache.Cache
	// itemsLock protects requests cache.
	itemsLock sync.RWMutex

	// itemsWithSubnet is the requests cache.
	itemsWithSubnet glcache.Cache
	// itemsWithSubnetLock protects requests cache.
	itemsWithSubnetLock sync.RWMutex

	// cacheSize is the size of a key-value pair of cache.
	cacheSize int
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
	binary.BigEndian.PutUint32(packed, uint32(time.Now().Unix())+lowestTTL(ci.m))

	// Put the length of the packed message.
	binary.BigEndian.PutUint16(packed[expTimeSz:], uint16(pmLen))

	// Put the packed message itself.
	packed = append(packed, pm...)

	// Put the address of the upstream.
	packed = append(packed, ci.u...)

	return packed
}

// optimisticTTL is the default TTL for expired cached responses in seconds.
const optimisticTTL = 60

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
		return
	}

	log.Printf("DNS cache is enabled")

	c := &cache{
		optimistic: p.CacheOptimistic,
		cacheSize:  p.CacheSizeBytes,
	}
	p.cache = c
	c.initLazy()
	if p.EnableEDNSClientSubnet {
		c.initLazyWithSubnet()
	}

	p.shortFlighter = newOptimisticResolver(
		p.replyFromUpstream,
		p.cacheResp,
		c.del,
	)
	p.shortFlighterWithSubnet = newOptimisticResolver(
		p.replyFromUpstream,
		p.cacheResp,
		c.delWithSubnet,
	)
}

// get returns cached item for the req if it's found.  expired is true if the
// item's TTL is expired.  key is the resulting key for req.  It's returned to
// avoid recalculating it afterwards.
func (c *cache) get(req *dns.Msg) (ci *cacheItem, expired bool, key []byte) {
	c.itemsLock.RLock()
	defer c.itemsLock.RUnlock()

	if c.items == nil || req == nil || len(req.Question) != 1 {
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

// getWithSubnet returns cached item for the req if it's found by client's IP
// and a subnet mask.  expired is true if the item's TTL is expired.  key is the
// resulting key for req.  It's returned to avoid recalculating it afterwards.
//
// Note that a slow longest-prefix-match algorithm is used, so cache searches
// are performed up to mask+1 times.
func (c *cache) getWithSubnet(req *dns.Msg, cliIP net.IP, mask uint8) (
	ci *cacheItem,
	expired bool,
	key []byte,
) {
	c.itemsWithSubnetLock.RLock()
	defer c.itemsWithSubnetLock.RUnlock()

	if c.itemsWithSubnet == nil || req == nil || len(req.Question) != 1 {
		return nil, false, nil
	}

	var data []byte
	for mask++; mask > 0 && data == nil; {
		mask--
		key = msgToKeyWithSubnet(req, cliIP, mask)
		data = c.itemsWithSubnet.Get(key)
	}
	if data == nil {
		return nil, false, key
	}

	if ci, expired = c.unpackItem(data, req); ci == nil {
		c.items.Del(key)
	}

	return ci, expired, key
}

// initLazy initializes the cache for general requests.
func (c *cache) initLazy() {
	c.itemsLock.Lock()
	defer c.itemsLock.Unlock()

	if c.items == nil {
		c.items = c.createCache()
	}
}

// initLazyWithSubnet initializes the cache for requests with subnets.
func (c *cache) initLazyWithSubnet() {
	c.itemsWithSubnetLock.Lock()
	defer c.itemsWithSubnetLock.Unlock()

	if c.itemsWithSubnet == nil {
		c.itemsWithSubnet = c.createCache()
	}
}

// createCache returns new Cache with predefined settings.
func (c *cache) createCache() (glc glcache.Cache) {
	conf := glcache.Config{
		MaxSize:   defaultCacheSize,
		EnableLRU: true,
	}

	if c.cacheSize > 0 {
		conf.MaxSize = uint(c.cacheSize)
	}

	return glcache.New(conf)
}

// set tries to add the ci into cache.
func (c *cache) set(ci *cacheItem) {
	if !isCacheable(ci.m) {
		return
	}

	c.initLazy()

	key := msgToKey(ci.m)
	packed := ci.pack()

	c.itemsLock.RLock()
	defer c.itemsLock.RUnlock()

	c.items.Set(key, packed)
}

// setWithSubnet tries to add the ci into cache with subnet and ip used to
// calculate the key.
func (c *cache) setWithSubnet(ci *cacheItem, ip net.IP, mask uint8) {
	if !isCacheable(ci.m) {
		return
	}

	c.initLazyWithSubnet()

	key := msgToKeyWithSubnet(ci.m, ip, mask)
	packed := ci.pack()

	c.itemsWithSubnetLock.RLock()
	defer c.itemsWithSubnetLock.RUnlock()

	c.itemsWithSubnet.Set(key, packed)
}

// isCacheable checks if m is valid to be cached.  For negative answers it
// follows RFC 2308 on how to cache NXDOMAIN and NODATA kinds of responses.
//
// See https://datatracker.ietf.org/doc/html/rfc2308#section-2.1,
// https://datatracker.ietf.org/doc/html/rfc2308#section-2.2.
func isCacheable(m *dns.Msg) bool {
	switch {
	case m == nil:
		return false
	case m.Truncated:
		log.Tracef("refusing to cache truncated message")

		return false
	case len(m.Question) != 1:
		log.Tracef("refusing to cache message with wrong number of questions")

		return false
	case lowestTTL(m) == 0:
		return false
	}

	qName := m.Question[0].Name
	switch rcode := m.Rcode; rcode {
	case dns.RcodeSuccess:
		if qType := m.Question[0].Qtype; qType != dns.TypeA && qType != dns.TypeAAAA {
			return true
		}

		return hasIPAns(m) || isCacheableNegative(m)
	case dns.RcodeNameError:
		return isCacheableNegative(m)
	default:
		log.Tracef(
			"%s: refusing to cache message with response code %s",
			qName,
			dns.RcodeToString[rcode],
		)

		return false
	}
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

// lowestTTL returns the lowest TTL in m's RRs or 0 if the information is
// absent.
func lowestTTL(m *dns.Msg) (ttl uint32) {
	ttl = math.MaxUint32

	for _, rrset := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, r := range rrset {
			ttl = minTTL(r.Header(), ttl)
		}
	}

	if ttl == math.MaxUint32 {
		return 0
	}

	return ttl
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
func respectTTLOverrides(ttl uint32, cacheMinTTL uint32, cacheMaxTTL uint32) uint32 {
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

// msgToKeyWithSubnet constructs the cache key from DO bit, type, class, subnet
// mask, client's IP address and question's name of m.
func msgToKeyWithSubnet(m *dns.Msg, clientIP net.IP, mask uint8) (key []byte) {
	q := m.Question[0]
	cap := 1 + 2*packedMsgLenSz + 1 + len(q.Name)
	ipLen := len(clientIP)
	masked := mask != 0
	if masked {
		cap += ipLen
	}

	// Initialize the slice.
	key = make([]byte, cap)
	k := 0

	// Put DO.
	if opt := m.IsEdns0(); opt != nil && opt.Do() {
		key[k] = 1
	} else {
		key[k] = 0
	}
	k++

	// Put Qtype.
	binary.BigEndian.PutUint16(key[:], q.Qtype)
	k += packedMsgLenSz

	// Put Qclass.
	binary.BigEndian.PutUint16(key[k:], q.Qclass)
	k += packedMsgLenSz

	// Add mask.
	key[k] = mask
	k++
	if masked {
		k += copy(key[k:], clientIP)
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

func (c *cache) del(key []byte) {
	c.itemsLock.RLock()
	defer c.itemsLock.RUnlock()

	if c.items == nil {
		return
	}

	c.items.Del(key)
}

func (c *cache) delWithSubnet(key []byte) {
	c.itemsWithSubnetLock.RLock()
	defer c.itemsWithSubnetLock.RUnlock()

	if c.itemsWithSubnet == nil {
		return
	}

	c.itemsWithSubnet.Del(key)
}
