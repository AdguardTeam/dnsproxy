package proxy

import (
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

// cache is used to cache requests.
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
	// optimistic defines if the cache should return expired items and
	// resolve those again.
	optimistic bool
}

// initCache initializes cache in case it is enabled.
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
		p.setInCache,
		c.Delete,
	)
	p.shortFlighterWithSubnet = newOptimisticResolver(
		p.replyFromUpstream,
		p.setInCache,
		c.DeleteWithSubnet,
	)
}

// Get returns cached *dns.Msg if it's found.  Nil otherwise.
func (c *cache) Get(req *dns.Msg) (res *dns.Msg, expired bool, key []byte) {
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

	if res, expired = unpackResponse(data, req, c.optimistic); res == nil {
		c.items.Del(key)
	}

	return res, expired, key
}

// GetWithSubnet returns cached *dns.Msg if it's found by client IP and subnet
// mask.  Nil otherwise.  Note that a slow longest-prefix-match algorithm used,
// so cache searches are performed up to mask+1 times.
func (c *cache) GetWithSubnet(req *dns.Msg, cliIP net.IP, mask uint8) (
	res *dns.Msg,
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

	if res, expired = unpackResponse(data, req, c.optimistic); res == nil {
		c.itemsWithSubnet.Del(key)
	}

	return res, expired, key
}

// initLazy initializes the cache for requests.
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
	maxSize := defaultCacheSize
	if c.cacheSize > 0 {
		maxSize = c.cacheSize
	}
	conf := glcache.Config{
		MaxSize:   uint(maxSize),
		EnableLRU: true,
	}

	return glcache.New(conf)
}

// Set tries to add the request into cache.
func (c *cache) Set(m *dns.Msg) {
	if !isCacheable(m) {
		return
	}

	c.initLazy()

	key := msgToKey(m)
	data := packResponse(m)

	c.itemsLock.RLock()
	defer c.itemsLock.RUnlock()

	c.items.Set(key, data)
}

// SetWithSubnet tries to add the request with subnet into cache.
func (c *cache) SetWithSubnet(m *dns.Msg, ip net.IP, mask uint8) {
	if !isCacheable(m) {
		return
	}

	c.initLazyWithSubnet()

	key := msgToKeyWithSubnet(m, ip, mask)
	data := packResponse(m)

	c.itemsWithSubnetLock.RLock()
	defer c.itemsWithSubnetLock.RUnlock()

	c.itemsWithSubnet.Set(key, data)
}

// isCacheable checks if m is valid to be cached.
func isCacheable(m *dns.Msg) bool {
	if m == nil {
		return false
	}

	// Truncated messages aren't valid.
	if m.Truncated {
		log.Tracef("Refusing to cache truncated message")

		return false
	}

	// If has wrong number of questions, also don't cache.
	if len(m.Question) != 1 {
		log.Tracef("Refusing to cache message with wrong number of questions")

		return false
	}

	if findLowestTTL(m) == 0 {
		return false
	}

	qName := m.Question[0].Name
	rcode := m.Rcode
	if rcode != dns.RcodeSuccess && rcode != dns.RcodeNameError {
		log.Tracef(
			"%s: refusing to cache message with response type %s",
			qName,
			dns.RcodeToString[rcode],
		)

		return false
	}

	if qType := m.Question[0].Qtype; m.Rcode != dns.RcodeSuccess ||
		(qType != dns.TypeA && qType != dns.TypeAAAA) {
		return true
	}

	// Now verify that it contains at least one A or AAAA record.
	if len(m.Answer) == 0 {
		log.Tracef(
			"%s: refusing to cache a NOERROR response with no answers",
			qName,
		)

		return false
	}

	for _, rr := range m.Answer {
		if h := rr.Header(); h.Rrtype == dns.TypeA || h.Rrtype == dns.TypeAAAA {
			return true
		}
	}

	log.Tracef("%s: refusing to cache a response with no A and AAAA answers", qName)

	return false
}

// findLowestTTL returns the lowest TTL in m's RRs or 0 if the information is
// absent.
func findLowestTTL(m *dns.Msg) (ttl uint32) {
	ttl = math.MaxUint32

	for _, r := range m.Answer {
		ttl = getTTLIfLower(r.Header(), ttl)
	}

	for _, r := range m.Ns {
		ttl = getTTLIfLower(r.Header(), ttl)
	}

	for _, r := range m.Extra {
		ttl = getTTLIfLower(r.Header(), ttl)
	}

	if ttl == math.MaxUint32 {
		return 0
	}

	return ttl
}

// getTTLIfLower returns the minimum of h's ttl and the passed ttl.
func getTTLIfLower(h *dns.RR_Header, ttl uint32) uint32 {
	if h.Rrtype == dns.TypeOPT {
		return ttl
	}
	if h.Ttl < ttl {
		return h.Ttl
	}
	return ttl
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
func msgToKey(m *dns.Msg) []byte {
	q := m.Question[0]
	name := q.Name
	b := make([]byte, 2+2+len(name))

	// put qtype, qclass, name
	binary.BigEndian.PutUint16(b, q.Qtype)
	binary.BigEndian.PutUint16(b[2:], q.Qclass)
	copy(b[4:], strings.ToLower(name))
	return b
}

// msgToKeyWithSubnet constructs the cache key from DO bit, type, class, subnet
// mask, client's IP address and question's name of m.
func msgToKeyWithSubnet(m *dns.Msg, ip net.IP, mask uint8) []byte {
	q := m.Question[0]
	cap := 1 + 2 + 2 + 1 + len(q.Name)
	if mask != 0 {
		cap += len(ip)
	}

	// init the array
	b := make([]byte, cap)
	k := 0

	// put do
	opt := m.IsEdns0()
	do := false
	if opt != nil {
		do = opt.Do()
	}
	if do {
		b[k] = 1
	} else {
		b[k] = 0
	}
	k++

	// put qtype
	binary.BigEndian.PutUint16(b[:], q.Qtype)
	k += 2

	// put qclass
	binary.BigEndian.PutUint16(b[k:], q.Qclass)
	k += 2

	// add mask
	b[k] = mask
	k++
	if mask != 0 {
		copy(b[k:], ip)
		k += len(ip)
	}

	copy(b[k:], strings.ToLower(q.Name))
	return b
}

// isDNSSEC returns true if r is a DNSSEC RR.  NSEC, NSEC3, DS, DNSKEY and
// RRSIG/SIG are DNSSEC records.
func isDNSSEC(r dns.RR) bool {
	switch r.Header().Rrtype {
	case dns.TypeNSEC, dns.TypeNSEC3, dns.TypeDS, dns.TypeRRSIG, dns.TypeSIG, dns.TypeDNSKEY:
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
		if !do && isDNSSEC(r) && r.Header().Rrtype != except {
			continue
		}
		if r.Header().Rrtype == dns.TypeOPT {
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

// packResponse turns m into a byte slice where first 4 bytes contain the expire
// value.
func packResponse(m *dns.Msg) []byte {
	pm, _ := m.Pack()
	actualTTL := findLowestTTL(m)
	expire := uint32(time.Now().Unix()) + actualTTL
	d := make([]byte, 4+len(pm))
	binary.BigEndian.PutUint32(d, expire)
	copy(d[4:], pm)

	return d
}

// filterMsg removes OPT RRs, DNSSEC RRs if do is false, sets TTL to ttl if it's
// not equal to 0 and puts the results to appropriate fields of dst.  It also
// filters the AD bit if both ad and do are false.
func filterMsg(dst, m *dns.Msg, ad, do bool, ttl uint32) {
	// As RFC-6840 (https://tools.ietf.org/html/rfc6840) says, validating
	// resolvers should only set the AD bit when a response both meets the
	// conditions listed in RFC-4035 (https://tools.ietf.org/html/rfc4035),
	// and the request contained either a set DO bit or a set AD bit.
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

// optimisticTTL is the default TTL for expired cached response.
const optimisticTTL = 60

// unpackResponse returns the unpacked response if it exists.  The returnExpired
// controls whether or not the expired response should be omitted.
func unpackResponse(data []byte, req *dns.Msg, returnExpired bool) (res *dns.Msg, expired bool) {
	expire := binary.BigEndian.Uint32(data[:4])
	now := time.Now().Unix()
	var ttl uint32
	if int64(expire) <= now {
		expired = true
		if !returnExpired {
			return nil, expired
		}

		ttl = optimisticTTL
	} else {
		ttl = expire - uint32(now)
	}

	m := &dns.Msg{}
	if m.Unpack(data[4:]) != nil {
		return nil, expired
	}

	adBit := req.AuthenticatedData
	var doBit bool
	if o := req.IsEdns0(); o != nil {
		doBit = o.Do()
	}

	res = &dns.Msg{}
	res.SetReply(req)
	res.AuthenticatedData = m.AuthenticatedData
	res.RecursionAvailable = m.RecursionAvailable
	res.Rcode = m.Rcode

	// Don't return OPT records from cache since it's deprecated by RFC-6891
	// (https://tools.ietf.org/html/rfc6891).
	// Also, if the request has DO bit set we only remove all the OPT
	// RRs, and also all DNSSEC RRs otherwise.
	filterMsg(res, m, adBit, doBit, ttl)

	return res, expired
}

func (c *cache) Delete(key []byte) {
	c.itemsLock.RLock()
	defer c.itemsLock.RUnlock()

	if c.items == nil {
		return
	}

	c.items.Del(key)
}

func (c *cache) DeleteWithSubnet(key []byte) {
	c.itemsWithSubnetLock.RLock()
	defer c.itemsWithSubnetLock.RUnlock()

	if c.itemsWithSubnet == nil {
		return
	}

	c.itemsWithSubnet.Del(key)
}
