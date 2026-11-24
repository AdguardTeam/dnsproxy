package proxy

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/cache/bytecache"
	"github.com/c2h5oh/datasize"
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

	// items is the requests cache.
	items bytecache.Interface

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
// into item for storing it in cache.  l and m must not be nil.
func respToItem(
	ctx context.Context,
	l *slog.Logger,
	m *dns.Msg,
	u upstream.Upstream,
) (item *cacheItem) {
	ttl := dnsmsg.CacheTTL(ctx, l, m)
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
		optimistic:       p.cacheOptimistic,
	})
	p.shortFlighter = newOptimisticResolver(p)
}

// cacheConfig is the configuration structure for [cache].
type cacheConfig struct {
	// size is the cache size in bytes.
	size datasize.ByteSize

	// optimisticTTL is the default TTL for expired cached responses when
	// optimistic is enabled.  It must not be negative.
	optimisticTTL time.Duration

	// optimisticMaxAge is the maximum time entries remain in the cache when
	// cache is optimistic.
	optimisticMaxAge time.Duration

	// optimistic defines if the cache should return expired items and resolve
	// those again.
	optimistic bool
}

// newCache returns a new properly initialized cache.  conf must be non-nil and
// valid.
func newCache(conf *cacheConfig) (c *cache) {
	return &cache{
		itemsLock:        &sync.RWMutex{},
		items:            newByteCache(conf.size),
		optimistic:       conf.optimistic,
		optimisticTTL:    conf.optimisticTTL,
		optimisticMaxAge: conf.optimisticMaxAge,
	}
}

// get returns cached item for the req if it's found.  expired is true if the
// item's TTL is expired.  key is the resulting key for req.  It's returned to
// avoid recalculating it afterwards.
func (c *cache) get(
	req *dns.Msg,
	subnet *net.IPNet,
	isPrivateClient bool,
) (ci *cacheItem, expired bool, key []byte) {
	c.itemsLock.RLock()
	defer c.itemsLock.RUnlock()

	if !canLookUpInCache(c.items, req) {
		return nil, false, nil
	}

	key = msgToKey(req, subnet, isPrivateClient)

	var ones int
	if subnet != nil && subnet.Mask != nil {
		ones, _ = subnet.Mask.Size()
	}

	data, ok := c.items.Get(key)

	// In order to reduce allocations we apply mask on bits level.  As the key
	// k has ecsIP in bytes slice representation, each iteration we can just
	// clear one bit in the end of it by applying the bitmask.
	for ones > 0 && !ok {
		ones--

		// Set mask identification byte in the key.
		key[keyPrefixIndex] = byte(ones)

		key[keyAddrIndex+ones/8] &= ^byte(0) << (8 - ones%8)

		data, ok = c.items.Get(key)
	}

	if !ok {
		key[keyFamilyIndex] = keyFamilyNone
		clear(key[keyAddrIndex : keyAddrIndex+keyAddrLen])
		data, ok = c.items.Get(key)
	}

	if !ok {
		return nil, false, key
	}

	if ci, expired = c.unpackItem(data, req); ci == nil {
		c.items.Del(key)
	}

	return ci, expired, key
}

// canLookUpInCache returns true if these parameters could be used to make a
// cache lookup.
func canLookUpInCache(cache bytecache.Interface, req *dns.Msg) (ok bool) {
	return cache != nil && req != nil && len(req.Question) == 1
}

// newByteCache returns a new byte cache with the given cacheSize.  If cacheSize
// is zero, [defaultCacheSize] is used.
func newByteCache(cacheSize datasize.ByteSize) (c bytecache.Interface) {
	return bytecache.NewDefault(&bytecache.DefaultConfig{
		MaxSize: cmp.Or(cacheSize, defaultCacheSize),
	})
}

// set stores response and upstream for req in the cache.  l, req, and m must
// not be nil.
func (c *cache) set(
	ctx context.Context,
	l *slog.Logger,
	req *dns.Msg,
	m *dns.Msg,
	u upstream.Upstream,
	subnet *net.IPNet,
	isPrivateClient bool,
) {
	item := respToItem(ctx, l, m, u)
	if item == nil {
		return
	}

	key := msgToKey(req, subnet, isPrivateClient)
	packed := item.pack()

	c.itemsLock.Lock()
	defer c.itemsLock.Unlock()

	c.items.Set(key, packed)
}

// ServFailMaxCacheTTL is the maximum time-to-live value for caching
// SERVFAIL responses in seconds.  It's consistent with the upper constraint
// of 5 minutes given by RFC 2308.
//
// See https://datatracker.ietf.org/doc/html/rfc2308#section-7.1.
//
// Deprecated: This value appears unused and will be removed in the future
// releases.
const ServFailMaxCacheTTL = dnsmsg.ServFailMaxCacheTTL

// clearItems empties the simple cache.
func (c *cache) clearItems() {
	c.itemsLock.Lock()
	defer c.itemsLock.Unlock()

	c.items.Clear()
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

// msgToKey constructs the cache key from type, class and question's name of m
// and optionally from the subnet if provided.  m must not be nil.  subnet may
// be nil.  isPrivateClient must be true if the client is considered private.
func msgToKey(m *dns.Msg, subnet *net.IPNet, isPrivateClient bool) (key []byte) {
	q := m.Question[0]
	name := q.Name
	key = make([]byte, keyHeaderLen+len(name))

	opt := m.IsEdns0()

	key[0] = 0

	if opt != nil && opt.Do() {
		key[0] |= keyFlagDO
	}

	if isPrivateClient {
		key[0] |= keyFlagPrivateClient
	}

	// Put QTYPE.
	binary.BigEndian.PutUint16(key[1:], q.Qtype)

	// Put QCLASS.
	binary.BigEndian.PutUint16(key[1+packedMsgLenSz:], q.Qclass)

	// Add subnet information if available.
	setSubnet(subnet, key)

	// Put QNAME.
	copy(key[keyHeaderLen:], strings.ToLower(q.Name))

	return key
}

// setSubnet encodes the subnet into the family, prefix, and address bytes of
// key.  key must be at least keyHeaderLen bytes long.
func setSubnet(subnet *net.IPNet, key []byte) {
	if subnet == nil || subnet.Mask == nil {
		return
	}

	ones, _ := subnet.Mask.Size()
	if ones <= 0 {
		return
	}

	masked := subnet.IP.Mask(subnet.Mask)

	if len(masked) == net.IPv4len {
		key[keyFamilyIndex] = keyFamilyIPv4
		key[keyPrefixIndex] = uint8(ones)
		copy(key[keyAddrIndex:], masked)
	} else if len(masked) == net.IPv6len {
		key[keyFamilyIndex] = keyFamilyIPv6
		key[keyPrefixIndex] = uint8(ones)
		copy(key[keyAddrIndex:], masked)
	}
}

// Cache key layout constants.
const (
	keyFamilyNone        = 0
	keyFamilyIPv4        = 1
	keyFamilyIPv6        = 2
	keyFamilyIndex       = 1 + 2*packedMsgLenSz
	keyPrefixIndex       = keyFamilyIndex + 1
	keyAddrIndex         = keyPrefixIndex + 1
	keyAddrLen           = net.IPv6len
	keyHeaderLen         = keyAddrIndex + keyAddrLen
	keyFlagDO            = 0x01
	keyFlagPrivateClient = 0x02
)

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
