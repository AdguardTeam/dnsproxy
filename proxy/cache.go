package proxy

import (
	"encoding/binary"
	"math"
	"strings"
	"sync"
	"time"

	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

const (
	defaultCacheSize = 64 * 1024 // in bytes
)

type cache struct {
	items        glcache.Cache // cache
	cacheSize    int           // cache size (in bytes)
	sync.RWMutex               // lock
}

func (c *cache) Get(request *dns.Msg) (*dns.Msg, bool) {
	if request == nil || len(request.Question) != 1 {
		return nil, false
	}
	// create key for request
	key := key(request)
	c.Lock()
	if c.items == nil {
		c.Unlock()
		return nil, false
	}
	c.Unlock()
	data := c.items.Get(key)
	if data == nil {
		return nil, false
	}

	res, isExpired := unpackResponse(data, request)
	if res == nil {
		return nil, false
	}
	return res, !isExpired
}

func (c *cache) Set(m *dns.Msg) {
	if m == nil {
		return // no-op
	}

	if !isCacheable(m) {
		return
	}

	key := key(m)

	c.Lock()
	// lazy initialization for cache
	if c.items == nil {
		conf := glcache.Config{
			MaxSize:   defaultCacheSize,
			EnableLRU: true,
		}
		if c.cacheSize > 0 {
			conf.MaxSize = uint(c.cacheSize)
		}
		c.items = glcache.New(conf)
	}
	c.Unlock()

	data := packResponse(m)
	_ = c.items.Set(key, data)
}

// check if message is cacheable
func isCacheable(m *dns.Msg) bool {
	// truncated messages aren't valid
	if m.Truncated {
		log.Tracef("Refusing to cache truncated message")
		return false
	}

	// if has wrong number of questions, also don't cache
	if len(m.Question) != 1 {
		log.Tracef("Refusing to cache message with wrong number of questions")
		return false
	}

	qName := m.Question[0].Name
	qType := m.Question[0].Qtype

	ttl := findLowestTTL(m)
	if ttl == 0 {
		return false
	}

	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		log.Tracef("%s: refusing to cache message with response type %s", qName, dns.RcodeToString[m.Rcode])
		return false
	}

	if m.Rcode == dns.RcodeSuccess && (qType == dns.TypeA || qType == dns.TypeAAAA) {
		// Now verify that it contains at least one A or AAAA record
		if len(m.Answer) == 0 {
			log.Tracef("%s: refusing to cache a NOERROR response with no answers", qName)
			return false
		}

		found := false
		for _, rr := range m.Answer {
			if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
				found = true
				break
			}
		}

		if !found {
			log.Tracef("%s: refusing to cache a response with no A and AAAA answers", qName)
			return false
		}
	}

	return true
}

func findLowestTTL(m *dns.Msg) uint32 {
	var ttl uint32 = math.MaxUint32

	if m.Answer != nil {
		for _, r := range m.Answer {
			ttl = getTTLIfLower(r.Header(), ttl)
		}
	}

	if m.Ns != nil {
		for _, r := range m.Ns {
			ttl = getTTLIfLower(r.Header(), ttl)
		}
	}

	if m.Extra != nil {
		for _, r := range m.Extra {
			ttl = getTTLIfLower(r.Header(), ttl)
		}
	}

	if ttl == math.MaxUint32 {
		return 0
	}

	return ttl
}

func getTTLIfLower(h *dns.RR_Header, ttl uint32) uint32 {
	if h.Rrtype == dns.TypeOPT {
		return ttl
	}
	if h.Ttl < ttl {
		return h.Ttl
	}
	return ttl
}

// Updates a given TTL to fall within the range specified
// by the cacheMinTTL and cacheMaxTTL settings
func respectTTLOverrides(ttl uint32, cacheMinTTL uint32, cacheMaxTTL uint32) uint32 {
	if ttl < cacheMinTTL {
		return cacheMinTTL
	}

	if cacheMaxTTL != 0 && ttl > cacheMaxTTL {
		return cacheMaxTTL
	}

	return ttl
}

// key constructs the cache key from type, class and question's name of m.
func key(m *dns.Msg) []byte {
	q := m.Question[0]
	name := q.Name
	b := make([]byte, 2+2+len(name))

	// put qtype, qclass, name
	binary.BigEndian.PutUint16(b, q.Qtype)
	binary.BigEndian.PutUint16(b[2:], q.Qclass)
	copy(b[4:], strings.ToLower(name))
	return b
}

// isDNSSEC returns true if r is a DNSSEC record.  NSEC,NSEC3,DS and RRSIG/SIG
// are DNSSEC records.  DNSKEYs is not in this list on the assumption that the
// client explicitly asked for it.
func isDNSSEC(r dns.RR) bool {
	switch r.Header().Rrtype {
	case dns.TypeNSEC, dns.TypeNSEC3, dns.TypeDS, dns.TypeRRSIG, dns.TypeSIG:
		return true

	default:
		return false
	}
}

// filterRRSlice removes OPT RRs, DNSSEC RRs if do is false, sets TTL if ttl is
// not equal to zero and returns the copy of the rrs.
func filterRRSlice(rrs []dns.RR, do bool, ttl uint32) (filtered []dns.RR) {
	if rrs == nil {
		return nil
	}

	j := 0
	rs := make([]dns.RR, len(rrs))
	for _, r := range rrs {
		if !do && isDNSSEC(r) {
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

	dst.Answer = filterRRSlice(m.Answer, do, ttl)
	dst.Ns = filterRRSlice(m.Ns, do, ttl)
	dst.Extra = filterRRSlice(m.Extra, do, ttl)
}

// unpackResponse returns the unpacked response if it exists and if it is expired,
func unpackResponse(data []byte, request *dns.Msg) (*dns.Msg, bool) {
	expire := binary.BigEndian.Uint32(data[:4])
	now := time.Now().Unix()

	ttl := int64(expire) - now
	isExpired := ttl <= 0

	// if expired,set the ttl to 60
	if isExpired {
		ttl = 60
	}

	m := &dns.Msg{}
	if m.Unpack(data[4:]) != nil {
		return nil, false
	}

	adBit := request.AuthenticatedData
	var doBit bool
	if o := request.IsEdns0(); o != nil {
		doBit = o.Do()
	}

	res := &dns.Msg{}
	res.SetReply(request)
	res.AuthenticatedData = m.AuthenticatedData
	res.RecursionAvailable = m.RecursionAvailable
	res.Rcode = m.Rcode

	// Don't return OPT records from cache since it's deprecated by RFC-6891
	// (https://tools.ietf.org/html/rfc6891).
	filterMsg(res, m, adBit, doBit, uint32(ttl))

	return res, isExpired
}
