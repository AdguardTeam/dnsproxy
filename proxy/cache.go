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

const defaultCacheSize = 64 * 1024 // in bytes

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

	res := unpackResponse(data, request)
	if res == nil {
		c.items.Del(key)
		return nil, false
	}
	return res, true
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

// Format:
// uint16(qtype)
// uint16(qclass)
// name
func key(m *dns.Msg) []byte {
	q := m.Question[0]
	b := make([]byte, 2+2+len(q.Name))
	binary.BigEndian.PutUint16(b[:], q.Qtype)
	binary.BigEndian.PutUint16(b[2:], q.Qclass)
	name := strings.ToLower(q.Name)
	copy(b[4:], name)
	return b
}

/*
expire [4]byte
dns_message []byte
*/
func packResponse(m *dns.Msg) []byte {
	pm, _ := m.Pack()
	expire := uint32(time.Now().Unix()) + findLowestTTL(m)
	var d []byte
	d = make([]byte, 4+len(pm))
	binary.BigEndian.PutUint32(d, expire)
	copy(d[4:], pm)
	return d
}

// Return nil if response has expired
func unpackResponse(data []byte, request *dns.Msg) *dns.Msg {
	now := time.Now().Unix()
	expire := binary.BigEndian.Uint32(data[:4])
	if int64(expire) <= now {
		return nil
	}
	ttl := expire - uint32(now)

	m := dns.Msg{}
	err := m.Unpack(data[4:])
	if err != nil {
		return nil
	}

	res := dns.Msg{}
	res.SetReply(request)
	res.Authoritative = false
	res.AuthenticatedData = m.AuthenticatedData
	res.RecursionAvailable = m.RecursionAvailable
	res.Rcode = m.Rcode

	for _, r := range m.Answer {
		answer := dns.Copy(r)
		answer.Header().Ttl = ttl
		res.Answer = append(res.Answer, answer)
	}
	for _, r := range m.Ns {
		ns := dns.Copy(r)
		ns.Header().Ttl = ttl
		res.Ns = append(res.Ns, ns)
	}
	for _, r := range m.Extra {
		// don't return OPT records as these are hop-by-hop
		if r.Header().Rrtype == dns.TypeOPT {
			continue
		}
		extra := dns.Copy(r)
		extra.Header().Ttl = ttl
		res.Extra = append(res.Extra, extra)
	}
	return &res
}
