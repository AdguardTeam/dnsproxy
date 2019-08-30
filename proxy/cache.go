package proxy

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"math"
	"strings"
	"sync"
	"time"

	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

const defaultCacheSize = 64 * 1024 // in bytes

type item struct {
	Msg  []byte    // dns message
	When time.Time // time when m was cached
	TTL  time.Duration
}

type cache struct {
	items        glcache.Cache // cache
	cacheSize    int           // cache size (in bytes)
	sync.RWMutex               // lock
}

func (c *cache) Get(request *dns.Msg) (*dns.Msg, bool) {
	if request == nil {
		return nil, false
	}
	// create key for request
	ok, key := key(request)
	if !ok {
		log.Tracef("key returned !ok")
		return nil, false
	}
	c.Lock()
	if c.items == nil {
		c.Unlock()
		return nil, false
	}
	c.Unlock()
	rawValue := c.items.Get([]byte(key))
	if rawValue == nil {
		return nil, false
	}

	var buf bytes.Buffer
	buf.Write(rawValue)
	dec := gob.NewDecoder(&buf)
	cachedValue := item{}
	err := dec.Decode(&cachedValue)
	if err != nil {
		log.Error("gob.Decode: %s", err)
		return nil, false
	}

	if cachedValue.When.Unix()+int64(cachedValue.TTL.Seconds()) <= time.Now().Unix() {
		c.items.Del([]byte(key))
		return nil, false
	}

	res := cachedValue.fromItem(request)
	return res, true
}

func (c *cache) Set(m *dns.Msg) {
	if m == nil {
		return // no-op
	}
	if !isCacheable(m) {
		return
	}
	ok, key := key(m)
	if !ok {
		return
	}

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

	i := toItem(m)
	ttl := time.Duration(findLowestTTL(m)) * time.Second
	i.TTL = ttl
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(i)
	if err != nil {
		log.Debug("gob.Encode: %s", err)
		return
	}

	_ = c.items.Set([]byte(key), buf.Bytes())
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
	if ttl <= 0 {
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

// key is binary little endian in sequence:
// uint16(qtype) then uint16(qclass) then name
func key(m *dns.Msg) (bool, string) {
	if len(m.Question) != 1 {
		log.Tracef("got msg with len(m.Question) != 1: %d", len(m.Question))
		return false, ""
	}

	bb := strings.Builder{}
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, m.Question[0].Qtype)
	bb.Write(b)
	binary.LittleEndian.PutUint16(b, m.Question[0].Qclass)
	bb.Write(b)
	name := strings.ToLower(m.Question[0].Name)
	bb.WriteString(name)
	return true, bb.String()
}

func toItem(m *dns.Msg) item {
	i := item{
		When: time.Now(),
	}
	i.Msg, _ = m.Pack()
	return i
}

func (i *item) fromItem(request *dns.Msg) *dns.Msg {
	res := &dns.Msg{}
	res.SetReply(request)

	m := dns.Msg{}
	m.Unpack(i.Msg)

	res.Authoritative = false
	res.AuthenticatedData = m.AuthenticatedData
	res.RecursionAvailable = m.RecursionAvailable
	res.Rcode = m.Rcode

	ttl := findLowestTTL(&m)
	timeLeft := math.Round(float64(ttl) - time.Since(i.When).Seconds())
	var newTTL uint32
	if timeLeft > 0 {
		newTTL = uint32(timeLeft)
	}
	for _, r := range m.Answer {
		answer := dns.Copy(r)
		answer.Header().Ttl = newTTL
		res.Answer = append(res.Answer, answer)
	}
	for _, r := range m.Ns {
		ns := dns.Copy(r)
		ns.Header().Ttl = newTTL
		res.Ns = append(res.Ns, ns)
	}
	for _, r := range m.Extra {
		// don't return OPT records as these are hop-by-hop
		if r.Header().Rrtype == dns.TypeOPT {
			continue
		}
		extra := dns.Copy(r)
		extra.Header().Ttl = newTTL
		res.Extra = append(res.Extra, extra)
	}
	return res
}
