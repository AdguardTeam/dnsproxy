package proxy

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/VictoriaMetrics/fastcache"
	"github.com/miekg/dns"
)

const defaultCacheSize = 64 * 1024 // in bytes

type item struct {
	Msg  []byte    // dns message
	When time.Time // time when m was cached
	TTL  time.Duration
}

type cache struct {
	items        *fastcache.Cache // cache
	cacheSize    int              // cache size
	sync.RWMutex                  // lock
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

	rawValue := c.items.Get(nil, []byte(key))
	var buf bytes.Buffer
	buf.Write(rawValue)
	dec := gob.NewDecoder(&buf)
	cachedValue := item{}
	err := dec.Decode(&cachedValue)
	if err != nil {
		log.Debug("gob.Decode(): %s", err)
		return nil, false
	}

	if cachedValue.When.Unix()+int64(cachedValue.TTL.Seconds()) <= time.Now().Unix() {
		// Note that we can accidentally delete a fresh element here
		//  (when another thread removes this element and then re-adds a new element with the same host name)
		//  but hopefully this is a very rare case.
		c.items.Del([]byte(key))
		return nil, false
	}

	response := cachedValue.fromItem(request)
	return response, true
}

func (c *cache) Set(m *dns.Msg) {
	if m == nil {
		return // no-op
	}
	if !isRequestCacheable(m) {
		return
	}
	if !isResponseCacheable(m) {
		return
	}
	ok, key := key(m)
	if !ok {
		return
	}
	i := toItem(m)

	c.Lock()
	// lazy initialization for cache
	if c.items == nil {
		size := defaultCacheSize
		if c.cacheSize > 0 {
			size = c.cacheSize
		}
		c.items = fastcache.New(size)
	}
	c.Unlock()

	// set ttl as expiration time for item
	ttl := time.Duration(findLowestTTL(m)) * time.Second
	i.TTL = ttl
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(i)
	if err != nil {
		log.Debug("enc.Encode: %s", err)
		return
	}
	c.items.Set([]byte(key), buf.Bytes())
}

// check only request fields
func isRequestCacheable(m *dns.Msg) bool {
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

	// only OK or NXdomain replies are cached
	switch m.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError: // that's an NXDomain
	case dns.RcodeServerFailure:
		return false // quietly refuse, don't log
	default:
		log.Tracef("%s: Refusing to cache message with rcode: %s", m.Question[0].Name, dns.RcodeToString[m.Rcode])
		return false
	}

	return true
}

func isResponseCacheable(m *dns.Msg) bool {
	ttl := findLowestTTL(m)
	if ttl == 0 {
		return false
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
	response := &dns.Msg{}
	response.SetReply(request)

	m := dns.Msg{}
	m.Unpack(i.Msg)

	response.Authoritative = false
	response.AuthenticatedData = m.AuthenticatedData
	response.RecursionAvailable = m.RecursionAvailable
	response.Rcode = m.Rcode

	ttl := findLowestTTL(&m)
	timeleft := math.Round(float64(ttl) - time.Since(i.When).Seconds())
	var newttl uint32
	if timeleft > 0 {
		newttl = uint32(timeleft)
	}
	for _, r := range m.Answer {
		answer := dns.Copy(r)
		answer.Header().Ttl = newttl
		response.Answer = append(response.Answer, answer)
	}
	for _, r := range m.Ns {
		ns := dns.Copy(r)
		ns.Header().Ttl = newttl
		response.Ns = append(response.Ns, ns)
	}
	for _, r := range m.Extra {
		// don't return OPT records as these are hop-by-hop
		if r.Header().Rrtype == dns.TypeOPT {
			continue
		}
		extra := dns.Copy(r)
		extra.Header().Ttl = newttl
		response.Extra = append(response.Extra, extra)
	}
	return response
}
