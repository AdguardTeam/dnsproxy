package proxy

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"

	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/miekg/dns"
)

type cacheSubnet struct {
	items        glcache.Cache // cache
	cacheSize    int           // cache size (in bytes)
	sync.RWMutex               // lock
}

// Get key
// Format:
// uint16(qtype)
// uint16(qclass)
// uint8(subnet_mask)
// client_ip
// name
func keyWithSubnet(m *dns.Msg, ip net.IP, mask uint8) []byte {
	q := m.Question[0]
	cap := 2 + 2 + 1 + len(q.Name)
	if mask != 0 {
		cap += len(ip)
	}
	b := make([]byte, cap)
	binary.BigEndian.PutUint16(b[:], q.Qtype)
	k := 2

	binary.BigEndian.PutUint16(b[k:], q.Qclass)
	k += 2

	b[k] = mask
	k++
	if mask != 0 {
		copy(b[k:], ip)
		k += len(ip)
	}

	copy(b[k:], strings.ToLower(q.Name))
	return b
}

// GetWithSubnet - get DNS response
// ip: client IP address
// mask: subnet mask for client IP address
// Return (response, true) if response is found
//  or (nil, false) on error
// Note: it's a slow longest-prefix-match algorithm -
//  we search in cache up to 'mask+1' times, decrementing the value with each iteration.
func (c *cacheSubnet) GetWithSubnet(request *dns.Msg, ip net.IP, mask uint8) (*dns.Msg, bool) {
	if request == nil || len(request.Question) != 1 {
		return nil, false
	}
	// create key for request
	c.Lock()
	if c.items == nil {
		c.Unlock()
		return nil, false
	}
	c.Unlock()

	var key, data []byte
	for {
		key = keyWithSubnet(request, ip, mask)
		data = c.items.Get(key)
		if data != nil {
			break
		}
		if mask == 0 {
			return nil, false
		}
		mask--
	}

	res := unpackResponse(data, request)
	if res == nil {
		c.items.Del(key)
		return nil, false
	}
	return res, true
}

// SetWithSubnet - store DNS response
// ip: IP subnet this response is valid for
// mask: subnet mask
func (c *cacheSubnet) SetWithSubnet(m *dns.Msg, ip net.IP, mask uint8) {
	if m == nil || !isCacheable(m) {
		return
	}
	key := keyWithSubnet(m, ip, mask)

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
