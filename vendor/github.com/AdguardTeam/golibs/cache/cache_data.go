package cache

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

type onDeleteType func(key []byte, val []byte)

type cache struct {
	items map[string]*item

	// LRU: for removing the least recently used item on reaching cache size limit
	// Note: slows down Get() due to an additional work with pointers
	// Example: [ (sentinel) <-> item1 <-> item2 <-> (sentinel) ]
	// When the item is accessed, it's moved to the end of the list.
	usage listItem

	lock sync.Mutex
	size uint // current size in bytes (keys+values)

	conf Config

	// stats:
	miss int32 // number of misses
	hit  int32 // number of hits
}

type item struct {
	key   []byte
	value []byte
	used  listItem
}

const maxUint = (1 << (unsafe.Sizeof(uint(0)) * 8)) - 1

func newCache(conf Config) *cache {
	c := cache{}
	c.items = make(map[string]*item)
	listInit(&c.usage)
	c.conf = conf
	if c.conf.MaxSize == 0 {
		c.conf.MaxSize = maxUint
	}
	if c.conf.MaxCount == 0 {
		c.conf.MaxCount = maxUint
	}
	if c.conf.MaxElementSize == 0 {
		c.conf.MaxElementSize = c.conf.MaxSize
	}
	if c.conf.MaxElementSize > c.conf.MaxSize {
		c.conf.MaxElementSize = c.conf.MaxSize
	}
	return &c
}

func (c *cache) Clear() {
	c.lock.Lock()
	c.items = make(map[string]*item)
	listInit(&c.usage)
	c.size = 0
	c.lock.Unlock()
	atomic.StoreInt32(&c.hit, 0)
	atomic.StoreInt32(&c.miss, 0)
}

// Set value
func (c *cache) Set(key []byte, val []byte) bool {
	addSize := uint(len(key) + len(val))
	if addSize > c.conf.MaxElementSize {
		return false // too large data
	}

	it := item{}
	it.key = key
	it.value = val

	c.lock.Lock()

	if !c.conf.EnableLRU &&
		(c.size+addSize > c.conf.MaxSize || uint(len(c.items)) == c.conf.MaxCount) {
		c.lock.Unlock()
		return false // cache is full
	}

	for c.size+addSize > c.conf.MaxSize || uint(len(c.items)) == c.conf.MaxCount {
		first := listFirst(&c.usage)
		it := (*item)(structPtr(unsafe.Pointer(first), unsafe.Offsetof(item{}.used)))
		c.size -= uint(len(it.key) + len(it.value))
		listUnlink(first)
		delete(c.items, string(it.key))

		if c.conf.OnDelete != nil {
			c.lock.Unlock()
			c.conf.OnDelete(it.key, it.value)
			c.lock.Lock()
		}
	}

	if c.conf.EnableLRU {
		listAppend(&it.used, listLast(&c.usage))
	}

	it2, exists := c.items[string(key)]
	if exists {
		listUnlink(&it2.used)
		c.size -= uint(len(it2.key) + len(it2.value))
	}
	c.items[string(key)] = &it
	c.size += addSize
	c.lock.Unlock()

	return exists
}

// Get value
func (c *cache) Get(key []byte) []byte {
	c.lock.Lock()
	val, ok := c.items[string(key)]
	if ok && c.conf.EnableLRU {
		listUnlink(&val.used)
		listAppend(&val.used, listLast(&c.usage))
	}
	c.lock.Unlock()
	if !ok {
		atomic.AddInt32(&c.miss, 1)
		return nil
	}
	atomic.AddInt32(&c.hit, 1)
	return val.value
}

// Del - delete element
func (c *cache) Del(key []byte) {
	c.lock.Lock()
	it, ok := c.items[string(key)]
	if !ok {
		c.lock.Unlock()
		return
	}
	listUnlink(&it.used)
	c.size -= uint(len(it.key) + len(it.value))
	delete(c.items, string(key))
	c.lock.Unlock()
}

// GetStats - get counters
func (c *cache) Stats() Stats {
	s := Stats{}
	s.Count = len(c.items)
	s.Size = int(c.size)
	s.Hit = int(atomic.LoadInt32(&c.hit))
	s.Miss = int(atomic.LoadInt32(&c.miss))
	return s
}
