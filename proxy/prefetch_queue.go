package proxy

import (
	"net"
	"sync"
	"time"
)

// prefetchItemPool is a pool of PrefetchItem objects to reduce GC pressure
var prefetchItemPool = sync.Pool{
	New: func() interface{} {
		return &PrefetchItem{}
	},
}

// AcquirePrefetchItem gets an item from the pool
func AcquirePrefetchItem(domain string, qtype uint16, subnet *net.IPNet, expireTime time.Time) *PrefetchItem {
	item := prefetchItemPool.Get().(*PrefetchItem)
	item.Domain = domain
	item.QType = qtype
	item.Subnet = subnet
	item.ExpireTime = expireTime
	item.Priority = 0
	item.HitCount = 0
	item.index = -1
	return item
}

// ReleasePrefetchItem returns an item to the pool
func ReleasePrefetchItem(item *PrefetchItem) {
	item.Domain = ""
	item.QType = 0
	item.Subnet = nil
	item.ExpireTime = time.Time{}
	item.Priority = 0
	item.HitCount = 0
	item.index = -1
	prefetchItemPool.Put(item)
}

// PrefetchItem represents a DNS query that needs to be refreshed
type PrefetchItem struct {
	Domain     string
	QType      uint16
	Subnet     *net.IPNet
	ExpireTime time.Time
	Priority   int64 // Lower value means higher priority (sooner to expire)
	HitCount   int   // Number of hits while in queue
	index      int   // Index in the heap, for update
}

// CalculatePriority calculates the priority based on remaining TTL and hit count
func (item *PrefetchItem) CalculatePriority() int64 {
	remaining := time.Until(item.ExpireTime).Seconds()
	// Dynamic Priority: TTL - (HitCount * 5)
	// Each hit reduces the "perceived" TTL by 5 seconds, making it more urgent
	bonus := int64(item.HitCount) * 5
	return int64(remaining) - bonus
}

// PriorityQueue implements a min-heap priority queue for PrefetchItems
type PriorityQueue struct {
	items []*PrefetchItem
	mu    sync.RWMutex
}

// NewPriorityQueue creates a new priority queue
func NewPriorityQueue(capacity int) *PriorityQueue {
	return &PriorityQueue{
		items: make([]*PrefetchItem, 0, capacity),
	}
}

// Push adds an item to the queue
func (pq *PriorityQueue) Push(item *PrefetchItem) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	item.Priority = item.CalculatePriority()
	item.index = len(pq.items)
	pq.items = append(pq.items, item)
	pq.up(len(pq.items) - 1)
}

// Pop removes and returns the highest priority item (lowest Priority value)
func (pq *PriorityQueue) Pop() *PrefetchItem {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if len(pq.items) == 0 {
		return nil
	}

	item := pq.items[0]
	n := len(pq.items) - 1
	pq.items[0] = pq.items[n]
	pq.items[0].index = 0 // Update index of moved item
	pq.items = pq.items[:n]
	item.index = -1 // Mark as removed

	if n > 0 {
		pq.down(0)
	}

	return item
}

// PopN removes and returns up to n highest priority items
func (pq *PriorityQueue) PopN(n int) []*PrefetchItem {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	count := n
	if len(pq.items) < count {
		count = len(pq.items)
	}

	if count == 0 {
		return nil
	}

	result := make([]*PrefetchItem, 0, count)

	for i := 0; i < count; i++ {
		if len(pq.items) == 0 {
			break
		}

		item := pq.items[0]
		n := len(pq.items) - 1
		pq.items[0] = pq.items[n]
		pq.items[0].index = 0
		pq.items = pq.items[:n]
		item.index = -1

		if n > 0 {
			pq.down(0)
		}

		result = append(result, item)
	}

	return result
}

// Peek returns the item with the lowest priority (earliest expiry) without removing it
func (pq *PriorityQueue) Peek() *PrefetchItem {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if len(pq.items) == 0 {
		return nil
	}

	return pq.items[0]
}

// Update modifies the priority of an item in the queue
func (pq *PriorityQueue) Update(item *PrefetchItem) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if item.index < 0 || item.index >= len(pq.items) {
		// Item not in queue or index invalid
		return
	}

	// Recalculate priority
	// Note: Priority is usually updated by caller before calling Update,
	// but we can ensure it here too if needed.
	// item.Priority = item.CalculatePriority()

	// Fix heap property
	// We try moving it up or down
	pq.up(item.index)
	pq.down(item.index)
}

// Len returns the current number of items in the queue
func (pq *PriorityQueue) Len() int {
	pq.mu.RLock()
	defer pq.mu.RUnlock()
	return len(pq.items)
}

func (pq *PriorityQueue) up(i int) {
	for {
		parent := (i - 1) / 2
		if parent == i || pq.items[parent].Priority <= pq.items[i].Priority {
			break
		}
		pq.swap(parent, i)
		i = parent
	}
}

func (pq *PriorityQueue) down(i int) {
	for {
		left := 2*i + 1
		if left >= len(pq.items) {
			break
		}

		smallest := left
		if right := left + 1; right < len(pq.items) && pq.items[right].Priority < pq.items[left].Priority {
			smallest = right
		}

		if pq.items[i].Priority <= pq.items[smallest].Priority {
			break
		}

		pq.swap(i, smallest)
		i = smallest
	}
}

func (pq *PriorityQueue) swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
	pq.items[i].index = i
	pq.items[j].index = j
}
