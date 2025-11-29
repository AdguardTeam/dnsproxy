package proxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPriorityQueue(t *testing.T) {
	pq := NewPriorityQueue(10)

	now := time.Now()
	item1 := AcquirePrefetchItem("example.com", 0, nil, now.Add(10*time.Second))
	item2 := AcquirePrefetchItem("google.com", 0, nil, now.Add(5*time.Second))
	item3 := AcquirePrefetchItem("test.com", 0, nil, now.Add(15*time.Second))

	pq.Push(item1)
	pq.Push(item2)
	pq.Push(item3)

	assert.Equal(t, 3, pq.Len())

	// Should pop item2 first (lowest TTL)
	pop1 := pq.Pop()
	assert.Equal(t, item2.Domain, pop1.Domain)

	// Should pop item1 next
	pop2 := pq.Pop()
	assert.Equal(t, item1.Domain, pop2.Domain)

	// Should pop item3 last
	pop3 := pq.Pop()
	assert.Equal(t, item3.Domain, pop3.Domain)

	// Should be empty
	assert.Nil(t, pq.Pop())
}

func TestPriorityQueue_PopN(t *testing.T) {
	pq := NewPriorityQueue(10)

	now := time.Now()
	for i := 0; i < 5; i++ {
		pq.Push(AcquirePrefetchItem(
			"domain",
			0,
			nil,
			now.Add(time.Duration(i)*time.Second),
		))
	}

	items := pq.PopN(3)
	assert.Len(t, items, 3)
	assert.Equal(t, 2, pq.Len())

	// Check order
	assert.True(t, items[0].ExpireTime.Before(items[1].ExpireTime))
	assert.True(t, items[1].ExpireTime.Before(items[2].ExpireTime))
}
