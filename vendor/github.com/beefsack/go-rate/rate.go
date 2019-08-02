package rate

import (
	"container/list"
	"sync"
	"time"
)

// A RateLimiter limits the rate at which an action can be performed.  It
// applies neither smoothing (like one could achieve in a token bucket system)
// nor does it offer any conception of warmup, wherein the rate of actions
// granted are steadily increased until a steady throughput equilibrium is
// reached.
type RateLimiter struct {
	limit    int
	interval time.Duration
	mtx      sync.Mutex
	times    list.List
}

// New creates a new rate limiter for the limit and interval.
func New(limit int, interval time.Duration) *RateLimiter {
	lim := &RateLimiter{
		limit:    limit,
		interval: interval,
	}
	lim.times.Init()
	return lim
}

// Wait blocks if the rate limit has been reached.  Wait offers no guarantees
// of fairness for multiple actors if the allowed rate has been temporarily
// exhausted.
func (r *RateLimiter) Wait() {
	for {
		ok, remaining := r.Try()
		if ok {
			break
		}
		time.Sleep(remaining)
	}
}

// Try returns true if under the rate limit, or false if over and the
// remaining time before the rate limit expires.
func (r *RateLimiter) Try() (ok bool, remaining time.Duration) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	now := time.Now()
	if l := r.times.Len(); l < r.limit {
		r.times.PushBack(now)
		return true, 0
	}
	frnt := r.times.Front()
	if diff := now.Sub(frnt.Value.(time.Time)); diff < r.interval {
		return false, r.interval - diff
	}
	frnt.Value = now
	r.times.MoveToBack(frnt)
	return true, 0
}
