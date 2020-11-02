package proxy

import (
	"fmt"
)

// semaphore is the semaphore interface.  acquire will block until the
// resource can be acquired.  release never blocks.
type semaphore interface {
	acquire()
	release()
}

// noopSemaphore is a semaphore that has no limit.
type noopSemaphore struct{}

// acquire implements the semaphore interface for noopSemaphore.
func (noopSemaphore) acquire() {}

// release implements the semaphore interface for noopSemaphore.
func (noopSemaphore) release() {}

// newNoopSemaphore returns a new noopSemaphore.
func newNoopSemaphore() (s semaphore) { return noopSemaphore{} }

// sig is an alias for struct{} to type less.
type sig = struct{}

// chanSemaphore is a channel-based semaphore.
type chanSemaphore struct {
	c chan sig
}

// acquire implements the semaphore interface for *chanSemaphore.
func (c *chanSemaphore) acquire() {
	c.c <- sig{}
}

// release implements the semaphore interface for *chanSemaphore.
func (c *chanSemaphore) release() {
	select {
	case <-c.c:
	default:
	}
}

// newChanSemaphore returns a new chanSemaphore with the provided
// maximum resource number.  maxRes must be greater than zero.
func newChanSemaphore(maxRes int) (s semaphore, err error) {
	if maxRes < 1 {
		return nil, fmt.Errorf("bad maxRes: %d", maxRes)
	}

	s = &chanSemaphore{
		c: make(chan sig, maxRes),
	}
	return s, nil
}
