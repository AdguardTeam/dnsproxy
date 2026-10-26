package proxy

import (
	"context"
	"time"
)

const (
	// cacheStatsCheckIvl is how often the cache size is checked against the
	// last logged one.
	cacheStatsCheckIvl = time.Minute

	// cacheStatsLogIvl is the longest time between two cache stats log lines.
	cacheStatsLogIvl = time.Hour

	// cacheStatsChange is the relative change in entries or bytes since the
	// last log line that logs the cache stats before cacheStatsLogIvl.
	cacheStatsChange = 0.05
)

// cacheStats is a snapshot of the cache's size.
type cacheStats struct {
	// entries is the number of entries in the general cache.
	entries int

	// bytes is the size of the general cache's keys and values.
	bytes int

	// subnetEntries is the number of entries in the subnet cache.
	subnetEntries int

	// subnetBytes is the size of the subnet cache's keys and values.
	subnetBytes int
}

// stats returns the current size of c.
func (c *cache) stats() (s cacheStats) {
	// Exclusive locks, since get deletes entries under the read lock and the
	// count is read from the underlying map without its own lock.
	c.itemsLock.Lock()
	st := c.items.Stats()
	c.itemsLock.Unlock()

	s.entries, s.bytes = st.Count, st.Size

	if c.itemsWithSubnet != nil {
		c.itemsWithSubnetLock.Lock()
		st = c.itemsWithSubnet.Stats()
		c.itemsWithSubnetLock.Unlock()

		s.subnetEntries, s.subnetBytes = st.Count, st.Size
	}

	return s
}

// changed returns true if any count in s differs from prev by at least
// [cacheStatsChange].
func (s cacheStats) changed(prev cacheStats) (ok bool) {
	return relChanged(prev.entries, s.entries) ||
		relChanged(prev.bytes, s.bytes) ||
		relChanged(prev.subnetEntries, s.subnetEntries) ||
		relChanged(prev.subnetBytes, s.subnetBytes)
}

// relChanged returns true if cur differs from prev by at least
// [cacheStatsChange] of prev.  Any change from zero counts.
func relChanged(prev, cur int) (ok bool) {
	d := max(cur-prev, prev-cur)
	if prev == 0 {
		return d > 0
	}

	return float64(d) >= cacheStatsChange*float64(prev)
}

// logCacheStats logs the cache's size at start, every [cacheStatsLogIvl], and
// sooner when it changes by [cacheStatsChange], until stop is closed.  p.cache
// must not be nil.
func (p *Proxy) logCacheStats(ctx context.Context, stop <-chan struct{}) {
	ticker := time.NewTicker(cacheStatsCheckIvl)
	defer ticker.Stop()

	last := p.cache.stats()
	lastAt := p.time.Now()
	p.writeCacheStats(ctx, last)

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}

		s := p.cache.stats()
		if now := p.time.Now(); s.changed(last) || now.Sub(lastAt) >= cacheStatsLogIvl {
			last, lastAt = s, now
			p.writeCacheStats(ctx, s)
		}
	}
}

// writeCacheStats writes s to the log.
func (p *Proxy) writeCacheStats(ctx context.Context, s cacheStats) {
	maxBytes := p.cacheSizeBytes
	if maxBytes <= 0 {
		maxBytes = defaultCacheSize
	}

	args := []any{
		"entries", s.entries,
		"bytes", s.bytes,
		"max_bytes", maxBytes,
	}
	if p.cache.itemsWithSubnet != nil {
		args = append(args, "subnet_entries", s.subnetEntries, "subnet_bytes", s.subnetBytes)
	}

	p.logger.InfoContext(ctx, "cache stats", args...)
}
