package proxy

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// PrefetchQueueManager manages the prefetch queue and background refresh process
type PrefetchQueueManager struct {
	queue        *PriorityQueue
	refreshing   map[string]bool
	scheduled    map[string]*PrefetchItem // Tracks items currently in the queue, mapping key to item pointer
	refreshingMu sync.RWMutex

	tracker *hitTracker

	batchSize       int
	checkInterval   time.Duration
	refreshBefore   time.Duration
	threshold       int
	thresholdWindow time.Duration
	semaphore       chan struct{}
	wakeCh          chan struct{}

	totalRefreshed  atomic.Int64
	totalFailed     atomic.Int64
	totalProcessed  atomic.Int64
	lastRefreshTime atomic.Int64 // Unix timestamp

	proxy  *Proxy
	logger *slog.Logger

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewPrefetchQueueManager creates a new prefetch manager
func NewPrefetchQueueManager(proxy *Proxy, config *PrefetchConfig) *PrefetchQueueManager {
	checkInterval := 10 * time.Second
	if config.CheckInterval > 0 {
		checkInterval = config.CheckInterval
	}

	refreshBefore := 5 * time.Second
	if config.RefreshBefore > 0 {
		refreshBefore = config.RefreshBefore
	}

	maxConcurrent := 10
	if config.MaxConcurrentRequests > 0 {
		maxConcurrent = config.MaxConcurrentRequests
	}

	// Auto-Configuration for Batch Size:
	// If BatchSize is 0 (default/auto), we set it to MaxConcurrentRequests.
	batchSize := config.BatchSize
	if batchSize == 0 {
		batchSize = maxConcurrent
	}

	threshold := 1
	if config.Threshold > 0 {
		threshold = config.Threshold
	}

	var thresholdWindow time.Duration
	if config.ThresholdWindow > 0 {
		thresholdWindow = config.ThresholdWindow
	}

	pm := &PrefetchQueueManager{
		queue:           NewPriorityQueue(10000),
		refreshing:      make(map[string]bool),
		scheduled:       make(map[string]*PrefetchItem),
		tracker:         newHitTracker(),
		batchSize:       batchSize,
		checkInterval:   checkInterval,
		refreshBefore:   refreshBefore,
		threshold:       threshold,
		thresholdWindow: thresholdWindow,
		semaphore:       make(chan struct{}, maxConcurrent),
		wakeCh:          make(chan struct{}, 1),
		proxy:           proxy,
		logger:          proxy.logger.With("component", "prefetch"),
		stopCh:          make(chan struct{}),
	}

	return pm
}

// Start starts the background refresh loop
func (pm *PrefetchQueueManager) Start() {
	pm.wg.Add(1)
	go pm.run()
}

// Stop stops the background refresh loop
func (pm *PrefetchQueueManager) Stop() {
	close(pm.stopCh)
	pm.wg.Wait()
}

func (pm *PrefetchQueueManager) run() {
	defer pm.wg.Done()

	timer := time.NewTimer(pm.checkInterval)
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}

	for {
		var nextRun time.Duration
		item := pm.queue.Peek()
		if item == nil {
			nextRun = 1 * time.Hour
		} else {
			targetTime := item.ExpireTime.Add(-pm.refreshBefore)
			nextRun = time.Until(targetTime)
			if nextRun < 0 {
				nextRun = 0
			}
		}

		timer.Reset(nextRun)

		select {
		case <-timer.C:
			pm.processQueue()
			pm.tracker.cleanup(pm.thresholdWindow)
		case <-pm.wakeCh:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-pm.stopCh:
			timer.Stop()
			return
		}
	}
}

// Add adds a domain to the prefetch queue
func (pm *PrefetchQueueManager) Add(domain string, qtype uint16, subnet *net.IPNet, expireTime time.Time) {
	if pm.queue.Len() >= 10000 {
		return
	}

	key := pm.makeKey(domain, qtype, subnet)

	pm.refreshingMu.Lock()
	if pm.refreshing[key] {
		pm.refreshingMu.Unlock()
		return
	}

	if item, ok := pm.scheduled[key]; ok {
		item.HitCount++
		oldPriority := item.Priority
		item.Priority = item.CalculatePriority()
		pm.queue.Update(item)

		head := pm.queue.Peek()
		if head == item && item.Priority < oldPriority {
			select {
			case pm.wakeCh <- struct{}{}:
			default:
			}
		}

		pm.refreshingMu.Unlock()
		return
	}

	item := AcquirePrefetchItem(domain, qtype, subnet, expireTime)
	item.HitCount = 1
	item.Priority = item.CalculatePriority()

	pm.scheduled[key] = item
	pm.refreshingMu.Unlock()

	pm.queue.Push(item)

	head := pm.queue.Peek()
	if head == item {
		select {
		case pm.wakeCh <- struct{}{}:
		default:
		}
	}
}

func (pm *PrefetchQueueManager) processQueue() {
	head := pm.queue.Peek()
	if head == nil {
		return
	}

	now := time.Now()
	if head.ExpireTime.Sub(now) > pm.refreshBefore {
		return
	}

	queueLen := pm.queue.Len()
	popCount := pm.batchSize

	maxBatch := cap(pm.semaphore) * 10
	if maxBatch < 10 {
		maxBatch = 10
	}

	if popCount > maxBatch {
		popCount = maxBatch
	}

	pm.logger.Debug("processing queue",
		"queue_len", queueLen,
		"batch_size", popCount)

	items := pm.queue.PopN(popCount)
	if len(items) == 0 {
		return
	}

	pm.logger.Info("batch flush triggered",
		"trigger_domain", head.Domain,
		"count", len(items))

	needRefresh := make([]*PrefetchItem, 0, len(items))

	for _, item := range items {
		timeUntilExpiry := item.ExpireTime.Sub(now)

		if timeUntilExpiry < -time.Minute {
			pm.logger.Debug("dropping expired item",
				"domain", item.Domain,
				"expired_ago", -timeUntilExpiry)

			pm.refreshingMu.Lock()
			delete(pm.scheduled, pm.makeKey(item.Domain, item.QType, item.Subnet))
			pm.refreshingMu.Unlock()

			ReleasePrefetchItem(item)
			continue
		}

		needRefresh = append(needRefresh, item)
	}

	if len(needRefresh) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, item := range needRefresh {
		wg.Add(1)
		go func(item *PrefetchItem) {
			defer wg.Done()

			pm.semaphore <- struct{}{}
			defer func() { <-pm.semaphore }()

			pm.refreshItem(item)
			ReleasePrefetchItem(item)
		}(item)
	}

	wg.Wait()
}

func (pm *PrefetchQueueManager) refreshItem(item *PrefetchItem) {
	key := pm.makeKey(item.Domain, item.QType, item.Subnet)

	pm.refreshingMu.Lock()
	if pm.refreshing[key] {
		pm.refreshingMu.Unlock()
		return
	}
	pm.refreshing[key] = true
	delete(pm.scheduled, key)
	pm.refreshingMu.Unlock()

	defer func() {
		pm.refreshingMu.Lock()
		delete(pm.refreshing, key)
		pm.refreshingMu.Unlock()
	}()

	req := &dns.Msg{}
	req.SetQuestion(item.Domain, item.QType)
	req.RecursionDesired = true

	if item.Subnet != nil {
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		e := new(dns.EDNS0_SUBNET)
		e.Code = dns.EDNS0SUBNET
		e.Family = 1
		if item.Subnet.IP.To4() == nil {
			e.Family = 2
		}
		ones, _ := item.Subnet.Mask.Size()
		e.SourceNetmask = uint8(ones)
		e.SourceScope = 0
		e.Address = item.Subnet.IP
		o.Option = append(o.Option, e)
		req.Extra = append(req.Extra, o)
	}

	dctx := pm.proxy.newDNSContext(ProtoUDP, req, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))

	err := pm.proxy.Resolve(dctx)
	if err != nil {
		pm.logger.Debug("prefetch failed",
			"domain", item.Domain,
			"qtype", item.QType,
			"err", err)
		pm.totalFailed.Add(1)
	} else {
		pm.logger.Debug("prefetch succeeded",
			"domain", item.Domain,
			"qtype", item.QType)
		pm.totalRefreshed.Add(1)
	}

	pm.totalProcessed.Add(1)
	pm.lastRefreshTime.Store(time.Now().Unix())
}

// GetStats returns the current statistics (legacy method for tests)
func (pm *PrefetchQueueManager) GetStats() (refreshed, failed int64, queueSize int) {
	return pm.totalRefreshed.Load(), pm.totalFailed.Load(), pm.queue.Len()
}

func (pm *PrefetchQueueManager) makeKey(domain string, qtype uint16, subnet *net.IPNet) string {
	k := domain + ":" + dns.TypeToString[qtype]
	if subnet != nil {
		k += ":" + subnet.String()
	}
	return k
}

// CheckThreshold checks if the domain has reached the access threshold
func (pm *PrefetchQueueManager) CheckThreshold(domain string, qtype uint16, subnet *net.IPNet) bool {
	key := pm.makeKey(domain, qtype, subnet)
	return pm.tracker.record(key, pm.threshold, pm.thresholdWindow)
}

type hitTracker struct {
	hits       map[string]int
	lastAccess map[string]time.Time
	mu         sync.Mutex
}

func newHitTracker() *hitTracker {
	return &hitTracker{
		hits:       make(map[string]int),
		lastAccess: make(map[string]time.Time),
	}
}

func (ht *hitTracker) record(key string, threshold int, window time.Duration) bool {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	if threshold <= 1 {
		return true
	}

	now := time.Now()
	if window > 0 {
		if last, ok := ht.lastAccess[key]; ok {
			if now.Sub(last) > window {
				ht.hits[key] = 0
			}
		}
		ht.lastAccess[key] = now
	}

	ht.hits[key]++
	return ht.hits[key] >= threshold
}

func (ht *hitTracker) cleanup(window time.Duration) {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	now := time.Now()
	expiry := window * 2
	if expiry == 0 {
		expiry = 1 * time.Hour
	}

	for k, t := range ht.lastAccess {
		if now.Sub(t) > expiry {
			delete(ht.lastAccess, k)
			delete(ht.hits, k)
		}
	}
}

// PrefetchStats contains statistics about the prefetch manager.
type PrefetchStats struct {
	Enabled         bool   `json:"enabled"`
	QueueLen        int    `json:"queue_len"`
	ScheduledCount  int    `json:"scheduled_count"`
	UniqueDomains   int    `json:"unique_domains"`
	TotalProcessed  int64  `json:"total_processed"`
	TotalRefreshed  int64  `json:"total_refreshed"`
	TotalFailed     int64  `json:"total_failed"`
	LastRefreshTime string `json:"last_refresh_time"`
	BatchSize       int    `json:"batch_size"`
	MaxConcurrent   int    `json:"max_concurrent"`
	Threshold       int    `json:"threshold"`
}

// Stats returns the current statistics of the prefetch manager.
func (pm *PrefetchQueueManager) Stats() *PrefetchStats {
	pm.refreshingMu.Lock()
	scheduledCount := len(pm.scheduled)
	uniqueDomains := pm.countUniqueDomains()
	pm.refreshingMu.Unlock()

	lastRefresh := "never"
	if ts := pm.lastRefreshTime.Load(); ts > 0 {
		lastRefresh = time.Unix(ts, 0).Format(time.RFC3339)
	}

	return &PrefetchStats{
		Enabled:         true,
		QueueLen:        pm.queue.Len(),
		ScheduledCount:  scheduledCount,
		UniqueDomains:   uniqueDomains,
		TotalProcessed:  pm.totalProcessed.Load(),
		TotalRefreshed:  pm.totalRefreshed.Load(),
		TotalFailed:     pm.totalFailed.Load(),
		LastRefreshTime: lastRefresh,
		BatchSize:       pm.batchSize,
		MaxConcurrent:   cap(pm.semaphore),
		Threshold:       pm.threshold,
	}
}

// countUniqueDomains counts the number of unique domains in the scheduled map
// Must be called with refreshingMu held
func (pm *PrefetchQueueManager) countUniqueDomains() int {
	domains := make(map[string]struct{})
	for _, item := range pm.scheduled {
		domains[item.Domain] = struct{}{}
	}
	return len(domains)
}
