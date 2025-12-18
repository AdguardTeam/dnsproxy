# DNSProxy Prefetch Extension Design

## 概述

**重构 dnsproxy 的乐观缓存机制**，从被动刷新改为主动预取。

### 原有逻辑（被动）
```
用户查询 -> 缓存过期 -> 返回旧缓存 -> 后台刷新
```

### 新逻辑（主动）
```
用户查询 -> 域名加入缓存 ->TTL-5秒时主动刷新 -> 缓存始终新鲜 -> 后台刷新

## 设计目标

1. **主动预取**：在缓存过期前主动刷新，而不是等到过期后被动刷新
2. **优先级队列**：根据 TTL 剩余时间计算紧急程度，优先刷新即将过期的域名
3. **批量处理**：每次处理 10 个域名，提高效率，减少上游压力
4. **统计分离**：预取刷新在 dnsproxy 内部完成，自动不计入统计
5. **替代现有方案**：完全替代 AdGuardHome 层面的预取系统

## 方案对比

| 特性 | 旧方案 (AdGuardHome 预取) | 新方案 (dnsproxy 重构) |
|------|-------------------------|----------------------|
| 预取池维护 | AdGuardHome | dnsproxy |
| 热门域名识别 | 访问计数 | 所有缓存域名 |
| 刷新触发 | AdGuardHome 调用 Resolve | dnsproxy 内部 |
| 统计分离 | 需要端口 0 标记 | 自动（不经过回调） |
| 维护成本 | 低 | 高（需要 fork） |
| 性能 | 良好 | 更优 |
| 代码位置 | AdGuardHome | dnsproxy |

## 架构设计

### 1. 预取队列管理器 (PrefetchQueueManager)

```go
type PrefetchQueueManager struct {
    // 优先级队列：按 TTL 剩余时间排序
    queue *PriorityQueue
    
    // 正在刷新的域名集合（避免重复刷新）
    refreshing map[string]bool
    
    // 配置
    batchSize      int           // 每批处理数量，默认 10
    checkInterval  time.Duration // 检查间隔，默认 10 秒
    refreshBefore  time.Duration // 提前刷新时间，默认 5 秒
    
    // 统计
    totalRefreshed int64
    totalFailed    int64
}
```

### 2. 优先级队列项

```go
type PrefetchItem struct {
    Domain     string
    QType      uint16
    ExpireTime time.Time
    Priority   int64  // 紧急程度分数，越小越紧急
}

// 计算优先级：剩余 TTL 秒数
func (item *PrefetchItem) CalculatePriority() int64 {
    remaining := time.Until(item.ExpireTime).Seconds()
    return int64(remaining)
}
```

### 3. 重构 dnsproxy.Cache

**关键改动**：将乐观缓存从被动改为主动

```go
type Cache struct {
    // 现有字段...
    items          *lru.Cache
    optimistic     bool
    
    // 新增：预取队列管理器（替代原有的被动刷新）
    prefetchManager *PrefetchQueueManager
    
    // 新增：是否启用主动预取
    prefetchEnabled bool
}
```

### 4. 缓存操作钩子

**在缓存的 `Set` 方法中添加钩子**：

```go
func (c *Cache) Set(msg *dns.Msg) {
    // 现有缓存逻辑...
    key := msgToKey(msg)
    c.items.Add(key, msg)
    
    // 如果启用主动预取，将域名加入预取队列
    // 这将替代原有的被动刷新机制
    if c.prefetchEnabled && c.prefetchManager != nil {
        for _, q := range msg.Question {
            ttl := extractMinTTL(msg)
            if ttl > 0 {
                expireTime := time.Now().Add(time.Duration(ttl) * time.Second)
                c.prefetchManager.Add(q.Name, q.Qtype, expireTime)
            }
        }
    }
}
```

### 5. 移除或禁用原有的被动刷新

**原有的乐观缓存逻辑**：
```go
// 旧逻辑：在 Get 时检查是否过期，如果过期则后台刷新
func (c *Cache) Get(key string) *dns.Msg {
    item := c.items.Get(key)
    if item == nil {
        return nil
    }
    
    msg := item.(*dns.Msg)
    
    // 如果启用乐观缓存且已过期
    if c.optimistic && isExpired(msg) {
        // 返回旧缓存
        // 触发后台刷新
        go c.refresh(key)
        return msg
    }
    
    return msg
}
```

**新逻辑**：
```go
// 新逻辑：不需要在 Get 时检查，预取管理器会主动刷新
func (c *Cache) Get(key string) *dns.Msg {
    item := c.items.Get(key)
    if item == nil {
        return nil
    }
    
    msg := item.(*dns.Msg)
    
    // 如果启用主动预取，不需要检查过期
    // 预取管理器会在 TTL-5秒时主动刷新
    if c.prefetchEnabled {
        return msg
    }
    
    // 如果未启用主动预取，使用原有的乐观缓存逻辑
    if c.optimistic && isExpired(msg) {
        go c.refresh(key)
        return msg
    }
    
    return msg
}
```

## 工作流程

### 1. 域名加入队列

```
用户查询 -> 缓存未命中 -> 查询上游 -> 缓存结果 -> 加入预取队列
                                                    |
                                                    v
                                            计算过期时间和优先级
```

### 2. 预取刷新循环

```
每 10 秒检查一次:
  1. 从优先级队列取出最紧急的 10 个域名
  2. 过滤：剩余 TTL < 5 秒的域名
  3. 批量刷新这些域名
  4. 更新统计信息
```

### 3. 刷新过程

```go
func (pm *PrefetchQueueManager) RefreshBatch(proxy *Proxy) {
    items := pm.queue.PopN(pm.batchSize)
    
    for _, item := range items {
        if time.Until(item.ExpireTime) > pm.refreshBefore {
            // 还不需要刷新，放回队列
            pm.queue.Push(item)
            continue
        }
        
        // 标记为正在刷新
        pm.refreshing[item.Domain] = true
        
        // 异步刷新
        go func(item *PrefetchItem) {
            defer func() {
                delete(pm.refreshing, item.Domain)
            }()
            
            // 创建内部查询（不计入统计）
            req := &dns.Msg{}
            req.SetQuestion(item.Domain, item.QType)
            
            ctx := &DNSContext{
                Req: req,
                Addr: netip.AddrPortFrom(netip.IPv4Unspecified(), 0), // 标记为内部请求
            }
            
            // 查询并更新缓存
            err := proxy.Resolve(ctx)
            if err != nil {
                atomic.AddInt64(&pm.totalFailed, 1)
            } else {
                atomic.AddInt64(&pm.totalRefreshed, 1)
            }
        }(item)
    }
}
```

## 配置选项

在 `proxy.Config` 中添加：

```go
type Config struct {
    // 现有字段...
    
    // 预取配置
    PrefetchEnabled      bool          // 是否启用预取
    PrefetchBatchSize    int           // 每批处理数量
    PrefetchCheckInterval time.Duration // 检查间隔
    PrefetchRefreshBefore time.Duration // 提前刷新时间
}
```

## 统计分离

### 重要说明

如果在 **dnsproxy 内部实现预取**，刷新操作在缓存层面完成，**不会触发请求处理流程**，因此：

✅ **不需要修改统计逻辑**

原因：
1. 预取刷新直接调用上游查询
2. 结果直接更新缓存
3. 不经过 `handleDNSRequest` 回调
4. 自然不会被统计记录

### 对比：当前方案需要统计分离

当前方案（AdGuardHome 层面）调用 `dnsProxy.Resolve()` 会触发回调，需要：

```go
// 在 AdGuardHome 的 handleDNSRequest 中
func (s *Server) handleDNSRequest(_ *proxy.Proxy, pctx *proxy.DNSContext) error {
    // 检查是否为预取请求（端口 0）
    isPrefetchRefresh := pctx.Addr.Addr().IsLoopback() && pctx.Addr.Port() == 0
    
    dctx := &dnsContext{
        proxyCtx:          pctx,
        isPrefetchRefresh: isPrefetchRefresh, // 标记跳过统计
    }
    
    // ... 处理请求
}
```

### dnsproxy 扩展方案的优势

在 dnsproxy 内部实现预取，刷新流程：

```
预取管理器 -> 创建 DNS 请求 -> 直接查询上游 -> 更新缓存
                                    ↓
                            不经过 handleDNSRequest
                                    ↓
                            不会被统计记录 ✅
```

而不是：

```
AdGuardHome -> dnsProxy.Resolve() -> handleDNSRequest 回调 -> 需要跳过统计 ⚠️
```

## 优势

1. **统一管理**：所有缓存刷新由 dnsproxy 统一处理
2. **高效批量**：每次处理 10 个域名，减少开销
3. **智能优先级**：根据紧急程度排序，优先刷新即将过期的域名
4. **避免重复**：通过 `refreshing` 集合避免重复刷新
5. **统计准确**：预取请求不计入用户查询统计

## 实现步骤

1. ✅ 设计文档（当前文件）
2. ⬜ Fork dnsproxy 项目
3. ⬜ 实现 PrefetchQueueManager
4. ⬜ 实现优先级队列
5. ⬜ 集成到 Cache
6. ⬜ 添加配置选项
7. ⬜ 修改 AdGuardHome 的 go.mod
8. ⬜ 测试验证

## 与当前方案对比

| 特性 | 当前方案 | DNSProxy 扩展方案 |
|------|---------|------------------|
| 预取池维护 | AdGuardHome | DNSProxy |
| 缓存刷新 | 调用 dnsproxy | DNSProxy 内部 |
| 统计分离 | 端口 0 标记 | 端口 0 标记 |
| 优先级队列 | 简单时间检查 | 优先级队列 |
| 批量处理 | 逐个处理 | 批量处理 |
| 维护成本 | 低（无外部依赖修改） | 高（需要维护 fork） |
| 性能 | 良好 | 更优 |
| 灵活性 | 高 | 中 |

## 详细实现

### 1. 优先级队列实现

```go
// PriorityQueue 使用最小堆实现优先级队列
type PriorityQueue struct {
    items []*PrefetchItem
    mu    sync.RWMutex
}

func (pq *PriorityQueue) Push(item *PrefetchItem) {
    pq.mu.Lock()
    defer pq.mu.Unlock()
    
    item.Priority = item.CalculatePriority()
    pq.items = append(pq.items, item)
    pq.up(len(pq.items) - 1)
}

func (pq *PriorityQueue) Pop() *PrefetchItem {
    pq.mu.Lock()
    defer pq.mu.Unlock()
    
    if len(pq.items) == 0 {
        return nil
    }
    
    item := pq.items[0]
    n := len(pq.items) - 1
    pq.items[0] = pq.items[n]
    pq.items = pq.items[:n]
    
    if n > 0 {
        pq.down(0)
    }
    
    return item
}

func (pq *PriorityQueue) PopN(n int) []*PrefetchItem {
    pq.mu.Lock()
    defer pq.mu.Unlock()
    
    count := min(n, len(pq.items))
    result := make([]*PrefetchItem, 0, count)
    
    for i := 0; i < count; i++ {
        if len(pq.items) == 0 {
            break
        }
        
        item := pq.items[0]
        n := len(pq.items) - 1
        pq.items[0] = pq.items[n]
        pq.items = pq.items[:n]
        
        if n > 0 {
            pq.down(0)
        }
        
        result = append(result, item)
    }
    
    return result
}

func (pq *PriorityQueue) up(i int) {
    for {
        parent := (i - 1) / 2
        if parent == i || pq.items[parent].Priority <= pq.items[i].Priority {
            break
        }
        pq.items[parent], pq.items[i] = pq.items[i], pq.items[parent]
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
        
        pq.items[i], pq.items[smallest] = pq.items[smallest], pq.items[i]
        i = smallest
    }
}

func (pq *PriorityQueue) Len() int {
    pq.mu.RLock()
    defer pq.mu.RUnlock()
    return len(pq.items)
}
```

### 2. 预取队列管理器完整实现

```go
type PrefetchQueueManager struct {
    queue          *PriorityQueue
    refreshing     map[string]bool
    refreshingMu   sync.RWMutex
    
    batchSize      int
    checkInterval  time.Duration
    refreshBefore  time.Duration
    
    totalRefreshed atomic.Int64
    totalFailed    atomic.Int64
    
    proxy          *Proxy
    logger         *slog.Logger
    
    stopCh         chan struct{}
    wg             sync.WaitGroup
}

func NewPrefetchQueueManager(proxy *Proxy, config *PrefetchConfig) *PrefetchQueueManager {
    pm := &PrefetchQueueManager{
        queue:         &PriorityQueue{items: make([]*PrefetchItem, 0, 1000)},
        refreshing:    make(map[string]bool),
        batchSize:     config.BatchSize,
        checkInterval: config.CheckInterval,
        refreshBefore: config.RefreshBefore,
        proxy:         proxy,
        logger:        proxy.logger.With("component", "prefetch"),
        stopCh:        make(chan struct{}),
    }
    
    return pm
}

func (pm *PrefetchQueueManager) Start() {
    pm.wg.Add(1)
    go pm.run()
}

func (pm *PrefetchQueueManager) Stop() {
    close(pm.stopCh)
    pm.wg.Wait()
}

func (pm *PrefetchQueueManager) run() {
    defer pm.wg.Done()
    
    ticker := time.NewTicker(pm.checkInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            pm.processQueue()
        case <-pm.stopCh:
            return
        }
    }
}

func (pm *PrefetchQueueManager) Add(domain string, qtype uint16, expireTime time.Time) {
    // 检查是否已在刷新中
    pm.refreshingMu.RLock()
    if pm.refreshing[domain] {
        pm.refreshingMu.RUnlock()
        return
    }
    pm.refreshingMu.RUnlock()
    
    item := &PrefetchItem{
        Domain:     domain,
        QType:      qtype,
        ExpireTime: expireTime,
    }
    
    pm.queue.Push(item)
}

func (pm *PrefetchQueueManager) processQueue() {
    items := pm.queue.PopN(pm.batchSize)
    if len(items) == 0 {
        return
    }
    
    now := time.Now()
    needRefresh := make([]*PrefetchItem, 0, len(items))
    
    // 过滤需要刷新的域名
    for _, item := range items {
        timeUntilExpiry := item.ExpireTime.Sub(now)
        
        if timeUntilExpiry > pm.refreshBefore {
            // 还不需要刷新，放回队列
            pm.queue.Push(item)
            continue
        }
        
        if timeUntilExpiry < -time.Minute {
            // 已经过期太久，丢弃
            pm.logger.Debug("dropping expired item",
                "domain", item.Domain,
                "expired_ago", -timeUntilExpiry)
            continue
        }
        
        needRefresh = append(needRefresh, item)
    }
    
    if len(needRefresh) == 0 {
        return
    }
    
    pm.logger.Info("processing prefetch batch",
        "count", len(needRefresh),
        "queue_size", pm.queue.Len())
    
    // 并发刷新
    var wg sync.WaitGroup
    for _, item := range needRefresh {
        wg.Add(1)
        go func(item *PrefetchItem) {
            defer wg.Done()
            pm.refreshItem(item)
        }(item)
    }
    
    wg.Wait()
}

func (pm *PrefetchQueueManager) refreshItem(item *PrefetchItem) {
    // 标记为正在刷新
    pm.refreshingMu.Lock()
    if pm.refreshing[item.Domain] {
        pm.refreshingMu.Unlock()
        return
    }
    pm.refreshing[item.Domain] = true
    pm.refreshingMu.Unlock()
    
    defer func() {
        pm.refreshingMu.Lock()
        delete(pm.refreshing, item.Domain)
        pm.refreshingMu.Unlock()
    }()
    
    // 创建内部查询
    req := &dns.Msg{}
    req.SetQuestion(item.Domain, item.QType)
    req.RecursionDesired = true
    
    ctx := &DNSContext{
        Proto: ProtoUDP,
        Req:   req,
        Addr:  netip.AddrPortFrom(netip.IPv4Unspecified(), 0), // 端口 0 标记为内部请求
    }
    
    // 查询并更新缓存
    err := pm.proxy.Resolve(ctx)
    if err != nil {
        pm.totalFailed.Add(1)
        pm.logger.Debug("prefetch refresh failed",
            "domain", item.Domain,
            "qtype", dns.TypeToString[item.QType],
            "error", err)
        return
    }
    
    pm.totalRefreshed.Add(1)
    pm.logger.Debug("prefetch refresh completed",
        "domain", item.Domain,
        "qtype", dns.TypeToString[item.QType])
}

func (pm *PrefetchQueueManager) GetStats() (refreshed, failed int64, queueSize int) {
    return pm.totalRefreshed.Load(), pm.totalFailed.Load(), pm.queue.Len()
}
```

### 3. 集成到 Cache

```go
// 在 cache.go 中修改 Set 方法
func (c *Cache) Set(msg *dns.Msg) {
    // 现有缓存逻辑...
    c.items.Set(key, item)
    
    // 如果启用预取，加入预取队列
    if c.prefetchEnabled && c.prefetchManager != nil {
        for _, q := range msg.Question {
            // 提取最小 TTL
            minTTL := uint32(0)
            for _, rr := range msg.Answer {
                ttl := rr.Header().Ttl
                if minTTL == 0 || (ttl > 0 && ttl < minTTL) {
                    minTTL = ttl
                }
            }
            
            if minTTL > 0 {
                expireTime := time.Now().Add(time.Duration(minTTL) * time.Second)
                c.prefetchManager.Add(q.Name, q.Qtype, expireTime)
            }
        }
    }
}
```

### 4. 配置结构

```go
type PrefetchConfig struct {
    Enabled       bool          // 是否启用预取
    BatchSize     int           // 每批处理数量，默认 10
    CheckInterval time.Duration // 检查间隔，默认 10 秒
    RefreshBefore time.Duration // 提前刷新时间，默认 5 秒
}

// 在 proxy.Config 中添加
type Config struct {
    // ... 现有字段
    
    // Prefetch 预取配置
    Prefetch *PrefetchConfig
}
```

### 5. 初始化流程

```go
// 在 proxy.New() 中初始化
func New(config *Config) (*Proxy, error) {
    // ... 现有初始化代码
    
    // 初始化缓存
    if config.CacheEnabled {
        cache := newCache(config.CacheSize, config.CacheMinTTL, config.CacheMaxTTL)
        
        // 如果启用预取，初始化预取管理器
        if config.Prefetch != nil && config.Prefetch.Enabled {
            prefetchManager := NewPrefetchQueueManager(proxy, config.Prefetch)
            cache.prefetchManager = prefetchManager
            cache.prefetchEnabled = true
            
            // 启动预取管理器
            prefetchManager.Start()
        }
        
        proxy.cache = cache
    }
    
    return proxy, nil
}

// 在 proxy.Stop() 中停止
func (p *Proxy) Stop() error {
    // ... 现有停止代码
    
    // 停止预取管理器
    if p.cache != nil && p.cache.prefetchManager != nil {
        p.cache.prefetchManager.Stop()
    }
    
    return nil
}
```

## 性能优化

### 1. 内存优化

- 使用对象池减少 GC 压力
- 限制队列最大大小（如 10000 个域名）
- 定期清理过期项

```go
var prefetchItemPool = sync.Pool{
    New: func() interface{} {
        return &PrefetchItem{}
    },
}

func (pm *PrefetchQueueManager) Add(domain string, qtype uint16, expireTime time.Time) {
    if pm.queue.Len() >= 10000 {
        pm.logger.Warn("prefetch queue full, dropping item", "domain", domain)
        return
    }
    
    item := prefetchItemPool.Get().(*PrefetchItem)
    item.Domain = domain
    item.QType = qtype
    item.ExpireTime = expireTime
    
    pm.queue.Push(item)
}
```

### 2. 并发控制

- 使用 worker pool 限制并发刷新数量
- 避免同时刷新过多域名导致上游压力

```go
type WorkerPool struct {
    workers   int
    taskCh    chan *PrefetchItem
    wg        sync.WaitGroup
    stopCh    chan struct{}
}

func (pm *PrefetchQueueManager) processQueue() {
    items := pm.queue.PopN(pm.batchSize)
    if len(items) == 0 {
        return
    }
    
    // 使用 worker pool 处理
    for _, item := range items {
        select {
        case pm.workerPool.taskCh <- item:
        case <-time.After(time.Second):
            // 超时，放回队列
            pm.queue.Push(item)
        }
    }
}
```

## 监控和调试

### 1. 指标收集

```go
type PrefetchMetrics struct {
    TotalRefreshed int64
    TotalFailed    int64
    QueueSize      int
    RefreshingCount int
    AvgRefreshTime time.Duration
}

func (pm *PrefetchQueueManager) GetMetrics() *PrefetchMetrics {
    pm.refreshingMu.RLock()
    refreshingCount := len(pm.refreshing)
    pm.refreshingMu.RUnlock()
    
    return &PrefetchMetrics{
        TotalRefreshed:  pm.totalRefreshed.Load(),
        TotalFailed:     pm.totalFailed.Load(),
        QueueSize:       pm.queue.Len(),
        RefreshingCount: refreshingCount,
    }
}
```

### 2. 日志记录

```go
// 定期输出统计信息
func (pm *PrefetchQueueManager) logStats() {
    ticker := time.NewTicker(time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            metrics := pm.GetMetrics()
            pm.logger.Info("prefetch stats",
                "refreshed", metrics.TotalRefreshed,
                "failed", metrics.TotalFailed,
                "queue_size", metrics.QueueSize,
                "refreshing", metrics.RefreshingCount)
        case <-pm.stopCh:
            return
        }
    }
}
```

## 测试计划

### 1. 单元测试

- 优先级队列正确性
- 并发安全性
- 内存泄漏检测

### 2. 集成测试

- 与 dnsproxy 集成
- 缓存刷新验证
- 统计准确性

### 3. 性能测试

- 大量域名场景（10000+）
- 高并发刷新
- 内存使用

## 实施路线图

### 阶段 1：原型验证（1-2 天）
- [ ] 实现基础优先级队列
- [ ] 实现简单的预取管理器
- [ ] 在测试环境验证

### 阶段 2：完整实现（3-5 天）
- [ ] 完善错误处理
- [ ] 添加并发控制
- [ ] 实现监控指标
- [ ] 编写单元测试

### 阶段 3：集成和优化（2-3 天）
- [ ] 集成到 dnsproxy
- [ ] 性能优化
- [ ] 内存优化
- [ ] 压力测试

### 阶段 4：文档和发布（1-2 天）
- [ ] 编写使用文档
- [ ] 更新 API 文档
- [ ] 准备发布说明

## 建议

考虑到维护成本，建议：
1. **短期**：使用当前方案（已实现）
2. **长期**：如果性能成为瓶颈，再考虑扩展 dnsproxy

或者：
1. 先在 AdGuardHome 层面实现优先级队列和批量处理
2. 验证效果后，再考虑是否需要移到 dnsproxy

## 当前状态

✅ **已完成**：
- AdGuardHome 层面的预取系统
- 端口 0 标记跳过统计
- 基本的预取刷新功能
- 编译成功 (AdGuardHome_final_v3.exe)

⬜ **待实现**（如果选择扩展 dnsproxy）：
- Fork dnsproxy 项目
- 实现优先级队列
- 实现预取队列管理器
- 集成测试
- 性能优化


## Migration Plan - From AdGuardHome Prefetch to dnsproxy Refactor

### Phase 1: Preparation
- [ ] Fork dnsproxy project
- [ ] Create feature branch
- [ ] Setup development environment

### Phase 2: Implement dnsproxy Prefetch
- [ ] Implement priority queue
- [ ] Implement prefetch queue manager
- [ ] Modify Cache.Set to add hooks
- [ ] Modify Cache.Get logic
- [ ] Add configuration options

### Phase 3: Remove AdGuardHome Prefetch
- [ ] Remove `internal/dnsforward/prefetch.go`
- [ ] Remove prefetch related configs
- [ ] Remove prefetch API endpoints
- [ ] Update frontend UI

### Phase 4: Integration and Testing
- [ ] Update go.mod to point to fork
- [ ] Integration testing
- [ ] Performance testing
- [ ] Documentation update

## Current Status

### Completed (Old Approach)
- ✅ AdGuardHome level prefetch system
- ✅ Port 0 marking to skip statistics
- ✅ Basic prefetch refresh functionality
- ✅ Successfully compiled (AdGuardHome_final_v3.exe)

### To Implement (New Approach - dnsproxy Refactor)
- ⬜ Fork dnsproxy project
- ⬜ Implement priority queue
- ⬜ Implement prefetch queue manager
- ⬜ Refactor Cache logic
- ⬜ Remove AdGuardHome prefetch code
- ⬜ Integration testing
- ⬜ Performance optimization

## Decision Recommendation

### Option A: Keep Current Approach
**Pros:**
- ✅ Already implemented and working
- ✅ Low maintenance cost
- ✅ High flexibility

**Cons:**
- ⚠️ Requires port 0 marking
- ⚠️ Code scattered across two layers

### Option B: Implement dnsproxy Refactor
**Pros:**
- ✅ Unified cache management
- ✅ Automatic statistics separation
- ✅ Better performance

**Cons:**
- ⚠️ Need to maintain fork
- ⚠️ Long implementation cycle (7-12 days)
- ⚠️ Need to merge when upgrading dnsproxy

### Recommendation

**Short-term (1-3 months)**: Use Option A (Current Approach)
- Quick deployment
- Validate effectiveness
- Collect feedback

**Long-term (After 3 months)**: Evaluate migration to Option B
- If performance meets requirements, keep Option A
- If better performance and architecture needed, migrate to Option B
