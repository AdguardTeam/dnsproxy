# DNSProxy 预取功能 - 循环防止方案

## 问题分析：潜在的循环风险

### 风险场景 1：预取刷新触发新的缓存，新缓存又加入队列
```
预取刷新 → 查询上游 → 得到响应 → cache.set() → 加入预取队列 → 预取刷新 → ...
```

### 风险场景 2：同一域名被重复加入队列
```
用户查询 → cache.set() → 加入队列
预取刷新 → cache.set() → 再次加入队列
用户再次查询 → cache.set() → 又加入队列
```

### 风险场景 3：刷新失败后重试导致循环
```
预取刷新失败 → 重新加入队列 → 再次刷新失败 → 重新加入队列 → ...
```

## 当前代码的防护措施

### ✅ 已有的防护（在现有代码中）

1. **refreshing 映射表**（在 prefetch_manager.go 中）
```go
// 防止同一域名同时被多次刷新
pm.refreshingMu.Lock()
if pm.refreshing[key] {
    pm.refreshingMu.Unlock()
    return
}
pm.refreshing[key] = true
pm.refreshingMu.Unlock()
```

2. **队列去重**（在 prefetch_queue.go 中）
```go
// Push 方法中检查是否已存在
if existing, ok := pq.items[key]; ok {
    // 只更新过期时间，不重复添加
    if expireTime.After(existing.ExpireTime) {
        existing.ExpireTime = expireTime
        existing.Priority = existing.CalculatePriority()
        heap.Fix(&pq.heap, existing.index)
    }
    return
}
```

3. **过期项丢弃**（在 prefetch_manager.go 中）
```go
if timeUntilExpiry < -time.Minute {
    // 已经过期太久，丢弃
    pm.logger.Debug("dropping expired item", ...)
    continue
}
```

## ⚠️ 发现的问题

### 问题 1：预取刷新会触发 cache.set()，导致重新加入队列

**当前流程：**
```
预取刷新 → proxy.Resolve() → 查询上游 → 得到响应 → cache.set() → 加入预取队列 ❌
```

**问题：** 预取刷新的结果会再次触发 `cache.set()`，导致域名被重新加入队列。

### 问题 2：没有标记预取请求

当前代码中，预取请求使用：
```go
Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)
```

但 `cache.set()` 方法无法区分这是预取请求还是正常请求。

## 解决方案

### 方案 A：在 DNSContext 中添加标记（推荐）

#### 步骤 1：修改 DNSContext 结构
```go
// 在 proxy/dnscontext.go 中
type DNSContext struct {
    // ... 现有字段
    
    // IsPrefetchRefresh 标记这是预取刷新请求
    // 预取刷新的响应不应该再次加入预取队列
    IsPrefetchRefresh bool
}
```

#### 步骤 2：修改 cache.set() 方法
```go
// 在 proxy/cache.go 中
func (c *cache) set(m *dns.Msg, u upstream.Upstream, l *slog.Logger) {
    item := c.respToItem(m, u, l)
    if item == nil {
        return
    }

    key := msgToKey(m)
    packed := item.pack()

    c.itemsLock.Lock()
    defer c.itemsLock.Unlock()

    c.items.Set(key, packed)

    // ⚠️ 关键修改：只有非预取请求才加入队列
    // 需要从调用链传递 IsPrefetchRefresh 标记
    // 但这需要修改 set() 的签名...
}
```

**问题：** `cache.set()` 方法无法直接访问 `DNSContext`。

#### 步骤 3：修改调用链传递标记

**选项 3.1：修改 cache.set() 签名**
```go
func (c *cache) set(m *dns.Msg, u upstream.Upstream, l *slog.Logger, isPrefetch bool) {
    // ...
    
    // 只有非预取请求才加入队列
    if c.prefetchEnabled && c.prefetchManager != nil && !isPrefetch && m != nil && len(m.Question) > 0 {
        // 加入预取队列
    }
}
```

**选项 3.2：在 Proxy 中添加标记字段**
```go
type Proxy struct {
    // ...
    
    // 使用 context.Context 或 thread-local 存储
    // 但 Go 没有 thread-local，需要其他方案
}
```

### 方案 B：在预取管理器中跳过缓存钩子（推荐）✅

#### 实现方式：直接调用上游，手动更新缓存

```go
// 在 prefetch_manager.go 的 refreshItem 方法中
func (pm *PrefetchManager) refreshItem(item *PrefetchItem) {
    // ... 前面的代码
    
    // ❌ 不要使用 proxy.Resolve()，因为它会触发 cache.set()
    // err := pm.proxy.Resolve(dctx)
    
    // ✅ 直接查询上游，然后手动更新缓存
    upstreams := pm.proxy.UpstreamConfig.getUpstreamsForDomain(item.Domain)
    if len(upstreams) == 0 {
        pm.metrics.TotalFailed.Add(1)
        return
    }
    
    // 创建 DNS 请求
    req := &dns.Msg{}
    req.SetQuestion(dns.Fqdn(item.Domain), item.QType)
    req.RecursionDesired = true
    
    // 直接查询上游
    resp, u, err := pm.proxy.exchangeUpstreams(req, upstreams)
    if err != nil {
        pm.metrics.TotalFailed.Add(1)
        pm.logger.Debug("prefetch refresh failed", ...)
        return
    }
    
    // ✅ 手动更新缓存，不触发预取队列钩子
    if pm.proxy.cache != nil && resp != nil {
        // 临时禁用预取钩子
        pm.proxy.cache.prefetchEnabled = false
        pm.proxy.cache.set(resp, u, pm.logger)
        pm.proxy.cache.prefetchEnabled = true
    }
    
    pm.metrics.TotalRefreshed.Add(1)
}
```

**优点：**
- ✅ 简单直接，不需要修改 DNSContext
- ✅ 不需要修改 cache.set() 签名
- ✅ 明确控制预取流程

**缺点：**
- ⚠️ 需要访问 proxy 的内部方法（exchangeUpstreams）
- ⚠️ 临时修改 prefetchEnabled 可能有并发问题

### 方案 C：添加专用的缓存更新方法（最佳）✅✅

#### 步骤 1：在 cache 中添加新方法

```go
// 在 proxy/cache.go 中添加
// setWithoutPrefetch 更新缓存但不触发预取队列
func (c *cache) setWithoutPrefetch(m *dns.Msg, u upstream.Upstream, l *slog.Logger) {
    item := c.respToItem(m, u, l)
    if item == nil {
        return
    }

    key := msgToKey(m)
    packed := item.pack()

    c.itemsLock.Lock()
    defer c.itemsLock.Unlock()

    c.items.Set(key, packed)
    
    // 不触发预取队列钩子
}
```

#### 步骤 2：在预取管理器中使用新方法

```go
// 在 prefetch_manager.go 中
func (pm *PrefetchManager) refreshItem(item *PrefetchItem) {
    // ... 查询上游
    
    // 使用专用方法更新缓存，不触发预取
    if pm.proxy.cache != nil && resp != nil {
        pm.proxy.cache.setWithoutPrefetch(resp, u, pm.logger)
    }
}
```

**优点：**
- ✅ 清晰明确，职责分离
- ✅ 没有并发问题
- ✅ 易于理解和维护

**缺点：**
- ⚠️ 需要添加新方法（但这是好的设计）

## 推荐方案：方案 C

### 实施步骤

1. **在 cache.go 中添加 setWithoutPrefetch 方法**
2. **修改 prefetch_manager.go 使用新方法**
3. **添加测试验证不会循环**

### 需要修改的文件

1. `proxy/cache.go` - 添加 `setWithoutPrefetch()` 方法
2. `proxy/prefetch_manager.go` - 修改 `refreshItem()` 使用新方法

## 其他防护措施

### 1. 添加队列大小限制（已有）
```go
if pm.queue.Len() >= pm.config.MaxQueueSize {
    pm.metrics.TasksDropped.Add(1)
    return
}
```

### 2. 添加刷新频率限制
```go
// 在 PrefetchManager 中添加
type PrefetchManager struct {
    // ...
    lastRefresh map[string]time.Time
    minRefreshInterval time.Duration // 例如 30 秒
}

func (pm *PrefetchManager) refreshItem(item *PrefetchItem) {
    key := makeKey(item.Domain, item.QType)
    
    // 检查是否刚刚刷新过
    if lastTime, ok := pm.lastRefresh[key]; ok {
        if time.Since(lastTime) < pm.minRefreshInterval {
            pm.logger.Debug("skipping refresh, too soon", ...)
            return
        }
    }
    
    // ... 执行刷新
    
    pm.lastRefresh[key] = time.Now()
}
```

### 3. 添加监控和告警
```go
// 定期检查队列大小
func (pm *PrefetchManager) monitorLoop() {
    ticker := time.NewTicker(time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            queueSize := pm.queue.Len()
            if queueSize > pm.config.MaxQueueSize * 0.8 {
                pm.logger.Warn("prefetch queue nearly full",
                    "size", queueSize,
                    "max", pm.config.MaxQueueSize)
            }
        case <-pm.stopCh:
            return
        }
    }
}
```

## 测试计划

### 测试 1：验证预取刷新不会重新加入队列
```go
func TestPrefetchNoLoop(t *testing.T) {
    // 1. 创建 proxy 和预取管理器
    // 2. 添加一个域名到队列
    // 3. 等待预取刷新
    // 4. 验证队列中没有重复的域名
    // 5. 验证队列大小没有增长
}
```

### 测试 2：验证正常查询会加入队列
```go
func TestNormalQueryAddToQueue(t *testing.T) {
    // 1. 创建 proxy 和预取管理器
    // 2. 发送正常 DNS 查询
    // 3. 验证域名被加入预取队列
}
```

### 测试 3：压力测试
```go
func TestPrefetchUnderLoad(t *testing.T) {
    // 1. 创建 proxy 和预取管理器
    // 2. 并发发送大量查询
    // 3. 运行一段时间
    // 4. 验证队列大小稳定
    // 5. 验证没有内存泄漏
}
```

## 总结

**推荐实施方案 C：**

1. ✅ 在 `cache.go` 中添加 `setWithoutPrefetch()` 方法
2. ✅ 修改 `prefetch_manager.go` 使用新方法更新缓存
3. ✅ 添加测试验证不会循环
4. ✅ 添加队列大小监控和告警

**这个方案：**
- 清晰明确，易于理解
- 没有并发问题
- 易于测试和维护
- 完全防止循环

**请确认是否采用方案 C？我将立即实施。**
