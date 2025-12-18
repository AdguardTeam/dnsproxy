# DNSProxy 文件修改指南

本文档说明需要修改 dnsproxy 中的哪些现有文件。

## 1. 修改 `proxy/config.go`

在 `Config` 结构体中添加预取配置：

```go
type Config struct {
	// ... 现有字段 ...
	
	// Prefetch configuration
	// If nil, prefetch is disabled
	Prefetch *PrefetchConfig `yaml:"prefetch"`
}
```

## 2. 修改 `proxy/cache.go`

### 2.1 在 Cache 结构体中添加字段

```go
type cache struct {
	// ... 现有字段 ...
	
	// Prefetch manager
	prefetchManager *PrefetchManager
	prefetchEnabled bool
}
```

### 2.2 修改 `Set` 方法

在缓存设置方法中添加钩子，将域名加入预取队列：

```go
func (c *cache) Set(m *dns.Msg) {
	// ... 现有缓存逻辑 ...
	
	// Add to prefetch queue if enabled
	if c.prefetchEnabled && c.prefetchManager != nil && m != nil {
		// Extract minimum TTL from response
		var minTTL uint32
		for _, rr := range m.Answer {
			ttl := rr.Header().Ttl
			if minTTL == 0 || (ttl > 0 && ttl < minTTL) {
				minTTL = ttl
			}
		}
		
		// Add to prefetch queue if we have a valid TTL
		if minTTL > 0 && len(m.Question) > 0 {
			q := m.Question[0]
			expireTime := time.Now().Add(time.Duration(minTTL) * time.Second)
			c.prefetchManager.Add(q.Name, q.Qtype, expireTime)
		}
	}
}
```

### 2.3 添加 `SetPrefetchManager` 方法

```go
// SetPrefetchManager sets the prefetch manager for this cache.
func (c *cache) SetPrefetchManager(pm *PrefetchManager) {
	c.prefetchManager = pm
	c.prefetchEnabled = pm != nil
}
```

## 3. 修改 `proxy/proxy.go`

### 3.1 在 Proxy 结构体中添加字段

```go
type Proxy struct {
	// ... 现有字段 ...
	
	// Prefetch manager
	prefetchManager *PrefetchManager
}
```

### 3.2 修改 `New` 函数

在创建 Proxy 时初始化预取管理器：

```go
func New(config *Config) (*Proxy, error) {
	// ... 现有初始化代码 ...
	
	// Initialize prefetch manager if enabled
	if config.Prefetch != nil && config.Prefetch.Enabled {
		if !config.CacheEnabled {
			return nil, errors.New("prefetch requires cache to be enabled")
		}
		
		p.prefetchManager = NewPrefetchManager(p, config.Prefetch)
		
		// Set prefetch manager in cache
		if p.cache != nil {
			p.cache.SetPrefetchManager(p.prefetchManager)
		}
	}
	
	return p, nil
}
```

### 3.3 修改 `Start` 方法

启动预取管理器：

```go
func (p *Proxy) Start() error {
	// ... 现有启动代码 ...
	
	// Start prefetch manager if enabled
	if p.prefetchManager != nil {
		p.prefetchManager.Start()
		p.logger.Info("prefetch manager started")
	}
	
	return nil
}
```

### 3.4 修改 `Stop` 方法

停止预取管理器：

```go
func (p *Proxy) Stop() error {
	// ... 现有停止代码 ...
	
	// Stop prefetch manager if running
	if p.prefetchManager != nil {
		p.prefetchManager.Stop()
		p.logger.Info("prefetch manager stopped")
	}
	
	return nil
}
```

### 3.5 添加 `GetPrefetchMetrics` 方法（可选）

```go
// GetPrefetchMetrics returns prefetch metrics if prefetch is enabled.
// Returns nil if prefetch is disabled.
func (p *Proxy) GetPrefetchMetrics() map[string]int64 {
	if p.prefetchManager == nil {
		return nil
	}
	return p.prefetchManager.GetMetrics()
}
```

## 4. 更新 `go.mod`（如果需要新依赖）

确保所有依赖都是最新的：

```bash
go mod tidy
```

## 5. 添加测试文件

### `proxy/prefetch_queue_test.go`

```go
package proxy

import (
	"testing"
	"time"
	
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestPrefetchQueue(t *testing.T) {
	pq := NewPrefetchQueue()
	
	// Test Push
	now := time.Now()
	pq.Push("example.com.", dns.TypeA, now.Add(10*time.Second))
	assert.Equal(t, 1, pq.Len())
	
	// Test Pop
	item := pq.Pop()
	assert.NotNil(t, item)
	assert.Equal(t, "example.com.", item.Domain)
	assert.Equal(t, dns.TypeA, item.QType)
	assert.Equal(t, 0, pq.Len())
}

func TestPrefetchQueuePriority(t *testing.T) {
	pq := NewPrefetchQueue()
	now := time.Now()
	
	// Add items with different expiry times
	pq.Push("urgent.com.", dns.TypeA, now.Add(1*time.Second))
	pq.Push("normal.com.", dns.TypeA, now.Add(10*time.Second))
	pq.Push("later.com.", dns.TypeA, now.Add(20*time.Second))
	
	// Should pop in order of urgency
	item1 := pq.Pop()
	assert.Equal(t, "urgent.com.", item1.Domain)
	
	item2 := pq.Pop()
	assert.Equal(t, "normal.com.", item2.Domain)
	
	item3 := pq.Pop()
	assert.Equal(t, "later.com.", item3.Domain)
}
```

### `proxy/prefetch_manager_test.go`

```go
package proxy

import (
	"testing"
	"time"
	
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestPrefetchManager(t *testing.T) {
	// Create a test proxy
	config := &Config{
		CacheEnabled: true,
		Prefetch: &PrefetchConfig{
			Enabled:       true,
			BatchSize:     5,
			CheckInterval: 1 * time.Second,
			RefreshBefore: 5 * time.Second,
		},
	}
	
	proxy, err := New(config)
	assert.NoError(t, err)
	assert.NotNil(t, proxy.prefetchManager)
	
	// Test Add
	now := time.Now()
	proxy.prefetchManager.Add("test.com.", dns.TypeA, now.Add(10*time.Second))
	
	metrics := proxy.prefetchManager.GetMetrics()
	assert.Equal(t, int64(1), metrics["queue_size"])
}
```

## 6. 更新文档

### 更新 `README.md`

添加预取功能说明：

```markdown
## Cache Prefetch

DNSProxy supports automatic cache prefetching to ensure cached entries are refreshed before they expire.

### Configuration

```yaml
cache:
  enabled: true
  size: 4194304
  
prefetch:
  enabled: true
  batch_size: 10
  check_interval: 10s
  refresh_before: 5s
  max_queue_size: 10000
  max_concurrent: 50
```

### How it works

1. When a DNS response is cached, it's added to the prefetch queue
2. The prefetch manager periodically checks the queue
3. Entries that are close to expiry are refreshed in the background
4. Refreshed entries update the cache automatically
5. Prefetch operations don't count towards query statistics

### Benefits

- Zero cache misses for frequently queried domains
- Improved response times
- Automatic cache freshness
- No impact on query statistics
```

## 7. 编译和测试

```bash
# 编译
go build ./...

# 运行测试
go test ./...

# 运行特定测试
go test ./proxy -v -run TestPrefetch

# 检查代码覆盖率
go test ./proxy -cover
```

## 8. 提交变更

```bash
git add .
git commit -m "feat: add cache prefetch functionality

- Add PrefetchQueue for priority-based queue management
- Add PrefetchManager for automatic cache refresh
- Integrate prefetch into cache Set operation
- Add configuration options for prefetch
- Add tests for prefetch functionality
- Update documentation

This feature ensures cached entries are refreshed before expiry,
eliminating cache misses and improving response times."

git push origin feature/active-prefetch
```

## 注意事项

1. **向后兼容**：确保不启用预取时，行为与原来完全一致
2. **性能测试**：测试大量域名场景下的性能
3. **内存使用**：监控队列大小和内存使用
4. **并发安全**：确保所有操作都是线程安全的
5. **错误处理**：妥善处理上游查询失败的情况

## 验证清单

- [ ] 代码编译通过
- [ ] 所有测试通过
- [ ] 预取功能正常工作
- [ ] 不启用预取时行为正常
- [ ] 性能测试通过
- [ ] 内存使用合理
- [ ] 文档已更新
- [ ] 提交信息清晰
