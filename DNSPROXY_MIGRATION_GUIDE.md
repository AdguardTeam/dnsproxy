# DNSProxy Active Prefetch Migration Guide

## 概述

本指南说明如何将 AdGuardHome 的 Active Cache Refresh 功能迁移到 dnsproxy 内部实现。

## 架构变更

### 之前（AdGuardHome 层面）
```
AdGuardHome (active_refresh.go)
    ↓
调用 dnsProxy.Resolve()
    ↓
触发 handleDNSRequest 回调
    ↓
需要端口 0 标记跳过统计
```

### 之后（dnsproxy 内部）
```
dnsproxy (prefetch_manager.go)
    ↓
直接查询上游
    ↓
直接更新缓存
    ↓
不经过回调
    ↓
自动不计入统计 ✅
```

## 需要在 dnsproxy 中添加的文件

### 1. `proxy/prefetch_queue.go`
优先级队列实现，管理需要刷新的缓存条目。

### 2. `proxy/prefetch_manager.go`
预取管理器，负责：
- 管理预取队列
- 调度刷新任务
- 批量处理
- 统计收集

### 3. 修改 `proxy/cache.go`
在 `Set()` 方法中添加钩子，将新缓存的域名加入预取队列。

### 4. 修改 `proxy/config.go`
添加预取配置选项。

### 5. 修改 `proxy/proxy.go`
初始化和启动预取管理器。

## 在 AdGuardHome 中的变更

### 删除文件
- `internal/dnsforward/active_refresh.go`

### 修改文件
- `internal/dnsforward/config.go` - 删除 Active Refresh 配置
- `internal/dnsforward/dnsforward.go` - 删除 Active Refresh 初始化
- `internal/dnsforward/process.go` - 删除缓存记录钩子
- `internal/dnsforward/stats.go` - 删除端口 0 检查（不再需要）
- `internal/dnsforward/http.go` - 删除 Active Refresh API
- `go.mod` - 更新 dnsproxy 依赖

## 实施步骤

### 阶段 1：在 dnsproxy fork 中实现功能

1. 创建分支
```bash
cd /path/to/your/dnsproxy-fork
git checkout -b feature/active-prefetch
```

2. 添加新文件（见下面的代码）

3. 修改现有文件（见下面的 diff）

4. 编译测试
```bash
go build ./...
go test ./...
```

5. 提交并推送
```bash
git add .
git commit -m "feat: add active prefetch functionality"
git push origin feature/active-prefetch
```

### 阶段 2：更新 AdGuardHome

1. 更新 go.mod
```go
replace github.com/AdguardTeam/dnsproxy => github.com/YOUR_USERNAME/dnsproxy v0.77.1-prefetch
```

2. 删除 active_refresh.go

3. 清理相关代码

4. 测试编译
```bash
go mod tidy
go build
```

## 配置迁移

### 旧配置（AdGuardHome）
```yaml
dns:
  active_refresh_enabled: true
  active_refresh_max_concurrent: 50
  active_refresh_threshold: 0.9
```

### 新配置（通过 dnsproxy）
```yaml
dns:
  cache_enabled: true
  cache_prefetch_enabled: true
  cache_prefetch_batch_size: 10
  cache_prefetch_check_interval: 10
  cache_prefetch_refresh_before: 5
```

## 优势

1. ✅ **统一管理**：缓存和预取在同一层
2. ✅ **自动统计分离**：不需要端口 0 标记
3. ✅ **更好的性能**：减少回调开销
4. ✅ **代码更清晰**：职责分离明确

## 注意事项

1. **版本管理**：需要维护 dnsproxy fork
2. **升级策略**：定期合并上游更新
3. **兼容性**：确保与 AdGuardHome 其他功能兼容

## 测试清单

- [ ] 缓存正常工作
- [ ] 预取功能启用
- [ ] 域名自动刷新
- [ ] 统计不包含预取请求
- [ ] 性能测试通过
- [ ] 内存使用正常
- [ ] 并发安全

## 回滚计划

如果遇到问题，可以快速回滚：

1. 恢复 go.mod 中的 dnsproxy 版本
2. 恢复 active_refresh.go
3. 恢复相关配置

```bash
git revert <commit-hash>
go mod tidy
go build
```

## 下一步

请按照以下顺序查看文件：

1. `DNSPROXY_CODE_prefetch_queue.go` - 优先级队列实现
2. `DNSPROXY_CODE_prefetch_manager.go` - 预取管理器
3. `DNSPROXY_PATCH_cache.go.diff` - cache.go 修改
4. `DNSPROXY_PATCH_config.go.diff` - config.go 修改
5. `DNSPROXY_PATCH_proxy.go.diff` - proxy.go 修改
6. `ADGUARDHOME_CLEANUP_GUIDE.md` - AdGuardHome 清理指南
