+++
date = '2025-11-04T00:00:00+08:00'
draft = false
title = 'FortiGate查看IPS Engine工作状态'
+++

## FortiGate IPS Engine 工作状态检查

### 1. 查看IPS Engine状态

使用以下命令查看IPS Engine的基本状态：

```bash
get system status
```

### 2. 查看IPS统计信息

查看详细的IPS统计和性能信息：

```bash
diagnose ips stats
```

这个命令会显示：
- IPS引擎版本
- 检测到的攻击数量
- 阻止的会话数
- IPS引擎负载

### 3. 查看IPS会话信息

查看当前IPS会话：

```bash
diagnose ips session list
```

### 4. 查看IPS引擎详细信息

查看IPS引擎的详细工作状态：

```bash
diagnose test application ipsmonitor 99
```

这个命令显示：
- IPS引擎工作模式
- 引擎状态（running/stopped）
- 处理的数据包统计
- 内存使用情况

### 5. 查看IPS规则库版本

检查当前使用的IPS签名数据库版本：

```bash
diagnose autoupdate versions
```

或者：

```bash
get system fortiguard status
```

### 6. 查看特定IPS传感器配置

```bash
show ips sensor <sensor-name>
```

### 7. 实时监控IPS事件

启用实时调试来监控IPS事件：

```bash
diagnose debug enable
diagnose debug application ipsmonitor -1
```

停止调试：

```bash
diagnose debug disable
diagnose debug reset
```

### 8. 查看IPS日志

在Web界面查看：
- **Log & Report** > **Intrusion Prevention**

在CLI查看最近的IPS日志：

```bash
execute log filter category ips
execute log display
```

### 9. 检查IPS性能指标

查看IPS相关的性能指标：

```bash
diagnose sys top
```

关注CPU和内存使用情况。

### 10. 查看IPS引擎进程

```bash
diagnose sys process pidof ips
get system performance status | grep -i ips
```

### 常见问题排查

#### IPS引擎未运行
```bash
# 检查IPS引擎状态
diagnose test application ipsmonitor 1

# 重启IPS引擎
diagnose test application ipsmonitor 1
```

#### 更新IPS签名库
```bash
# 手动更新
execute update-now

# 检查更新状态
diagnose autoupdate status
```

#### 查看IPS引擎负载
```bash
diagnose ips stats
```

如果负载过高（>80%），考虑：
- 优化IPS策略
- 启用硬件加速（如果可用）
- 升级硬件资源

### 最佳实践

1. **定期检查IPS引擎状态**：建议每周检查一次
2. **保持签名库更新**：配置自动更新
3. **监控性能指标**：避免IPS引擎过载影响网络性能
4. **定期审查日志**：分析攻击趋势和误报
5. **测试IPS策略**：在非生产环境测试新规则

### 相关配置示例

#### 配置IPS传感器
```bash
config ips sensor
    edit "default"
        set comment "Default IPS sensor"
        config entries
            edit 1
                set severity high critical
                set action block
            next
        end
    next
end
```

#### 应用到防火墙策略
```bash
config firewall policy
    edit 1
        set name "LAN to WAN"
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set ips-sensor "default"
        set nat enable
    next
end
```

### 参考文档

- FortiGate CLI Reference Guide
- FortiGate Administration Guide
- Fortinet Technical Documentation
