+++
date = '2026-10-22T00:00:00+08:00'
draft = false
title = 'TCP 状态机与异常流量识别'
tags = ['协议分析', 'TCP', '流量分析']
description = '通过 TCP 状态机理解连接生命周期，识别 SYN Flood、端口扫描等异常流量特征。'
+++

TCP 的可靠性建立在状态机之上。理解每个状态的转换条件，是流量分析和异常检测的基础。

## 状态转换图

```
                              +---------+
                              |  CLOSED |
                              +---------+
           passive open            |           active open
                |                  |                |
                v                  |                v
          +---------+              |          +---------+
          |  LISTEN |              |          |SYN_SENT |
          +---------+              |          +---------+
    rcv SYN    |                   |     rcv SYN+ACK  |
    snd SYN+ACK|                   |     snd ACK      |
               v                   |                  v
         +----------+              |          +-----------+
         | SYN_RCVD |              |          | ESTABLISHED|
         +----------+              |          +-----------+
    rcv ACK of SYN  |              |     close / FIN  |
                    v              |                  v
              +-----------+        |           +---------+
              | ESTABLISHED|       |           | FIN_WAIT1|
              +-----------+        |           +---------+
```

## 三次握手抓包

```bash
# tcpdump 抓 TCP 握手
tcpdump -i eth0 -nn 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0' -w handshake.pcap

# tshark 分析
tshark -r handshake.pcap -Y "tcp.flags.syn==1" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.flags
```

典型三次握手输出：

```
Time        Src            Dst            Flags
0.000000    192.168.1.10   93.184.216.34  SYN
0.021342    93.184.216.34  192.168.1.10   SYN, ACK
0.021398    192.168.1.10   93.184.216.34  ACK
```

## 异常特征识别

### SYN Flood

```
特征：大量 SYN 包，无对应 ACK 完成握手
半连接队列耗尽 → 合法连接被拒
```

```bash
# 统计单位时间 SYN 包来源
tcpdump -nn 'tcp[tcpflags] == tcp-syn' | \
  awk '{print $3}' | \
  sort | uniq -c | sort -rn | head -20
```

### 端口扫描特征对比

| 扫描类型 | Flags | 目标响应 | 隐蔽性 |
|----------|-------|---------|-------|
| TCP Connect | SYN | SYN+ACK / RST | 低 |
| SYN Scan | SYN | SYN+ACK → RST | 中 |
| FIN Scan | FIN | 无响应(open) / RST(closed) | 高 |
| NULL Scan | 无 | 同上 | 高 |
| XMAS Scan | FIN+PSH+URG | 同上 | 高 |

## TIME_WAIT 状态堆积

高并发服务器常见问题，主动关闭方会进入 TIME_WAIT 等待 2×MSL：

```bash
# 查看当前状态分布
ss -s

# TIME_WAIT 数量
ss -tan | grep TIME-WAIT | wc -l

# 内核调优（谨慎使用）
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.ipv4.tcp_fin_timeout=30
```

## 参考

- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [TCP/IP Illustrated, Vol. 1 — Stevens](https://www.amazon.com/TCP-Illustrated-Vol-Addison-Wesley-Professional/dp/0201633469)
