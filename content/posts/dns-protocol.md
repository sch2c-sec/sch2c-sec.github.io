+++
date = '2026-10-18T00:00:00+08:00'
draft = false
title = 'DNS 协议报文结构与解析'
tags = ['协议分析', 'DNS', '网络']
description = '从二进制层面解析 DNS 查询与响应报文，涵盖压缩指针、EDNS0 扩展与常见记录类型。'
+++

DNS 是互联网最基础的协议之一，运行在 UDP/TCP 53 端口。理解其报文结构是协议分析和安全研究的基础。

## 报文结构总览

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|  Opcode |AA|TC|RD|RA| Z|AD|CD|   RCODE    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

## 实际抓包示例

查询 `example.com` 的 A 记录：

```
# 请求报文（hex）
12 34        # ID: 0x1234
01 00        # Flags: QR=0(query), RD=1(递归)
00 01        # QDCOUNT: 1 个问题
00 00        # ANCOUNT: 0
00 00        # NSCOUNT: 0
00 00        # ARCOUNT: 0

# Question Section
07 65 78 61 6d 70 6c 65  # \x07example
03 63 6f 6d              # \x03com
00                       # 根标签结束
00 01                    # QTYPE: A
00 01                    # QCLASS: IN
```

## 名称压缩指针

DNS 用压缩指针避免重复存储域名，前两位为 `11` 表示是指针：

```python
def parse_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # 压缩指针：0xC0 = 1100 0000
        if (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            labels.append(parse_name(data, ptr)[0])
            offset += 2
            break
        labels.append(data[offset+1:offset+1+length].decode())
        offset += 1 + length
    return ".".join(labels), offset
```

## 常见记录类型

| 类型 | 值 | 用途 |
|------|-----|------|
| A | 1 | IPv4 地址 |
| AAAA | 28 | IPv6 地址 |
| CNAME | 5 | 别名 |
| MX | 15 | 邮件服务器 |
| TXT | 16 | 任意文本（SPF/DKIM 等） |
| NS | 2 | 权威域名服务器 |
| SOA | 6 | 区域起始授权 |

## 用 scapy 构造查询

```python
from scapy.all import *

pkt = IP(dst="8.8.8.8") / UDP(dport=53) / \
      DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))

resp = sr1(pkt, timeout=2, verbose=0)
print(resp[DNS].summary())
```

## 参考

- [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 6891 — EDNS(0)](https://www.rfc-editor.org/rfc/rfc6891)
