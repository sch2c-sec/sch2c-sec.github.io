+++
date = '2026-10-18T00:00:00+08:00'
draft = false
title = 'DNS Message Format and Parsing'
tags = ['Protocol Analysis', 'DNS', 'Networking']
description = 'A binary-level look at DNS query and response messages, covering compression pointers, the EDNS0 extension and common record types.'
+++

DNS is one of the most fundamental protocols on the Internet, running on UDP/TCP port 53. Understanding its message structure is the foundation of protocol analysis and security research.

## Message Structure Overview

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

## Packet Capture Example

Querying the A record of `example.com`:

```
# Request message (hex)
12 34        # ID: 0x1234
01 00        # Flags: QR=0 (query), RD=1 (recursion desired)
00 01        # QDCOUNT: 1 question
00 00        # ANCOUNT: 0
00 00        # NSCOUNT: 0
00 00        # ARCOUNT: 0

# Question Section
07 65 78 61 6d 70 6c 65  # \x07example
03 63 6f 6d              # \x03com
00                       # End of root label
00 01                    # QTYPE: A
00 01                    # QCLASS: IN
```

## Name Compression Pointers

DNS uses compression pointers to avoid storing repeated domain names. When the top two bits are `11`, the field is a pointer:

```python
def parse_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Compression pointer: 0xC0 = 1100 0000
        if (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            labels.append(parse_name(data, ptr)[0])
            offset += 2
            break
        labels.append(data[offset+1:offset+1+length].decode())
        offset += 1 + length
    return ".".join(labels), offset
```

## Common Record Types

| Type | Value | Purpose |
|------|-----|------|
| A | 1 | IPv4 address |
| AAAA | 28 | IPv6 address |
| CNAME | 5 | Alias |
| MX | 15 | Mail server |
| TXT | 16 | Arbitrary text (SPF, DKIM, etc.) |
| NS | 2 | Authoritative name server |
| SOA | 6 | Start of authority |

## Building a Query with scapy

```python
from scapy.all import *

pkt = IP(dst="8.8.8.8") / UDP(dport=53) / \
      DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))

resp = sr1(pkt, timeout=2, verbose=0)
print(resp[DNS].summary())
```

## References

- [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 6891 — EDNS(0)](https://www.rfc-editor.org/rfc/rfc6891)
