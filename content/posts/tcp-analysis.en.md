+++
date = '2026-10-22T00:00:00+08:00'
draft = false
title = 'TCP State Machine and Anomalous Traffic Detection'
tags = ['Protocol Analysis', 'TCP', 'Traffic Analysis']
description = 'Understand the connection lifecycle through the TCP state machine, and learn to recognize the traffic signatures of SYN floods, port scans and other anomalies.'
+++

TCP's reliability is built on a state machine. Understanding the transition conditions of each state is the foundation of traffic analysis and anomaly detection.

## State Transition Diagram

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

## Capturing the Three-Way Handshake

```bash
# Capture the TCP handshake with tcpdump
tcpdump -i eth0 -nn 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0' -w handshake.pcap

# Analyze with tshark
tshark -r handshake.pcap -Y "tcp.flags.syn==1" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.flags
```

Typical three-way handshake output:

```
Time        Src            Dst            Flags
0.000000    192.168.1.10   93.184.216.34  SYN
0.021342    93.184.216.34  192.168.1.10   SYN, ACK
0.021398    192.168.1.10   93.184.216.34  ACK
```

## Identifying Anomalies

### SYN Flood

```
Signature: a flood of SYN packets with no matching ACK to complete the handshake
Half-open connection queue exhausted → legitimate connections refused
```

```bash
# Count SYN packet sources per time window
tcpdump -nn 'tcp[tcpflags] == tcp-syn' | \
  awk '{print $3}' | \
  sort | uniq -c | sort -rn | head -20
```

### Port Scan Signature Comparison

| Scan type | Flags | Target response | Stealth |
|----------|-------|---------|-------|
| TCP Connect | SYN | SYN+ACK / RST | Low |
| SYN Scan | SYN | SYN+ACK → RST | Medium |
| FIN Scan | FIN | No response (open) / RST (closed) | High |
| NULL Scan | None | Same as above | High |
| XMAS Scan | FIN+PSH+URG | Same as above | High |

## TIME_WAIT Buildup

A common problem on high-concurrency servers: the side that closes the connection first enters TIME_WAIT and waits for 2×MSL:

```bash
# Show the current state distribution
ss -s

# Number of TIME_WAIT sockets
ss -tan | grep TIME-WAIT | wc -l

# Kernel tuning (use with caution)
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.ipv4.tcp_fin_timeout=30
```

## References

- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [TCP/IP Illustrated, Vol. 1 — Stevens](https://www.amazon.com/TCP-Illustrated-Vol-Addison-Wesley-Professional/dp/0201633469)
