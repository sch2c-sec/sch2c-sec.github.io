+++
date = '2026-10-15T00:00:00+08:00'
draft = false
title = 'TLS 1.3 握手过程详解'
tags = ['协议分析', 'TLS', '密码学']
description = 'TLS 1.3 相比 1.2 大幅削减了握手往返次数，本文逐字节分析其握手流程与密钥派生过程。'
+++

TLS 1.3 于 2018 年正式发布（[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)），相比 TLS 1.2 有两个核心改进：握手从 2-RTT 降至 1-RTT，以及强制前向保密。

## 握手流程

```
Client                                           Server

ClientHello
+ key_share
+ supported_versions        -------->
                                                ServerHello
                                                + key_share
                                                + supported_versions
                                       {EncryptedExtensions}
                                       {CertificateRequest*}
                                              {Certificate*}
                                        {CertificateVerify*}
                                                  {Finished}
                            <--------  [Application Data*]
{Certificate*}
{CertificateVerify*}
{Finished}                  -------->
[Application Data]          <------->  [Application Data]
```

> `{}` 表示使用握手密钥加密，`[]` 表示使用应用密钥加密。

## ClientHello 结构

```
16 03 01 00 f1          # TLS Record: Handshake, legacy version 1.0, length
01 00 00 ed             # Handshake Type: ClientHello (1), length
03 03                   # ClientVersion: TLS 1.2 (legacy)
[32 bytes random]       # Random
00                      # Session ID Length: 0
00 08                   # Cipher Suites Length: 8
  13 02                 #   TLS_AES_256_GCM_SHA384
  13 03                 #   TLS_CHACHA20_POLY1305_SHA256
  13 01                 #   TLS_AES_128_GCM_SHA256
  00 ff                 #   TLS_EMPTY_RENEGOTIATION_INFO_SCSV
```

## 密钥派生（HKDF）

TLS 1.3 使用 HKDF（[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)）派生所有密钥：

```
             0
             |
             v
   PSK -->  HKDF-Extract = Early Secret
             |
             v
       Derive-Secret(., "ext binder" | "res binder", "")
                         = binder_key
             |
             v
       Derive-Secret(., "c e traffic", ClientHello)
                         = client_early_traffic_secret
```

## Wireshark 过滤器

```wireshark
# 只看 TLS 1.3
tls.handshake.extensions.supported_versions == 0x0304

# 查看 ClientHello
tls.handshake.type == 1

# 查看证书
tls.handshake.type == 11
```

## 与 TLS 1.2 对比

| 特性 | TLS 1.2 | TLS 1.3 |
|------|---------|---------|
| 握手往返 | 2-RTT | 1-RTT |
| 0-RTT 恢复 | 不支持 | 支持（有重放风险） |
| 前向保密 | 可选 | 强制 |
| RSA 密钥交换 | 支持 | 移除 |
| 支持的密码套件 | 37 个 | 5 个 |
