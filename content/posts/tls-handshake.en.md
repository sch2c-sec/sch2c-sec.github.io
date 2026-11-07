+++
date = '2026-10-15T00:00:00+08:00'
draft = false
title = 'TLS 1.3 Handshake Explained'
tags = ['Protocol Analysis', 'TLS', 'Cryptography']
description = 'TLS 1.3 cuts the number of handshake round trips compared with 1.2. This post walks through the handshake flow and key derivation byte by byte.'
+++

TLS 1.3 was published in 2018 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)). Compared with TLS 1.2, it makes two core improvements: the handshake drops from 2-RTT to 1-RTT, and forward secrecy is mandatory.

## Handshake Flow

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

> `{}` means encrypted with handshake keys; `[]` means encrypted with application keys.

## ClientHello Structure

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

## Key Derivation (HKDF)

TLS 1.3 derives all of its keys with HKDF ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)):

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

## Wireshark Filters

```wireshark
# TLS 1.3 only
tls.handshake.extensions.supported_versions == 0x0304

# Show ClientHello
tls.handshake.type == 1

# Show certificates
tls.handshake.type == 11
```

## Comparison with TLS 1.2

| Feature | TLS 1.2 | TLS 1.3 |
|------|---------|---------|
| Handshake round trips | 2-RTT | 1-RTT |
| 0-RTT resumption | Not supported | Supported (replay risk) |
| Forward secrecy | Optional | Mandatory |
| RSA key exchange | Supported | Removed |
| Cipher suites | 37 | 5 |
