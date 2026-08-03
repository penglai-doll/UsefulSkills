# decoding Knowledge Index

| Knowledge ID | Support | Signals | Read when |
|---|---|---|---|
| [`decoding.compression`](compression.md) | verified-decode | `gzip`, `zlib`, `deflate` | 出现压缩魔数或 Content-Encoding 时。 |
| [`decoding.encoding`](encoding.md) | verified-decode | `url`, `base64`, `base64url`, `hex`, `rot13` | 字段满足编码约束时。 |
| [`decoding.file-container`](file-container.md) | verified-extract | `magic`, `zip`, `pdf`, `pe`, `elf` | 输出可能是文件或归档时。 |
| [`decoding.symmetric`](symmetric.md) | verified-decode | `aes`, `cbc`, `ecb`, `gcm` | sidecar/profile 指定 AES key/mode/IV/nonce/tag 时。 |
| [`decoding.xor`](xor.md) | verified-decode | `xor`, `key`, `known-plaintext` | 提供 key、随机 XOR 协议或已知明文时。 |
