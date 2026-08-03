# WireToutetu Knowledge Index

先依据 CLI `routes.recommended_references` 读取命中的叶子；不要一次加载整个知识库。

| Domain | Leaves | Index |
|---|---:|---|
| `ctf-patterns` | 6 | [ctf-patterns/index.md](ctf-patterns/index.md) |
| `decoding` | 5 | [decoding/index.md](decoding/index.md) |
| `protocols` | 17 | [protocols/index.md](protocols/index.md) |
| `schemas` | 1 | [schemas/index.md](schemas/index.md) |
| `tooling` | 4 | [tooling/index.md](tooling/index.md) |
| `webshell` | 8 | [webshell/index.md](webshell/index.md) |

## Signal lookup

| Signal | Knowledge IDs |
|---|---|
| `aes` | `decoding.symmetric`, `webshell.behinder`, `webshell.godzilla` |
| `aircrack` | `tooling.optional-tools` |
| `antsword` | `webshell.antsword` |
| `base64` | `ctf-patterns.multilayer`, `decoding.encoding`, `webshell.antsword` |
| `base64url` | `decoding.encoding` |
| `behinder` | `webshell.behinder` |
| `capinfos` | `tooling.tshark` |
| `cbc` | `decoding.symmetric` |
| `chopper` | `webshell.chopper` |
| `chunked` | `protocols.http1` |
| `dcid` | `protocols.http3-quic` |
| `dec` | `schemas.data-contracts` |
| `deflate` | `decoding.compression` |
| `dns` | `protocols.dns` |
| `dns-tunnel` | `ctf-patterns.dns-icmp-tunnels` |
| `dns.qry.name` | `protocols.dns` |
| `eapol` | `protocols.wifi` |
| `ecb` | `decoding.symmetric` |
| `echo` | `protocols.icmp` |
| `elf` | `decoding.file-container` |
| `eval` | `webshell.chopper` |
| `evt` | `schemas.data-contracts` |
| `ffmpeg` | `tooling.optional-tools` |
| `fields` | `tooling.tshark` |
| `file` | `ctf-patterns.flag-object` |
| `find` | `schemas.data-contracts` |
| `flag` | `ctf-patterns.flag-object` |
| `flow` | `schemas.data-contracts` |
| `ftp` | `protocols.ftp` |
| `ftp-data` | `protocols.ftp` |
| `gcm` | `decoding.symmetric` |
| `get` | `protocols.http1` |
| `godzilla` | `webshell.godzilla` |
| `gzip` | `ctf-patterns.multilayer`, `decoding.compression` |
| `h2` | `protocols.http2` |
| `hex` | `ctf-patterns.multilayer`, `decoding.encoding` |
| `hid` | `ctf-patterns.keyboard-mouse`, `protocols.usb-hid` |
| `high-entropy` | `webshell.detection-matrix` |
| `http` | `protocols.http1` |
| `http2` | `protocols.http2` |
| `http3` | `protocols.http3-quic` |
| `icmp` | `protocols.icmp` |
| `icmp-tunnel` | `ctf-patterns.dns-icmp-tunnels` |
| `icmpv6` | `protocols.icmp` |
| `key` | `decoding.xor` |
| `keyboard` | `ctf-patterns.keyboard-mouse`, `protocols.usb-hid` |
| `keylog` | `protocols.tls` |
| `klv` | `webshell.suo5` |
| `known-plaintext` | `decoding.xor` |
| `large-capture` | `tooling.large-captures` |
| `linux` | `tooling.platform-routing` |
| `magic` | `ctf-patterns.flag-object`, `decoding.file-container` |
| `mail` | `protocols.smtp` |
| `memory-limit` | `tooling.large-captures` |
| `mime` | `protocols.smtp` |
| `mongodb` | `protocols.databases` |
| `mouse` | `ctf-patterns.keyboard-mouse` |
| `multipart` | `protocols.http1` |
| `mysql` | `protocols.databases` |
| `neoreg` | `webshell.regeorg` |
| `obfpost` | `webshell.weevely` |
| `obj` | `schemas.data-contracts` |
| `object` | `ctf-patterns.flag-object` |
| `opcode` | `protocols.websocket` |
| `out_of_order` | `protocols.tcp-udp` |
| `packet-length` | `ctf-patterns.side-channels` |
| `password` | `webshell.weevely` |
| `pasv` | `protocols.ftp` |
| `pdf` | `decoding.file-container` |
| `pe` | `decoding.file-container` |
| `post` | `protocols.http1`, `webshell.antsword`, `webshell.behinder`, `webshell.chopper`, `webshell.detection-matrix`, `webshell.godzilla` |
| `preflight` | `tooling.platform-routing` |
| `proxy` | `protocols.socks`, `webshell.regeorg` |
| `quic` | `protocols.http3-quic` |
| `radiotap` | `protocols.wifi` |
| `rdp` | `protocols.rdp` |
| `redis` | `protocols.databases` |
| `regeorg` | `webshell.regeorg` |
| `retr` | `protocols.ftp` |
| `retransmission` | `protocols.tcp-udp` |
| `rot13` | `ctf-patterns.multilayer`, `decoding.encoding`, `webshell.antsword` |
| `rsa` | `protocols.tls` |
| `rtcp` | `protocols.rtp` |
| `rtp` | `protocols.rtp` |
| `scapy` | `tooling.optional-tools` |
| `schema` | `schemas.data-contracts` |
| `scid` | `protocols.http3-quic` |
| `side-channel` | `ctf-patterns.side-channels` |
| `sleep` | `ctf-patterns.blind-sqli-timing` |
| `slice` | `tooling.large-captures` |
| `smb` | `protocols.smb` |
| `smb2` | `protocols.smb` |
| `smb3` | `protocols.smb` |
| `smtp` | `protocols.smtp` |
| `socks` | `protocols.socks` |
| `socks5` | `protocols.socks` |
| `sqli` | `ctf-patterns.blind-sqli-timing` |
| `ssl` | `protocols.tls` |
| `ssrc` | `protocols.rtp` |
| `stor` | `protocols.ftp` |
| `streamid` | `protocols.http2` |
| `suo5` | `webshell.suo5` |
| `tcp` | `protocols.tcp-udp` |
| `timing` | `ctf-patterns.blind-sqli-timing`, `ctf-patterns.side-channels` |
| `tls` | `protocols.tls` |
| `tpkt` | `protocols.rdp` |
| `tshark` | `tooling.tshark` |
| `txn` | `schemas.data-contracts` |
| `txt` | `protocols.dns` |
| `udp` | `protocols.tcp-udp` |
| `upgrade` | `protocols.websocket` |
| `url` | `decoding.encoding` |
| `usb` | `protocols.usb-hid` |
| `usbhid` | `protocols.usb-hid` |
| `webshell` | `webshell.detection-matrix` |
| `websocket` | `protocols.websocket`, `webshell.suo5` |
| `weevely` | `webshell.weevely` |
| `windows` | `tooling.platform-routing` |
| `wlan` | `protocols.wifi` |
| `wpa` | `protocols.wifi` |
| `wsl` | `tooling.platform-routing` |
| `x-cmd` | `webshell.regeorg` |
| `x224` | `protocols.rdp` |
| `xor` | `ctf-patterns.multilayer`, `decoding.xor`, `webshell.behinder`, `webshell.godzilla`, `webshell.suo5` |
| `zeek` | `tooling.optional-tools` |
| `zip` | `decoding.file-container` |
| `zlib` | `decoding.compression` |
