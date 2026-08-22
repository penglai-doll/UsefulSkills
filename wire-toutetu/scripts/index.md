# WireToutetu Script Index

此文件由 `build_indexes.py` 从 `registry.yaml` 确定性生成。

| Plugin | Stage | Support | Signals | Knowledge |
|---|---|---|---|---|
| `proto.dns` | transactions | verified-extract | `dns` | `protocols.dns` |
| `proto.ftp` | transactions | verified-extract | `ftp`, `ftp-data` | `protocols.ftp` |
| `proto.http1` | transactions | verified-extract | `http`, `post`, `get` | `protocols.http1` |
| `proto.http2` | transactions | best-effort | `http2`, `h2` | `protocols.http2` |
| `proto.icmp` | transactions | verified-extract | `icmp`, `icmpv6` | `protocols.icmp` |
| `proto.mongodb` | transactions | best-effort | `mongodb`, `mongo` | `protocols.databases` |
| `proto.mysql` | transactions | best-effort | `mysql` | `protocols.databases` |
| `proto.quic` | transactions | metadata-only | `quic`, `http3` | `protocols.http3-quic` |
| `proto.rdp` | transactions | best-effort | `rdp`, `tpkt`, `x224` | `protocols.rdp` |
| `proto.redis` | transactions | best-effort | `redis`, `resp` | `protocols.databases` |
| `proto.rtp` | transactions | best-effort | `rtp`, `rtcp` | `protocols.rtp` |
| `proto.smb` | transactions | best-effort | `smb`, `smb2`, `smb3` | `protocols.smb` |
| `proto.smtp` | transactions | verified-extract | `smtp`, `mime` | `protocols.smtp` |
| `proto.socks` | transactions | best-effort | `socks`, `socks5` | `protocols.socks` |
| `proto.tcp_udp` | inventory | verified-extract | `tcp`, `udp` | `protocols.tcp-udp` |
| `proto.tls` | decode | best-effort | `tls`, `ssl`, `keylog` | `protocols.tls` |
| `proto.usb_hid` | transactions | verified-extract | `usb`, `hid`, `keyboard` | `protocols.usb-hid` |
| `proto.websocket` | transactions | best-effort | `websocket`, `upgrade` | `protocols.websocket` |
| `proto.wifi` | inventory | best-effort | `wlan`, `radiotap`, `eapol` | `protocols.wifi` |
| `tunnel.regeorg` | webshell | verified-extract | `http`, `regeorg`, `neoreg`, `proxy` | `webshell.regeorg` |
| `webshell.antsword` | webshell | verified-decode | `http`, `post`, `base64`, `rot13`, `antsword` | `webshell.antsword` |
| `webshell.behinder` | webshell | verified-decode | `http`, `post`, `aes`, `xor`, `behinder` | `webshell.behinder` |
| `webshell.chopper` | webshell | verified-decode | `http`, `post`, `chopper`, `eval` | `webshell.chopper` |
| `webshell.godzilla` | webshell | verified-decode | `http`, `post`, `aes`, `xor`, `godzilla` | `webshell.godzilla` |
| `webshell.suo5` | webshell | verified-decode | `http`, `websocket`, `suo5`, `klv`, `xor` | `webshell.suo5` |
| `webshell.weevely` | webshell | verified-decode | `http`, `post`, `weevely`, `password` | `webshell.weevely` |
