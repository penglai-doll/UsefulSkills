# protocols Knowledge Index

| Knowledge ID | Support | Signals | Read when |
|---|---|---|---|
| [`protocols.databases`](databases.md) | best-effort | `mysql`, `redis`, `mongodb` | 出现数据库端口或解码字段时。 |
| [`protocols.dns`](dns.md) | verified-extract | `dns`, `dns.qry.name`, `txt` | 出现 DNS、长子域、TXT 或高频 NXDOMAIN 时。 |
| [`protocols.ftp`](ftp.md) | verified-extract | `ftp`, `ftp-data`, `pasv`, `retr`, `stor` | 出现 FTP 控制或数据连接时。 |
| [`protocols.http1`](http1.md) | verified-extract | `http`, `get`, `post`, `chunked`, `multipart` | 出现 HTTP/1.x、表单、上传下载或 WebShell 候选时。 |
| [`protocols.http2`](http2.md) | best-effort | `http2`, `h2`, `streamid` | 出现 ALPN h2 或 http2.streamid 时。 |
| [`protocols.http3-quic`](http3-quic.md) | metadata-only | `quic`, `http3`, `dcid`, `scid` | 出现 QUIC、HTTP/3 或 UDP/443 时。 |
| [`protocols.icmp`](icmp.md) | verified-extract | `icmp`, `icmpv6`, `echo` | 出现 Echo、自定义 data 或异常长度时。 |
| [`protocols.rdp`](rdp.md) | best-effort | `rdp`, `tpkt`, `x224` | 出现 TPKT/X.224、CredSSP 或 RDPUDP 时。 |
| [`protocols.rtp`](rtp.md) | best-effort | `rtp`, `rtcp`, `ssrc` | 出现 RTP/RTCP 或连续 UDP 媒体时。 |
| [`protocols.smb`](smb.md) | best-effort | `smb`, `smb2`, `smb3` | 出现 SMB 协商、树连接或文件读写时。 |
| [`protocols.smtp`](smtp.md) | verified-extract | `smtp`, `mime`, `mail` | 出现 SMTP、MIME boundary 或附件时。 |
| [`protocols.socks`](socks.md) | best-effort | `socks`, `socks5`, `proxy` | 出现 SOCKS 握手或代理链时。 |
| [`protocols.tcp-udp`](tcp-udp.md) | verified-extract | `tcp`, `udp`, `retransmission`, `out_of_order` | 出现 TCP/UDP 或需判断缺段、乱序、重传时。 |
| [`protocols.tls`](tls.md) | best-effort | `tls`, `ssl`, `keylog`, `rsa` | 出现 TLS、SSLKEYLOGFILE、RSA 私钥或应用层不可见时。 |
| [`protocols.usb-hid`](usb-hid.md) | verified-extract | `usb`, `hid`, `usbhid`, `keyboard` | 出现 USBPcap、usbmon 或 HID report 时。 |
| [`protocols.websocket`](websocket.md) | best-effort | `websocket`, `upgrade`, `opcode` | 出现 HTTP Upgrade、opcode 或长连接双向帧时。 |
| [`protocols.wifi`](wifi.md) | best-effort | `wlan`, `radiotap`, `eapol`, `wpa` | 出现 802.11、Radiotap 或 EAPOL 时。 |
