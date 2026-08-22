# ctf-patterns Knowledge Index

| Knowledge ID | Support | Signals | Read when |
|---|---|---|---|
| [`ctf-patterns.blind-sqli-timing`](blind-sqli-timing.md) | best-effort | `sqli`, `sleep`, `timing` | 参数呈布尔/时间盲注序列时。 |
| [`ctf-patterns.dns-icmp-tunnels`](dns-icmp-tunnels.md) | best-effort | `dns-tunnel`, `icmp-tunnel` | 标签或 Echo data 呈分片序列时。 |
| [`ctf-patterns.flag-object`](flag-object.md) | best-effort | `flag`, `file`, `object`, `magic` | 用户要求找 flag、文件或恢复对象时。 |
| [`ctf-patterns.keyboard-mouse`](keyboard-mouse.md) | best-effort | `keyboard`, `mouse`, `hid` | USB/HID 抓包需还原输入或轨迹时。 |
| [`ctf-patterns.multilayer`](multilayer.md) | verified-decode | `base64`, `hex`, `gzip`, `xor`, `rot13` | 载荷呈嵌套编码、压缩或魔数时。 |
| [`ctf-patterns.side-channels`](side-channels.md) | best-effort | `side-channel`, `packet-length`, `timing` | 明文不可见但题目暗示侧信道时。 |
