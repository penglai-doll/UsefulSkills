# webshell Knowledge Index

| Knowledge ID | Support | Signals | Read when |
|---|---|---|---|
| [`webshell.antsword`](antsword.md) | verified-decode | `antsword`, `base64`, `rot13`, `post` | 出现蚁剑 PHP 编码链、随机前缀或 eval 参数时。 |
| [`webshell.behinder`](behinder.md) | verified-decode | `behinder`, `aes`, `xor`, `post` | POST 高熵、固定路径、AES/XOR 或提供冰蝎 key 时。 |
| [`webshell.chopper`](chopper.md) | verified-decode | `chopper`, `eval`, `post` | 出现单参数 POST、脚本关键字或响应定界时。 |
| [`webshell.detection-matrix`](detection-matrix.md) | best-effort | `webshell`, `post`, `high-entropy` | 命中多个家族或需排除正常 POST 时。 |
| [`webshell.godzilla`](godzilla.md) | verified-decode | `godzilla`, `aes`, `xor`, `post` | 出现 pass+key、MD5 定界或哥斯拉 profile 时。 |
| [`webshell.regeorg`](regeorg.md) | verified-extract | `regeorg`, `neoreg`, `x-cmd`, `proxy` | 出现 CONNECT/FORWARD/READ/DISCONNECT 头时。 |
| [`webshell.suo5`](suo5.md) | verified-decode | `suo5`, `klv`, `xor`, `websocket` | 出现 URL-safe Base64 分帧、2 字节 XOR 或 KLV 键时。 |
| [`webshell.weevely`](weevely.md) | verified-decode | `weevely`, `obfpost`, `password` | 提供候选密码或发现密码派生定界时。 |
