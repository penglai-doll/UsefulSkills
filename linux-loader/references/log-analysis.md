# Log Analysis

读取时机: 用户要求登录、入侵、WebShell、操作时间线、服务日志或事故复盘时读取。

## OS 日志

- `/var/log/auth.log`
- `/var/log/secure`
- `/var/log/syslog`
- `/var/log/messages`
- `/var/log/cron`
- systemd journal 目录

## 用户痕迹

- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d`
- `/home/*/.bash_history`
- `/root/.bash_history`
- SSH: `/etc/ssh`, `/home/*/.ssh`, `/root/.ssh`

## Web/面板日志

- Nginx/Apache access/error logs
- `/www/wwwlogs`
- `/www/server/panel/logs`
- 1Panel 日志目录

输出时间线时优先给摘要和关键证据路径，不粘贴大段日志。
