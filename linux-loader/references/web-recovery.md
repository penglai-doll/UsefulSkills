# Web Recovery

读取时机: 用户要求恢复网站，或命中 web root / Nginx / Apache / PHP / Node / Java 服务线索时读取。

## Web roots

- `/www/wwwroot`
- `/var/www`
- `/srv`
- `/usr/share/nginx/html`
- `/home/*/public_html`
- Docker mount 映射中的 web 路径

## 配置

- Nginx: `/etc/nginx`, `/www/server/nginx/conf`
- Apache: `/etc/apache2`, `/etc/httpd`, `/www/server/apache/conf`
- PHP: `.env`, `config.php`, `database.php`, `.user.ini`
- Node/Java/Python: `.env`, `config/`, `application.yml`, `settings.py`

## 输出

- 站点目录和框架线索。
- 配置文件位置，不直接暴露 secrets，除非用户明确要求本地提取。
- 上传目录、备份文件、日志入口。
