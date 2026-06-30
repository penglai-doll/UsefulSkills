# Common Hosting Panels

读取时机: 命中非 BT/1Panel 的面板线索时读取。保持轻量，不做深教程。

## 快速路径

- cPanel: `/var/cpanel`, `/usr/local/cpanel`, `/etc/apache2/conf.d`, `/home/*/public_html`
- Plesk: `/opt/psa`, `/var/www/vhosts`, `/etc/psa`, `/var/log/plesk`
- DirectAdmin: `/usr/local/directadmin`, `/home/*/domains`
- Webmin: `/etc/webmin`, `/var/webmin`
- CyberPanel: `/usr/local/CyberCP`, `/home/*/public_html`
- Nginx Proxy Manager: Docker/compose 目录，通常有 `data/nginx` 和 `letsencrypt`

## 输出

- 面板类型和命中路径。
- 站点根目录候选。
- 配置、备份、日志入口。
- 是否需要读取 Docker reference。
