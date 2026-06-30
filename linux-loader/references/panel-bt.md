# BT / aaPanel

读取时机: 命中 `/www/server/panel`、`/www/wwwroot`、`/www/backup`、宝塔/aaPanel 服务，或用户要求还原宝塔数据时读取。

## 常见路径

- 面板: `/www/server/panel`
- 站点: `/www/wwwroot`
- 备份: `/www/backup`
- Nginx: `/www/server/nginx/conf`
- Apache: `/www/server/apache/conf`
- PHP: `/www/server/php`
- MySQL: `/www/server/data`, `/www/server/mysql`
- 日志: `/www/wwwlogs`, `/www/server/panel/logs`

## 分析目标

- 面板配置和站点列表。
- 网站目录、配置文件、上传目录。
- 数据库目录或备份文件。
- Nginx/Apache/PHP 配置。
- 面板日志和操作痕迹。

仅在命中宝塔/aaPanel 或用户明确要求时读取本文件。
