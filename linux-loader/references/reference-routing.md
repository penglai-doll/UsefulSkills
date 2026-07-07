# Reference Routing

读取时机: 基础 JSON 已生成后先读本文件。只加载 `priority=required` 的详细 reference。

## 路由规则

| 线索或用户目标 | reference | priority |
| --- | --- | --- |
| `/www/server/panel`, `/www/wwwroot`, `/www/backup`, BT/aaPanel 服务 | `panel-bt.md` | required |
| `/opt/1panel`, `/var/lib/1panel`, `1panel.service`, 1Panel compose/app 布局 | `panel-1panel.md` | required |
| Webmin, CyberPanel, cPanel, Plesk, DirectAdmin, Nginx Proxy Manager | `panel-common.md` | required |
| `/var/lib/docker`, Docker service, container metadata, compose 文件, Docker 用户目标 | `docker-linux.md` | required |
| `/var/www`, `/srv`, Nginx/Apache 配置, 网站恢复目标 | `web-recovery.md` | required |
| MySQL/MariaDB/PostgreSQL/Redis/MongoDB 数据目录或数据库恢复目标 | `database-recovery.md` | required |
| 登录、入侵、WebShell、操作时间线、日志分析目标 | `log-analysis.md` | required |

## 本地模型规则

- `inspect_evidence.py` 应输出 `routes.recommended_references`，包括 `file`, `priority`, `reason`。
- 未命中且用户未提出的方向不要读取详细 reference。
- 可选 reference 只提示，不读取，除非用户确认或 focused task 需要。
