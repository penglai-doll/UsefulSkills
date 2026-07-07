# Database Recovery

读取时机: 用户要求数据库恢复，或命中 MySQL/MariaDB/PostgreSQL/Redis/MongoDB 数据目录、dump 或备份时读取。

## 常见目录

- MySQL/MariaDB: `/var/lib/mysql`, `/www/server/data`, `/www/server/mysql`
- PostgreSQL: `/var/lib/postgresql`
- Redis: `/var/lib/redis`, `/etc/redis`
- MongoDB: `/var/lib/mongodb`
- Docker volumes: 通过 `docker-linux.md` 的 mount mapping 定位

## 常见备份

- `/www/backup`
- `*.sql`, `*.sql.gz`, `*.dump`, `*.bak`
- 面板 backup 目录

## 原则

- 不启动数据库服务。
- 不修复数据文件。
- 先定位数据目录、版本线索、配置和备份，再建议离线恢复方案。
