# Docker Linux

读取时机: 命中 Docker data-root、Docker service、compose 文件，或用户要求 Docker/容器数据恢复时读取。

## 入口

- 默认 data-root: `/var/lib/docker`
- 自定义 data-root: `/etc/docker/daemon.json`
- 容器元数据: `containers/<id>/config.v2.json`, `containers/<id>/hostconfig.json`
- volumes: `volumes/<name>/_data`
- compose: `docker-compose.yml`, `compose.yaml`, `*.compose.yml`

## 优先输出挂载关系

字段:

- container id/name
- image
- compose project
- container path
- host path 或 volume name
- resolved volume path
- source exists
- likely_business_data: `web`, `database`, `config`, `backup`, `data`

重点路径:

- `/app`
- `/data`
- `/config`
- `/var/www`
- `/usr/share/nginx/html`
- `/www/wwwroot`
- `/etc/nginx`
- `/var/lib/mysql`
- `/var/lib/postgresql`

## 禁止

- 不启动容器。
- 不执行镜像内程序。
- 不修改 Docker metadata。
- 不把完整 metadata 塞进模型上下文，使用摘要和 sidecar。
