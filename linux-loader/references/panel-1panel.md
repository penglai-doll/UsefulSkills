# 1Panel

读取时机: 命中 `/opt/1panel`、`/var/lib/1panel`、`1panel.service`、1Panel app/compose 布局，或用户要求还原 1Panel 时读取。

## 常见路径

- 安装目录: `/opt/1panel`
- 数据目录: `/var/lib/1panel`
- 服务: `1panel.service`
- 应用编排: 1Panel app 目录中的 compose 文件
- 备份和日志: 检查 1Panel 数据目录下 backup/log 相关目录

## Docker 关联

1Panel 常依赖 Docker/Compose。命中 1Panel 后通常也读取 `docker-linux.md`，重点恢复:

- app compose 文件
- named volume
- bind mount
- 网站和数据库容器的数据路径

不要启动容器或服务。
