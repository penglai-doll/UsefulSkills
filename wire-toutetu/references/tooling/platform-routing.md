---
knowledge_id: tooling.platform-routing
title: Windows/Linux/WSL 路由
signals: [windows, linux, wsl, preflight]
read_when: 开始分析或工具缺失时。
support_status: best-effort
---

# Windows/Linux/WSL 路由

## 读取时机

开始分析或工具缺失时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

Windows 查 Wireshark；Linux 查包管理器；WSL 明确路径转换与 Linux TShark。

## 反例

宿主安装不代表 WSL 可调用。

## 提取方法

preflight 只探测并给升级提示，安装与驱动另行确认。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

混用版本会产生字段与路径差异。

## 夹具

Windows/TShark 4.6.4 实机验证；Linux/WSL 的路由判定以 mock 与单元测试覆盖，真实 TShark 冒烟由集成夹具补充，维持 best-effort 分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
