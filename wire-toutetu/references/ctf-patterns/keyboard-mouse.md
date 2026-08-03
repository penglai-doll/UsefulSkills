---
knowledge_id: ctf-patterns.keyboard-mouse
title: 键鼠轨迹题
signals: [keyboard, mouse, hid]
read_when: USB/HID 抓包需还原输入或轨迹时。
support_status: best-effort
---

# 键鼠轨迹题

## 读取时机

USB/HID 抓包需还原输入或轨迹时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

键盘维护 modifier+pressed；鼠标累积 signed dx/dy 和按键状态。

## 反例

布局、采样率与灵敏度影响结果。

## 提取方法

输出原始事件表和解释结果，允许指定布局/缩放/坐标。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

缺 descriptor 时列假设并标 partial。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
