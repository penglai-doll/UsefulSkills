---
knowledge_id: protocols.wifi
title: IEEE 802.11/WPA
signals: [wlan, radiotap, eapol, wpa]
read_when: 出现 802.11、Radiotap 或 EAPOL 时。
support_status: best-effort
---

# IEEE 802.11/WPA

## 读取时机

出现 802.11、Radiotap 或 EAPOL 时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

BSSID/STA、信道、管理帧、四次握手、重试和保护标志。

## 反例

Deauth 也可能来自漫游或干扰。

## 提取方法

先确认握手与 SSID/BSSID，再使用显式提供的 PSK/PMK。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

缺握手或密钥错误时只保留元数据。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
