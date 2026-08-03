---
knowledge_id: protocols.usb-hid
title: USB/HID 与键鼠恢复
signals: [usb, hid, usbhid, keyboard]
read_when: 出现 USBPcap、usbmon 或 HID report 时。
support_status: verified-extract
---

# USB/HID 与键鼠恢复

## 读取时机

出现 USBPcap、usbmon 或 HID report 时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

bus/device/endpoint、report ID、modifier、keycode、按下释放和鼠标位移。

## 反例

键盘布局、组合键和丢包会改变结果。

## 提取方法

按设备端点维护按键状态，同时输出原始 report 与布局假设。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

未知 descriptor、NKRO 或缺 release 时标 partial。

## 夹具

`pcap.usb-hid-basic`

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
