# 升级分析矩阵

只有在现有产物、主流程脚本和更窄的补洞命令都无法回答当前问题时，才读取本文件。

## 何时升级

- Manifest 或 resources 仍不完整，需要更强的解码路径
- Java 侧调用链在 JNI、native 壳、packer 或 signer 问题处中断
- 两阶段回连都无法给出结果，但仍有明确的高价值待解问题
- 现有报告缺少某个关键结论，而该结论无法从已有 artifacts 中恢复

## 优先升级顺序

1. 先复用已有输出目录和中间产物
2. 再用更窄的单点命令补缺口
3. 最后才升级到更重的工具或更深的源码阅读

## 常见升级路径

- Manifest / resources 不清晰：优先 `apktool`、`aapt2`、`apkanalyzer`
- 代码入口不清晰：优先 `jadx` 导航一方源码，再配合 `rg`
- Native 命中 packer、anti-analysis 或 JNI 断裂：先保留限制说明，再决定是否单独做 native 深挖
- Split APK 缺少 base 信息：先确认 `base.apk` 是否完整，再决定是否展开 split 组合分析

## 不要升级的情况

- 只是为了重复确认已经成立的结论
- 只会把阅读范围扩大到无关三方库或 AndroidX
- 无法明确说明“升级这一步能补哪个具体缺口”
