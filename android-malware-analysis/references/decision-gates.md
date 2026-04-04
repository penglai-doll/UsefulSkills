# 分支与跳过决策

在每个阶段结束后使用本文件，决定下一步要继续、跳过，还是升级分析力度。

## 使用方法

每次只回答三个问题：

1. 当前阶段已经确认了什么
2. 还缺哪一个结论
3. 为了补这个缺口，最小必要的下一步是什么

如果一个动作不能直接补当前缺口，就先不要做。

## 输入形态分支

- 输入已经是 JADX 目录
  - 跳过 DEX 反编译，只补资源或 manifest 缺口
- 输入已经是 apktool 目录
  - 跳过资源解包，只在缺源码时补 `jadx`
- 输入目录已经包含 `analysis.json`、`callback-config.json`、`report.md`
  - 先读产物，不要立刻重跑主流程

## 应用类型分支

- WebView / Hybrid / uni-app / Cordova
  - 优先看 `assets/`、`res/raw/`、远程 URL、JS bridge、下载逻辑
- Flutter
  - 优先看 manifest、资源配置、渠道常量、MethodChannel / platform bridge
- React Native
  - 优先看 bundle、bridge、原生模块注册、远程配置
- 纯原生
  - 优先看 manifest 组件、一方包、命令分发与回连构造

## 权限与组件分支

- 有 `BIND_ACCESSIBILITY_SERVICE` 或声明无障碍服务
  - 继续检查 UI 自动化、手势、窗口树、截图
- 没有无障碍权限，也没有无障碍服务
  - 跳过无障碍深挖
- 有 `RECEIVE_BOOT_COMPLETED`、前台服务、闹钟、唤醒锁
  - 继续检查驻留与拉活链路
- 没有相关权限和组件
  - 降低持久化分支优先级
- 有 `READ_SMS` / `SEND_SMS` / `RECEIVE_SMS`
  - 继续检查短信读取、拦截、发送逻辑
- 没有短信权限和 API
  - 跳过短信分支

## 载荷与执行流分支

- 有 `DexClassLoader`、内嵌 `.dex` / `.apk` / `.jar`、大体积加密资源
  - 继续检查二阶段载荷
- 没有动态加载迹象
  - 不要花大量时间在 loader 分支
- 启动链只落到少数 service / receiver / command dispatcher
  - 围绕这些类继续扩展
- 某些包或类没有 manifest 注册、没有调用边、没有命令分发引用
  - 只记摘要，不深挖

## 回连分析分支

- 第一阶段字符串检索只出现公开域名、license、三方 SDK 地址
  - 不要直接定性为 C2，继续做第二阶段代码推理
- 第二阶段在一方代码中恢复出域名常量、URL 拼接或 socket/gateway 组装
  - 采信第二阶段结果，并停止扩大无关 IOC 搜索
- 第二阶段没有结果，但第一阶段有少量一方候选
  - 保留为低置信度候选，并在报告中写明限制
- 两阶段都没有结果
  - 结束回连扩展，避免在无关库中盲搜

## 三方库分支

- 包前缀属于 AndroidX、Google、Kotlin、OkHttp、Retrofit 等平台或基础库
  - 先当作库，不当作恶意结论
- 三方库只在依赖树中出现，但没有进入入口链路、命令链路或回连链路
  - 只做一行摘要
- 三方库被一方代码直接调用，而且职责影响恶意判断
  - 读最小必要源码；仍不清楚时再查官方文档

## Native 分支

- 存在 `lib/`、`System.loadLibrary`、JNI 方法、Java 侧逻辑断裂、packer 签名或反分析标记
  - 先做最小 native strings 分析，再决定是否升级 native 深挖
- 不存在这些迹象
  - 不要默认展开 native 深挖

## 停止条件

当以下条件成立时，停止继续展开新分支：

- 关键结论已经可以由三步以上逻辑链支撑
- 两阶段回连已经给出最终采信或明确无结论
- 剩余未分析对象不在入口链路、权限链路或回连链路上
- 继续分析只会重复验证已经成立的结论
