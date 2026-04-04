# Android 恶意应用静态分析报告

## 1. 样本与基本信息

- 样本路径: `/samples/demo.apk`
- 包类型: `apk`
- 分析模式: `full`
- 风险等级: `high` (`87`)
- 包名: `com.demo.shell`
- 主入口函数: `com.demo.entry.MainActivity.onCreate(...)`

## 2. 环境检查

- 推荐模式: `full`
- 是否满足完整分析: `true`

## 3. 技术类型与业务功能分类

- 首要技术类型: `WebView 混合应用`
- 业务功能 `信息窃取`（高）: 高危运行时权限覆盖短信、联系人、标识符、媒体或存储等敏感数据面。

## 4. 回连基础设施与加密线索

### 第一阶段：原始字符串检索

- 一方候选 URLs: `https://demo-c2.example/api/upload`
- 三方/库候选摘要: URLs `1` 条，域名 `1` 条

### 第二阶段：反编译代码推理

- URLs: `https://demo-c2.example/api/upload`
- 代码线索: `sources/com/demo/net/Config.java` -> `"https://" + host + "/api/upload"`

### 最终采信结果

- 采信说明: 优先采用反编译代码推理结果，因为发现了一方源码中的域名常量与拼接 URL。

## 5. 控制流与执行路径

- 概要: 基于静态证据推测的启动、采集、处理与回连路径。

## 6. 证据链

### 样本存在明确的回连或控制基础设施。

逻辑链:
1. 第一阶段先做原始字符串检索，提取 URL、域名、IP 与配置样式字符串。
2. 第二阶段在一方反编译代码中追踪域名常量、Socket 配置与字符串拼接。
3. 若代码推理阶段得到更强证据，则优先采信其输出作为最终回连结果。

## 7. 产物

- 回连配置导出: `cache/demo/callback-config.json`
- 调试噪声日志: `cache/demo/noise-log.json`
- Markdown 报告: `报告/demo/report.md`
- DOCX 报告: `报告/demo/report.docx`
