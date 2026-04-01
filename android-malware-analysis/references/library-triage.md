# AndroidX / 第三方库分流

在反编译代码分析中，先判断当前代码属于一方业务代码，还是 AndroidX / 第三方库。

## 目标

- 减少把库代码当成恶意业务逻辑的误报
- 减少无效大段源码阅读带来的 token 消耗
- 把分析重点放回一方代码、配置常量、桥接调用和回连构造
- 在需要调证时，优先从应用侧配置里抽取第三方 SDK key，而不是先读 SDK 内部实现

## 一方代码优先规则

优先阅读这些位置：

- manifest 中声明的 `activity`、`service`、`receiver`、`provider` 所在包
- launcher activity 所在包
- application 类所在包
- 直接持有域名、URL、socket、gateway、AES/Base64、命令分发的类
- `res/values/`、`res/xml/`、manifest 中的应用自有配置

如果 manifest package 是伪装包名，优先相信 manifest 组件实际落点，不要只相信 `package_name`。

## 常见三方/平台包前缀

默认先视为库代码，再决定是否需要深入：

- `android.`
- `androidx.`
- `com.android.`
- `com.google.`
- `java.`
- `javax.`
- `kotlin.`
- `kotlinx.`
- `okhttp3.`
- `retrofit2.`
- `org.apache.`
- `org.jetbrains.`

遇到以下名字时，也优先当作库或 SDK 上下文，而不是恶意结论本身：

- `WorkManager`
- `Room`
- `Compose`
- `ExoPlayer`
- `Bugsnag`
- `Facebook`
- `Snapkit`
- `WhatsApp`

## 分流流程

1. 先用 `rg` 或类名搜索确认包前缀和调用方向。
2. 只记录一行“这个库大概负责什么”。
3. 回到一方代码，找它如何调用该库。
4. 如果这是阿里、百度、腾讯、华为、友盟、极光、个推等 SDK，先在 manifest、`res/values`、一方初始化代码、应用自带 `json/properties/xml` 配置中提取 `AppKey`、`API Key`、`AccessKeyId`、`AccessKeySecret` 等值。
5. 只有在库的职责仍然不清楚时，才做网络检索。
6. 网络检索只查官方文档或上游项目文档，不查二手博客做定性依据。

## 网络检索建议

优先搜索：

- 官方 Android / AndroidX 文档
- 官方 SDK 文档
- 库项目的官方站点或 GitHub README / docs
- Maven Central / 官方制品页用于确认 artifact 和包名

输出时只保留最小必要结论，例如：

- `androidx.work`：后台任务调度框架，本身不是恶意能力证据
- `Bugsnag`：崩溃上报 SDK，相关 URL 不应直接当作 C2
- `ExoPlayer`：媒体播放库，文档链接不应直接当作回连地址
- `com.baidu.lbsapi`：若应用侧配置里出现 `API_KEY` / `AK`，应整理进报告供后续调证
- `com.alibaba.*` / `com.aliyun.*`：若应用侧配置里出现 `AccessKeyId` / `AccessKeySecret` / `AppKey`，应整理进报告供后续调证

## 常见误报例子

- `Handler.Callback`、`Window.Callback`、`SurfaceHolder.Callback`
  这是 Android 回调接口，不等于网络 callback
- Compose / SlotTable 相关字符串
  不应直接推导为博彩或业务关键词
- Bugsnag、Facebook、Snapkit、WhatsApp、ExoPlayer 文档或 SDK URL
  这是三方服务或文档地址，不应直接采信为恶意回连
