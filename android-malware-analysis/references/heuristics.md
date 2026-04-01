# Android Malware Heuristics

Use this file when you need to interpret signals from `scripts/analyze_package.py`.

## High-Signal Permission Combinations

- `BIND_ACCESSIBILITY_SERVICE` plus `SYSTEM_ALERT_WINDOW`
  - Common in overlay phishing, banker malware, and UI automation abuse.
- `REQUEST_INSTALL_PACKAGES` plus embedded payload files
  - Common in droppers and staged installers.
- `RECEIVE_BOOT_COMPLETED` plus network indicators
  - Suggests persistence with post-reboot communication.
- `SEND_SMS`, `READ_SMS`, or `RECEIVE_SMS`
  - Often used for OTP interception or premium-SMS fraud; verify context because some legitimate apps still use SMS flows.
- `MANAGE_EXTERNAL_STORAGE`
  - Broad data access; suspicious in consumer apps without a strong file-management use case.

## Loader and Payload Clues

- `DexClassLoader`, `InMemoryDexClassLoader`, and `PathClassLoader`
  - Strong evidence of runtime code loading.
- Embedded `.apk`, `.dex`, or `.jar` under `assets/` or `res/raw/`
  - Strong evidence of staged payload delivery.
- Large opaque `.dat` or `.bin` files combined with loader strings
  - Often indicate encrypted or packed secondary payloads.

## Native and Anti-Analysis Clues

- Native libraries are not malicious by themselves, but they raise review priority when paired with sparse Java strings or suspicious network endpoints.
- `frida`, `xposed`, `substrate`, `ptrace`, or debugger checks
  - Common anti-analysis markers.
- Packer names such as `jiagu`, `ijiami`, `bangcle`, `secshell`, or `chaosvmp`
  - Treat as obfuscation or protector artifacts, not as a malware verdict on their own.

## Network and Exfiltration Clues

- Hardcoded HTTP(S) URLs, non-private IPv4 addresses, and suspicious domains are useful IOCs.
- `HostnameVerifier`, trust-manager overrides, or trust-all strings
  - Often suggest TLS bypass or custom certificate handling.
- WebView JavaScript bridge strings
  - Raise risk when the app also loads remote content or remote configuration.

## False-Positive Notes

- Accessibility APIs can be legitimate for accessibility-focused apps.
- Device admin APIs can be legitimate in enterprise device-management software.
- Packer artifacts may appear in commercial apps that want anti-tamper protection.
- Cryptocurrency, wallet, and encryption keywords are weak indicators without execution context.
- AndroidX、Compose、WorkManager、Room、ExoPlayer 等平台或基础库字符串，默认不应直接推导为恶意业务功能。
- Bugsnag、Facebook、Snapkit、WhatsApp 等第三方 SDK 的文档链接、上报地址或 API 域名，默认不应直接采信为恶意 C2。
- `Handler.Callback`、`Window.Callback`、`SurfaceHolder.Callback` 等接口名称属于常见框架回调，不等于网络 callback。

## Negative-Signal Pruning

Use absence of evidence to reduce work only when the absence is explicit in static artifacts.

- No `lib/` native libraries and no `System.loadLibrary`
  - De-prioritize native analysis unless other evidence points to JNI handoff.
- No accessibility permission and no declared accessibility service
  - Skip accessibility-abuse deep dive.
- No SMS permissions and no SMS APIs
  - Skip OTP-interception or premium-SMS branches.
- No `DexClassLoader` / `InMemoryDexClassLoader` and no embedded payload files
  - Skip staged-payload deep dive.
- No WebView, no remote URL loads, and no JavaScript bridge
  - De-prioritize WebView abuse analysis.
- Third-party packages not referenced by manifest components, entry flow, or callback assembly
  - Summarize them and return to first-party code.
