from __future__ import annotations

FUNCTION_LABELS_ZH = {
    "adult-live": "成人/直播引流",
    "fraud-phishing": "欺诈/钓鱼",
    "gambling": "博彩",
    "information-stealing": "信息窃取",
    "native-android": "原生 Android",
    "react-native": "React Native",
    "trojan-dropper": "木马/投递器",
    "uniapp": "uni-app",
    "webview-hybrid": "WebView 混合应用",
}
CONFIDENCE_LABELS_ZH = {
    "high": "高",
    "medium": "中",
    "low": "低",
}
STAGE_LABELS_ZH = {
    "behavioral-outcome": "行为结论",
    "callback": "回连阶段",
    "data-acquisition": "数据采集",
    "data-protection": "数据处理",
    "framework-bootstrap": "框架启动",
    "startup": "启动阶段",
}


def label_function_name(name: str) -> str:
    return FUNCTION_LABELS_ZH.get(name, name)


def label_confidence(name: str) -> str:
    return CONFIDENCE_LABELS_ZH.get(name, name)


def label_stage(name: str) -> str:
    return STAGE_LABELS_ZH.get(name, name)


def build_flow(manifest_info: dict, framework: dict, functions: list[dict], crypto: dict, callback_config: dict, triage: dict) -> dict:
    steps = []
    launcher = manifest_info.get("launcher_activity") or manifest_info.get("application_name") or manifest_info.get("package_name")
    if launcher:
        steps.append({"stage": "startup", "summary": f"可从 `{launcher}` 推定应用启动入口。", "evidence": [manifest_info.get("main_entry_function") or launcher]})

    primary = framework["primary_type"]
    if primary == "flutter":
        steps.append({"stage": "framework-bootstrap", "summary": "样本可能先启动 Flutter 容器，再通过原生插件桥接关键能力。", "evidence": framework["types"][0]["evidence"]})
    elif primary == "uniapp":
        steps.append({"stage": "framework-bootstrap", "summary": "样本可能通过 uni-app / DCloud 容器加载前端包并调用原生桥。", "evidence": framework["types"][0]["evidence"]})
    elif primary == "webview-hybrid":
        steps.append({"stage": "framework-bootstrap", "summary": "样本可能通过 WebView 容器加载页面或资源，并向页面暴露原生桥。", "evidence": framework["types"][0]["evidence"]})
    else:
        steps.append({"stage": "framework-bootstrap", "summary": "未发现主导性的混合框架，行为主要依据 manifest 组件与 API 字符串推断。", "evidence": framework["types"][0]["evidence"]})

    sensitive_notes = []
    if manifest_info.get("dangerous_permissions"):
        sensitive_notes.append("危险权限")
    if manifest_info.get("special_permissions"):
        sensitive_notes.append("特殊权限")
    if {"Accessibility automation", "SMS interception or fraud", "Screen capture capability"} & {signal["title"] for signal in triage.get("signals", [])}:
        sensitive_notes.append("运行时采集 API")
    if sensitive_notes:
        steps.append({"stage": "data-acquisition", "summary": f"敏感数据采集很可能依赖 {', '.join(sensitive_notes)}。", "evidence": (manifest_info.get("dangerous_permissions", []) + manifest_info.get("special_permissions", []))[:6]})

    if crypto["algorithms"] or crypto["modes"] or crypto["decryption_methods"]:
        crypto_summary = ", ".join(crypto["algorithms"] + crypto["modes"] + crypto["decryption_methods"]) or "加密线索"
        steps.append({"stage": "data-protection", "summary": f"静态字符串显示样本可能通过 {crypto_summary} 进行编码、加密或解密。", "evidence": crypto["evidence"][:4]})

    endpoint_values = callback_config["endpoints"]["urls"] or callback_config["endpoints"]["domains"] or callback_config["endpoints"]["ips"]
    if endpoint_values:
        steps.append({"stage": "callback", "summary": "采集或处理后的数据很可能会发送到远程回连基础设施。", "evidence": endpoint_values[:6]})

    if functions:
        steps.append({"stage": "behavioral-outcome", "summary": f"综合静态证据，首要业务功能判定为 {label_function_name(functions[0]['name'])}（{label_confidence(functions[0]['confidence'])}）。", "evidence": functions[0]["evidence"][:4]})
    return {"summary": "基于静态证据推测的启动、采集、处理与回连路径。", "steps": steps}


def build_evidence_chains(framework: dict, functions: list[dict], callback_config: dict, crypto: dict, sdk_key_profile: dict, flow: dict, native_summary: dict | None = None) -> list[dict]:
    chains = [
        {
            "conclusion": f"样本的主要技术栈为 {label_function_name(framework['primary_type'])}。",
            "logic_chain": [
                "先识别运行时与资源层面的框架特征。",
                "再将这些特征与常见混合框架签名进行匹配。",
                "最后采信证据最强、特异性最高的技术类型。",
            ],
            "evidence": framework["types"][0]["evidence"][:4],
        }
    ]
    if functions:
        chains.append(
            {
                "conclusion": f"样本的首要业务功能判定为 {label_function_name(functions[0]['name'])}。",
                "logic_chain": [
                    "结合权限、载荷特征与可疑 API 迹象建立能力画像。",
                    "再将其与业务关键词和常见恶意能力组合进行对照。",
                    "最后选出分值最高且证据最集中的业务功能类型。",
                ],
                "evidence": functions[0]["evidence"][:5],
            }
        )
    if any(callback_config["endpoints"].values()):
        chains.append(
            {
                "conclusion": "样本存在明确的回连或控制基础设施。",
                "logic_chain": [
                    "第一阶段先做原始字符串检索，提取 URL、域名、IP 与配置样式字符串。",
                    "第二阶段在一方反编译代码中追踪域名常量、Socket 配置与字符串拼接。",
                    "若代码推理阶段得到更强证据，则优先采信其输出作为最终回连结果。",
                ],
                "evidence": callback_config["endpoints"]["urls"][:4] + callback_config["endpoints"]["domains"][:4] + [item["value"] for item in callback_config["clues"][:3]],
            }
        )
    if crypto["algorithms"] or crypto["decryption_methods"]:
        chains.append(
            {
                "conclusion": "样本很可能在本地使用或回连发送前进行了静态编码或加密处理。",
                "logic_chain": [
                    "先在代码和资源中搜索加密算法、模式与编码原语。",
                    "再搜索 decrypt、decode 与 key-material 相关方法名。",
                    "最后尽量把这些线索与数据流或回连路径关联起来。",
                ],
                "evidence": crypto["evidence"][:5],
            }
        )
    if flow["steps"]:
        chains.append(
            {
                "conclusion": "可以从静态证据中重建一条从启动到回连的执行路径。",
                "logic_chain": [step["summary"] for step in flow["steps"]],
                "evidence": [item for step in flow["steps"] for item in step["evidence"][:2]][:8],
            }
        )
    if sdk_key_profile.get("keys"):
        chains.append(
            {
                "conclusion": "样本内存在可用于后续调证的第三方 SDK 标识或密钥配置。",
                "logic_chain": [
                    "在 manifest、资源配置或一方初始化代码中发现与第三方 SDK 厂商上下文匹配的 key 字段。",
                    "字段名和值同时满足厂商线索与 key 命名规则，不像普通包名、URL、资源名或占位符。",
                    "这些值可作为后续向 SDK 厂商或平台侧调证的账号标识线索。",
                ],
                "evidence": [f"{item['vendor']} {item['key_type']}: {item['value']} ({item['source']})" for item in sdk_key_profile["keys"][:6]],
            }
        )
    if native_summary and (native_summary.get("packers") or native_summary.get("anti_analysis") or native_summary.get("native_urls")):
        evidence = native_summary.get("so_files", [])[:2] + native_summary.get("packers", [])[:2] + native_summary.get("anti_analysis", [])[:2] + native_summary.get("native_urls", [])[:2]
        chains.append(
            {
                "conclusion": "Native 库提供了额外的打包、反分析或回连线索。",
                "logic_chain": [
                    "先定位 APK 中的 `.so` 库文件。",
                    "再从 native strings 中识别加固、反分析和潜在回连标记。",
                    "若命中 packer 或 anti-analysis 关键词，则把 native 层视作后续深挖优先分支。",
                ],
                "evidence": evidence,
            }
        )
    return chains
