from __future__ import annotations

import re

FRAMEWORK_RULES = {
    "flutter": (
        ("asset", re.compile(r"(?:^|/)assets/flutter_assets/|(?:^|/)libflutter\.so$", re.IGNORECASE)),
        ("code", re.compile(r"\b(?:io\.flutter|FlutterActivity|FlutterEngine|MethodChannel|EventChannel)\b")),
    ),
    "uniapp": (
        ("asset", re.compile(r"(?:^|/)assets/apps/__UNI__|(?:^|/)assets/data/dcloud_", re.IGNORECASE)),
        ("code", re.compile(r"\b(?:io\.dcloud|uni-app|plus\.runtime|WeexFeature|DCloudApplication)\b", re.IGNORECASE)),
    ),
    "webview-hybrid": (
        ("asset", re.compile(r"(?:^|/)assets/www/|(?:^|/)index\.html$", re.IGNORECASE)),
        ("code", re.compile(r"\b(?:android\.webkit\.WebView|addJavascriptInterface|setJavaScriptEnabled|WebViewClient|loadUrl\(|evaluateJavascript)\b")),
    ),
    "react-native": (
        ("asset", re.compile(r"(?:^|/)index\.android\.bundle$", re.IGNORECASE)),
        ("code", re.compile(r"\b(?:com\.facebook\.react|ReactActivity|ReactNativeHost)\b")),
    ),
    "cordova": (
        ("asset", re.compile(r"(?:^|/)cordova(?:\.min)?\.js$|(?:^|/)assets/www/", re.IGNORECASE)),
        ("code", re.compile(r"\b(?:org\.apache\.cordova|CordovaActivity|CordovaWebView)\b")),
    ),
}


def classify_frameworks(entry_names: list[str], string_records: list[tuple[str, str]], manifest_info: dict) -> dict:
    findings = {}
    joined_components = " ".join(filter(None, [manifest_info.get("application_name"), manifest_info.get("launcher_activity")]))
    for framework, rule_set in FRAMEWORK_RULES.items():
        evidence = []
        for source, pattern in rule_set:
            if source == "asset":
                for name in entry_names:
                    if pattern.search(name):
                        evidence.append(f"{name}: 资源特征")
                        break
            else:
                for record_source, text in string_records:
                    if pattern.search(text) or pattern.search(joined_components):
                        evidence.append(f"{record_source}: {text[:140]}")
                        break
        if evidence:
            findings[framework] = {"score": len(evidence), "evidence": evidence}
    if not findings:
        findings["native-android"] = {"score": 1, "evidence": ["未发现明显的混合框架特征。"]}
    ordered = sorted(findings.items(), key=lambda item: (item[1]["score"], item[0]), reverse=True)
    return {
        "primary_type": ordered[0][0],
        "types": [{"name": name, "score": payload["score"], "evidence": payload["evidence"][:3]} for name, payload in ordered],
    }
