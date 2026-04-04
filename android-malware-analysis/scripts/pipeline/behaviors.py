from __future__ import annotations

import re

FUNCTION_KEYWORDS = {
    "information-stealing": [r"\b(?:otp|sms|imei|imsi|deviceid|clipboard|contacts|accessibility|screen capture)\b", "\u9a8c\u8bc1\u7801", "\u901a\u8baf\u5f55"],
    "fraud-phishing": [r"\b(?:bank|wallet|kyc|login|password|verify|overlay)\b", "\u94f6\u884c", "\u5bc6\u7801", "\u9a8c\u8bc1"],
    "gambling": [r"\b(?:casino|bet|slot|lottery|poker|roulette)\b", "\u535a\u5f69", "\u8d4c", "\u5f69\u7968"],
    "adult-live": [r"\b(?:adult|sex|escort|live chat)\b", "\u76f4\u64ad", "\u88f8\u804a", "\u6210\u4eba"],
    "trojan-dropper": [r"\b(?:dropper|loader|payload|install package|dexclassloader)\b", "\u66f4\u65b0\u5305", "\u5b89\u88c5\u5305"],
}
CRYPTO_PATTERNS = {
    "AES": re.compile(r"\bAES(?:/[A-Za-z0-9-]+){0,2}\b"),
    "DES": re.compile(r"\bDES(?:ede)?(?:/[A-Za-z0-9-]+){0,2}\b"),
    "RSA": re.compile(r"\bRSA(?:/[A-Za-z0-9-]+){0,2}\b"),
    "EC": re.compile(r"\bEC(?:DSA)?\b"),
    "ChaCha20": re.compile(r"\bChaCha20\b", re.IGNORECASE),
    "Base64": re.compile(r"\bBase64\b", re.IGNORECASE),
    "XOR": re.compile(r"\bXOR\b", re.IGNORECASE),
    "CipherAPI": re.compile(r"\b(?:Cipher\.getInstance|SecretKeySpec|IvParameterSpec|KeyFactory)\b"),
}
CRYPTO_MODES = {
    "CBC": re.compile(r"\bCBC\b"),
    "ECB": re.compile(r"\bECB\b"),
    "GCM": re.compile(r"\bGCM\b"),
    "PKCS5Padding": re.compile(r"\bPKCS5Padding\b"),
    "PKCS7Padding": re.compile(r"\bPKCS7Padding\b"),
    "NoPadding": re.compile(r"\bNoPadding\b"),
}
DECRYPTION_PATTERNS = {
    "decrypt": re.compile(r"\b[a-zA-Z0-9_$]*decrypt[a-zA-Z0-9_$]*\b", re.IGNORECASE),
    "decode": re.compile(r"\b[a-zA-Z0-9_$]*decode[a-zA-Z0-9_$]*\b", re.IGNORECASE),
    "key-material": re.compile(r"\b(?:secret|apikey|api_key|token|iv|salt|publicKey|privateKey)\b", re.IGNORECASE),
}


def keyword_hits(string_records: list[tuple[str, str]]) -> dict:
    hits = {name: [] for name in FUNCTION_KEYWORDS}
    for source, text in string_records:
        for name, patterns in FUNCTION_KEYWORDS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    hits[name].append(f"{source}: {text[:140]}")
                    break
    return {name: values[:6] for name, values in hits.items() if values}


def classify_functions(triage: dict, manifest_info: dict, framework: dict, hits: dict, callback_config: dict) -> list[dict]:
    scores: dict[str, dict] = {}

    def bump(name: str, points: int, reason: str) -> None:
        bucket = scores.setdefault(name, {"score": 0, "evidence": []})
        bucket["score"] += points
        bucket["evidence"].append(reason)

    permissions = set(manifest_info.get("permissions", []))
    dangerous = set(manifest_info.get("dangerous_permissions", [])) | set(manifest_info.get("special_permissions", []))
    titles = {signal["title"] for signal in triage.get("signals", [])}
    urls_present = bool(callback_config["endpoints"]["urls"] or callback_config["endpoints"]["domains"])

    if dangerous & {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS", "android.permission.READ_PHONE_STATE", "android.permission.RECORD_AUDIO", "android.permission.CAMERA", "android.permission.MANAGE_EXTERNAL_STORAGE"}:
        bump("information-stealing", 2, "高危运行时权限覆盖短信、联系人、标识符、媒体或存储等敏感数据面。")
    if {"Accessibility automation", "SMS interception or fraud", "Screen capture capability"} & titles:
        bump("information-stealing", 2, "运行时迹象显示存在无障碍滥用、短信拦截或屏幕采集能力。")
    if urls_present:
        bump("information-stealing", 1, "敏感数据采集能力与回连基础设施同时存在。")

    if {"Accessibility plus overlay abuse", "Overlay or phishing UI", "OTP theft or banker-like capability cluster"} & titles:
        bump("fraud-phishing", 2, "悬浮窗与无障碍证据共同指向凭据或 OTP 欺诈场景。")
    if framework["primary_type"] in {"webview-hybrid", "uniapp"} and urls_present:
        bump("fraud-phishing", 1, "混合容器配合远程回连可支持钓鱼或诱导式业务流程。")

    if {"Loader with staged payload", "Embedded APK payload", "Suspicious bundled payload", "Dynamic code loading"} & titles:
        bump("trojan-dropper", 3, "内嵌载荷与动态加载同时存在，指向分阶段投递。")
    if "android.permission.REQUEST_INSTALL_PACKAGES" in permissions or "Installer or dropper behavior" in titles:
        bump("trojan-dropper", 2, "具备安装器能力，支持投递器或更新器行为。")

    for name, values in hits.items():
        if values:
            bump(name, 2, f"在代码或资源中命中对应业务关键词：{values[0]}")

    ordered = sorted(scores.items(), key=lambda item: (item[1]["score"], item[0]), reverse=True)
    results = []
    for name, payload in ordered:
        if payload["score"] < 2:
            continue
        confidence = "high" if payload["score"] >= 5 else "medium" if payload["score"] >= 3 else "low"
        results.append({"name": name, "score": payload["score"], "confidence": confidence, "evidence": payload["evidence"][:5]})
    return results


def detect_crypto(string_records: list[tuple[str, str]]) -> dict:
    result = {"algorithms": [], "modes": [], "decryption_methods": [], "evidence": []}
    for source, text in string_records:
        for name, pattern in CRYPTO_PATTERNS.items():
            if pattern.search(text) and name not in result["algorithms"]:
                result["algorithms"].append(name)
                result["evidence"].append(f"{source}: {text[:160]}")
        for name, pattern in CRYPTO_MODES.items():
            if pattern.search(text) and name not in result["modes"]:
                result["modes"].append(name)
                result["evidence"].append(f"{source}: {text[:160]}")
        for name, pattern in DECRYPTION_PATTERNS.items():
            if pattern.search(text) and name not in result["decryption_methods"]:
                result["decryption_methods"].append(name)
                result["evidence"].append(f"{source}: {text[:160]}")
    result["evidence"] = result["evidence"][:10]
    return result
