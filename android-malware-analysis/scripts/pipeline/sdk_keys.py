from __future__ import annotations

import re
from html import unescape as html_unescape

import analyze_package
from pipeline.callbacks import RESOURCE_ANALYSIS_PREFIXES, URL_LIKE_RE, add_noise_example, is_code_like_source, manifest_source_prefixes

RESOURCE_STRING_VALUE_RE = re.compile(r"<(?:string|item)\b[^>]*name=\"(?P<name>[^\"]+)\"[^>]*>(?P<value>[^<]+)</(?:string|item)>", re.IGNORECASE)
XML_METADATA_VALUE_RE = re.compile(
    r"android:name\s*=\s*\"(?P<name>[^\"]+)\"[^>]*android:value\s*=\s*\"(?P<value>[^\"]+)\"|"
    r"android:value\s*=\s*\"(?P<value2>[^\"]+)\"[^>]*android:name\s*=\s*\"(?P<name2>[^\"]+)\"",
    re.IGNORECASE,
)
QUOTED_KEY_VALUE_RE = re.compile(
    r"(?P<name>[A-Za-z0-9_.-]{2,100})\s*(?:=|:)\s*(?P<quote>\"|')(?P<value>[^\"'\r\n]{1,200})(?P=quote)",
    re.IGNORECASE,
)
PLAIN_KEY_VALUE_RE = re.compile(r"(?P<name>[A-Za-z0-9_.-]{2,100})\s*=\s*(?P<value>[A-Za-z0-9_./:+=-]{6,200})")
RESOURCE_REFERENCE_RE = re.compile(r"^@string/(?P<name>[A-Za-z0-9_./-]+)$")
SDK_PLACEHOLDER_RE = re.compile(
    r"^(?:null|nil|none|true|false|debug|release|test|prod|staging|default|unknown|channel|placeholder|sample|demo|"
    r"appid|appkey|apikey|secret|token|key|license|replace[_-]?me|your[_-]?(?:app|api|sdk|access)[_-]?(?:id|key|secret))$",
    re.IGNORECASE,
)
SDK_FIELD_LABEL_HINTS = (
    ("AccessKeySecret", ("accesskeysecret", "secretaccesskey", "aksecret"), False),
    ("AccessKeyId", ("accesskeyid", "akid"), False),
    ("MasterSecret", ("mastersecret",), False),
    ("Client Secret", ("clientsecret",), False),
    ("Client ID", ("clientid",), False),
    ("API Key", ("apikey", "mapapikey", "lbsapikey"), False),
    ("App Secret", ("appsecret", "sdksecret"), True),
    ("AppKey", ("appkey", "sdkappkey"), True),
    ("AppId", ("appid", "googleappid", "wxappid", "qqappid", "buglyappid"), True),
    ("Security Token", ("securitytoken", "sts", "token"), True),
    ("AK", ("ak",), True),
    ("SK", ("sk",), True),
    ("SN", ("sn",), True),
    ("License", ("licensekey", "license"), True),
)
RESOURCE_NOISE_LABELS = {
    "anim",
    "animator",
    "array",
    "attr",
    "bool",
    "color",
    "dimen",
    "drawable",
    "font",
    "id",
    "integer",
    "interpolator",
    "layout",
    "menu",
    "mipmap",
    "navigation",
    "plurals",
    "raw",
    "r",
    "string",
    "style",
    "xml",
}
THIRD_PARTY_SDK_RULES = (
    {
        "vendor": "阿里/阿里云",
        "sdk_family": "Alibaba / Aliyun",
        "context_re": re.compile(r"(?:alibaba|aliyun|alipay|oss|httpdns|mpaas|utdid|amdc|taobao)", re.IGNORECASE),
        "field_hints": ("alibaba", "aliyun", "alipay", "oss", "httpdns", "mpaas", "utdid", "amdc"),
    },
    {
        "vendor": "百度",
        "sdk_family": "Baidu",
        "context_re": re.compile(r"(?:baidu|lbsapi|mapapi|bce)", re.IGNORECASE),
        "field_hints": ("baidu", "lbsapi", "mapapi", "bce"),
    },
    {
        "vendor": "高德",
        "sdk_family": "AMap / AutoNavi",
        "context_re": re.compile(r"(?:amap|autonavi|gaode)", re.IGNORECASE),
        "field_hints": ("amap", "autonavi", "gaode"),
    },
    {
        "vendor": "腾讯",
        "sdk_family": "Tencent",
        "context_re": re.compile(r"(?:tencent|bugly|qcloud|wechat|weixin|qqconnect|msdk|mapsdk)", re.IGNORECASE),
        "field_hints": ("tencent", "bugly", "qcloud", "wechat", "weixin", "qq", "msdk", "mapsdk"),
    },
    {
        "vendor": "华为",
        "sdk_family": "Huawei / AGConnect",
        "context_re": re.compile(r"(?:huawei|agconnect|appgallery|hms)", re.IGNORECASE),
        "field_hints": ("huawei", "agconnect", "appgallery", "hms"),
    },
    {
        "vendor": "友盟",
        "sdk_family": "Umeng",
        "context_re": re.compile(r"(?:umeng|mobclick|uapp)", re.IGNORECASE),
        "field_hints": ("umeng", "mobclick", "uapp"),
    },
    {
        "vendor": "极光",
        "sdk_family": "JPush / Jiguang",
        "context_re": re.compile(r"(?:jpush|jiguang|cn\.jpush)", re.IGNORECASE),
        "field_hints": ("jpush", "jiguang"),
    },
    {
        "vendor": "个推",
        "sdk_family": "Getui / Igexin",
        "context_re": re.compile(r"(?:getui|igexin)", re.IGNORECASE),
        "field_hints": ("getui", "igexin"),
    },
    {
        "vendor": "谷歌",
        "sdk_family": "Google / Firebase",
        "context_re": re.compile(r"(?:firebase|google[_-]?services|gcm_defaultsenderid|google_api_key|google_app_id)", re.IGNORECASE),
        "field_hints": ("firebase", "google", "gcm"),
    },
)


def normalize_key_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def collect_resource_string_values(string_records: list[tuple[str, str]]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for source, text in string_records:
        normalized = source.replace("\\", "/")
        if not normalized.startswith("resources/res/values/"):
            continue
        for match in RESOURCE_STRING_VALUE_RE.finditer(text):
            name = match.group("name")
            value = html_unescape(match.group("value")).strip()
            value = re.sub(r"<[^>]+>", "", value).strip()
            if value:
                mapping.setdefault(name, value)
    return mapping


def resolve_sdk_value(raw_value: str, resource_strings: dict[str, str]) -> tuple[str | None, str | None]:
    value = raw_value.strip()
    match = RESOURCE_REFERENCE_RE.match(value)
    if not match:
        return value, None
    resolved = resource_strings.get(match.group("name"))
    if not resolved:
        return None, value
    return resolved, value


def sdk_key_source_rank(source: str, first_party_prefixes: list[str]) -> int:
    normalized = source.replace("\\", "/")
    if normalized.endswith("AndroidManifest.xml"):
        return 4
    if normalized.startswith(RESOURCE_ANALYSIS_PREFIXES):
        return 4
    if any(normalized.startswith(prefix) for prefix in first_party_prefixes):
        return 4
    if normalized.startswith("assets/") or normalized.endswith((".json", ".properties", ".xml")):
        return 3
    if is_code_like_source(source):
        return 1
    return 0


def is_meaningful_sdk_value(value: str) -> bool:
    cleaned = value.strip().strip(",;")
    if len(cleaned) < 4 or len(cleaned) > 200:
        return False
    if cleaned.startswith("@") or cleaned.startswith("${"):
        return False
    if SDK_PLACEHOLDER_RE.match(cleaned):
        return False
    if URL_LIKE_RE.match(cleaned):
        return False
    if analyze_package.is_probable_domain(cleaned.lower()):
        return False
    if re.fullmatch(r"[A-Za-z_][\w./-]{0,120}", cleaned) and not re.search(r"\d", cleaned) and "." in cleaned:
        return False
    if cleaned.lower().startswith(("android.permission.", "android.", "androidx.", "com.", "org.", "io.", "kotlin.")):
        return False
    return True


def infer_sdk_key_type(field_name: str, vendor_context: bool) -> str | None:
    normalized = normalize_key_name(field_name)
    for label, hints, requires_vendor in SDK_FIELD_LABEL_HINTS:
        if any(hint in normalized for hint in hints):
            if requires_vendor and not vendor_context:
                continue
            return label
    return None


def iter_sdk_key_assignments(text: str) -> list[tuple[str, str]]:
    pairs = []
    seen = set()
    for match in XML_METADATA_VALUE_RE.finditer(text):
        name = match.group("name") or match.group("name2")
        value = match.group("value") or match.group("value2")
        if name and value and (name, value) not in seen:
            seen.add((name, value))
            pairs.append((name, value))
    for pattern in (QUOTED_KEY_VALUE_RE, PLAIN_KEY_VALUE_RE):
        for match in pattern.finditer(text):
            name = match.group("name")
            value = match.group("value")
            if name and value and (name, value) not in seen:
                seen.add((name, value))
                pairs.append((name, value))
    return pairs


def extract_third_party_sdk_keys(string_records: list[tuple[str, str]], manifest_info: dict) -> dict:
    first_party_prefixes = manifest_source_prefixes(manifest_info)
    resource_strings = collect_resource_string_values(string_records)
    results = []
    seen = set()
    suppressed = {"low_context": 0, "placeholder": 0, "unresolved_ref": 0}
    suppressed_examples: list[dict[str, str]] = []

    for source, text in string_records:
        source_rank = sdk_key_source_rank(source, first_party_prefixes)
        if source_rank < 3:
            continue
        lowered_source = source.lower()
        lowered_text = text.lower()
        for field_name, raw_value in iter_sdk_key_assignments(text):
            normalized_field = normalize_key_name(field_name)
            vendor_matches = []
            for rule in THIRD_PARTY_SDK_RULES:
                vendor_context = bool(rule["context_re"].search(lowered_source) or rule["context_re"].search(lowered_text) or any(hint in normalized_field for hint in rule["field_hints"]))
                key_type = infer_sdk_key_type(field_name, vendor_context=vendor_context)
                if vendor_context and key_type:
                    vendor_matches.append((rule, key_type))

            if not vendor_matches:
                suppressed["low_context"] += 1
                add_noise_example(
                    suppressed_examples,
                    {
                        "source": source,
                        "field_name": field_name,
                        "raw_value": raw_value,
                        "reason": "low_context",
                    },
                )
                continue

            resolved_value, resolved_from = resolve_sdk_value(raw_value, resource_strings)
            if not resolved_value:
                suppressed["unresolved_ref"] += 1
                add_noise_example(
                    suppressed_examples,
                    {
                        "source": source,
                        "field_name": field_name,
                        "raw_value": raw_value,
                        "reason": "unresolved_ref",
                    },
                )
                continue
            if not is_meaningful_sdk_value(resolved_value):
                suppressed["placeholder"] += 1
                noise_example = {
                    "source": source,
                    "field_name": field_name,
                    "raw_value": raw_value,
                    "reason": "placeholder",
                }
                if resolved_from:
                    noise_example["resolved_from"] = resolved_from
                if resolved_value != raw_value:
                    noise_example["resolved_value"] = resolved_value
                add_noise_example(suppressed_examples, noise_example)
                continue

            for rule, key_type in vendor_matches:
                confidence = "high" if source_rank >= 4 and any(hint in normalized_field for hint in rule["field_hints"]) else "medium"
                record = {
                    "vendor": rule["vendor"],
                    "sdk_family": rule["sdk_family"],
                    "key_type": key_type,
                    "value": resolved_value,
                    "source": source,
                    "confidence": confidence,
                    "evidence": text[:180],
                }
                if resolved_from:
                    record["resolved_from"] = resolved_from
                dedupe_key = (record["vendor"], record["sdk_family"], record["key_type"], record["value"])
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                results.append(record)

    results.sort(key=lambda item: (0 if item["confidence"] == "high" else 1, item["vendor"], item["sdk_family"], item["key_type"], item["value"]))
    summary: dict[str, dict] = {}
    for item in results:
        bucket = summary.setdefault(item["vendor"], {"sdk_families": set(), "key_types": set(), "count": 0})
        bucket["sdk_families"].add(item["sdk_family"])
        bucket["key_types"].add(item["key_type"])
        bucket["count"] += 1

    return {
        "notes": "仅提取样本内可直接观察到的第三方 SDK 明文或近明文 key 配置，用于后续向厂商调证；不代表对应 SDK 已实际联网或完成注册。",
        "keys": results[:20],
        "vendors": [
            {
                "vendor": vendor,
                "sdk_families": sorted(payload["sdk_families"]),
                "key_types": sorted(payload["key_types"]),
                "count": payload["count"],
            }
            for vendor, payload in sorted(summary.items())
        ],
        "suppressed_candidates": sum(suppressed.values()),
        "suppressed_breakdown": suppressed,
        "suppressed_examples": suppressed_examples,
    }
