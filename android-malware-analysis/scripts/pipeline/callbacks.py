from __future__ import annotations

import json
import re
from urllib.parse import urlparse

import analyze_package

CONFIG_HINT_RE = re.compile(r"(?:\b(?:base[_-]?url|api[_-]?(?:host|url)|server|domain|host|socket|port|upload|download|gateway|endpoint)\b|ws://|wss://|mqtt://)", re.IGNORECASE)
IGNORED_URLS = {"http://schemas.android.com/apk/res/android", "http://schemas.android.com/apk/res-auto"}
IGNORED_DOMAIN_PREFIXES = ("schemas.android.", "android.", "androidx.", "com.android.", "com.google.", "io.dcloud.")
CALLBACK_SOURCE_HINT_RE = re.compile(
    r"(?:\b(?:base[_-]?url|api[_-]?(?:host|url)|server|domain|host|socket|port|upload|download|gateway|endpoint)\b|"
    r"\b[a-zA-Z0-9_$]*(?:dom|host|server|socket|endpoint|gateway|url|ws|mqtt|error)[a-zA-Z0-9_$]*\b|"
    r"ws://|wss://|mqtt://)",
    re.IGNORECASE,
)
URL_LIKE_RE = re.compile(r"(?:https?|wss?|mqtt)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)
STRING_ASSIGN_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*\"([^\"]*)\"")
CONCAT_EXPR_RE = re.compile(r"\"([^\"]*)\"\s*\+\s*([A-Za-z_$][\w$]*)\s*\+\s*\"([^\"]*)\"")
CODE_LIKE_SUFFIXES = (".java", ".js", ".json", ".kt", ".properties", ".smali", ".txt")
RESOURCE_ANALYSIS_PREFIXES = (
    "resources/res/values/",
    "resources/res/xml/",
)
MAX_NOISE_EXAMPLES = 12
FINAL_PUBLIC_SERVICE_HOSTS = {
    "apps.apple.com",
}
FINAL_PUBLIC_SERVICE_SUFFIXES = (
    ".aliyuncs.com",
    ".apple.com",
    ".dbankcloud.com",
    ".googleapis.com",
    ".gstatic.com",
    ".hicloud.com",
    ".huawei.com",
)
FINAL_PUBLIC_SERVICE_KEYWORDS = (
    "dbankcloud",
    "hicloud",
)
FINAL_URL_NOISE_RE = re.compile(
    r"(?:agreement|faq|guide|help|license|personal-info|policy|privacy|support|terms|third-party-info|info-sharing|collected)",
    re.IGNORECASE,
)
INSTALLER_ARTIFACT_RE = re.compile(r"\.(?:apk|dmg|exe|ipa|msi|pkg|zip)(?:$|[?#])", re.IGNORECASE)
TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
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
BRAND_TOKEN_STOPWORDS = {
    "activity",
    "android",
    "androidapp",
    "app",
    "application",
    "common",
    "core",
    "debug",
    "demo",
    "launcher",
    "main",
    "prod",
    "provider",
    "receiver",
    "release",
    "sdk",
    "service",
    "splash",
    "test",
}


def is_code_like_source(source: str) -> bool:
    lowered = source.lower()
    return lowered.endswith(CODE_LIKE_SUFFIXES) or "/sources/" in lowered or lowered.startswith("sources/")


def manifest_source_prefixes(manifest_info: dict) -> list[str]:
    component_names = []
    for key in ("launcher_activity", "application_name"):
        value = manifest_info.get(key)
        if value:
            component_names.append(value)
    for section in ("activities", "services", "receivers", "providers"):
        for item in manifest_info.get(section, []):
            value = item.get("name")
            if value:
                component_names.append(value)
    package_name = manifest_info.get("package_name")
    if package_name and "." in package_name:
        component_names.append(package_name)

    prefixes = []
    seen = set()
    for name in component_names:
        if "." not in name:
            continue
        package_path = name.rsplit(".", 1)[0].replace(".", "/")
        prefix = f"sources/{package_path}/"
        if prefix in seen:
            continue
        seen.add(prefix)
        prefixes.append(prefix)
    return prefixes


def preferred_analysis_records(string_records: list[tuple[str, str]], manifest_info: dict) -> list[tuple[str, str]]:
    prefixes = manifest_source_prefixes(manifest_info)
    selected = []
    for source, text in string_records:
        normalized = source.replace("\\", "/")
        if any(normalized.startswith(prefix) for prefix in prefixes):
            selected.append((source, text))
            continue
        if normalized.endswith("AndroidManifest.xml") or normalized.startswith(RESOURCE_ANALYSIS_PREFIXES):
            selected.append((source, text))
    return selected or string_records


def is_probable_callback_domain(domain: str) -> bool:
    lowered = domain.lower().rstrip(".")
    if lowered.startswith(IGNORED_DOMAIN_PREFIXES):
        return False
    if analyze_package.is_ignored_public_host(lowered):
        return False
    return analyze_package.is_probable_domain(lowered)


def looks_like_package_or_resource_domain(domain: str) -> bool:
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return False
    non_tld = labels[:-1]
    if not non_tld:
        return False
    if len(labels) >= 6:
        return True
    if len(labels) >= 5 and all(len(label) <= 3 for label in non_tld):
        return True
    if len(labels) >= 5 and sum(len(label) <= 2 for label in non_tld) >= len(non_tld) - 1:
        return True
    if any(label in RESOURCE_NOISE_LABELS for label in non_tld):
        return True
    return False


def has_callback_like_context(source: str, text: str) -> bool:
    normalized = source.replace("\\", "/").lower()
    if URL_LIKE_RE.search(text) or CALLBACK_SOURCE_HINT_RE.search(text):
        return True
    if normalized.endswith("AndroidManifest.xml".lower()):
        return True
    return normalized.startswith(RESOURCE_ANALYSIS_PREFIXES)


def add_noise_example(bucket: list[dict], example: dict, limit: int = MAX_NOISE_EXAMPLES) -> None:
    normalized = {key: value for key, value in example.items() if value not in (None, "", [], {})}
    example_key = tuple((key, json.dumps(normalized[key], ensure_ascii=False, sort_keys=True)) for key in sorted(normalized))
    for existing in bucket:
        existing_key = tuple((key, json.dumps(existing[key], ensure_ascii=False, sort_keys=True)) for key in sorted(existing))
        if existing_key == example_key:
            return
    if len(bucket) < limit:
        bucket.append(normalized)


def string_scan_domain_disposition(source: str, text: str, domain: str) -> tuple[bool, str | None]:
    if not is_probable_callback_domain(domain):
        return False, "not_probable_callback_domain"
    if looks_like_package_or_resource_domain(domain):
        return False, "package_or_resource_noise"
    if is_code_like_source(source) and not has_callback_like_context(source, text):
        return False, "low_context_code_domain"
    return True, None


def should_keep_string_scan_domain(source: str, text: str, domain: str) -> bool:
    keep, _ = string_scan_domain_disposition(source, text, domain)
    return keep


def add_endpoint_value(bucket: dict[str, set[str]], category: str, value: str) -> None:
    normalized = value.rstrip(").,;\"'").strip()
    if not normalized:
        return
    if category == "urls":
        if normalized in IGNORED_URLS or analyze_package.is_ignored_public_url(normalized):
            return
        host = urlparse(normalized).hostname
        if host and is_probable_callback_domain(host):
            bucket["urls"].add(normalized)
            bucket["domains"].add(host.lower())
        return
    if category == "domains" and is_probable_callback_domain(normalized):
        bucket["domains"].add(normalized.lower())


def extract_callback_candidates_from_sources(string_records: list[tuple[str, str]], manifest_info: dict) -> tuple[dict[str, list[str]], list[dict]]:
    code_records = [(source, text) for source, text in string_records if is_code_like_source(source)]

    preferred_records = code_records
    prefixes = manifest_source_prefixes(manifest_info)
    if prefixes:
        package_records = [
            (source, text)
            for source, text in code_records
            if any(source.replace("\\", "/").startswith(prefix) for prefix in prefixes)
        ]
        if package_records:
            preferred_records = package_records

    def scan(records: list[tuple[str, str]]) -> tuple[dict[str, list[str]], list[dict]]:
        endpoints: dict[str, set[str]] = {"urls": set(), "domains": set(), "ips": set(), "emails": set()}
        clues = []
        seen_clues = set()
        scoped_values: dict[str, dict[str, str]] = {}
        global_values: dict[str, str] = {}

        def add_clue(source: str, text: str) -> None:
            clue = {"source": source, "value": text[:220]}
            key = (clue["source"], clue["value"])
            if key in seen_clues:
                return
            seen_clues.add(key)
            clues.append(clue)

        for source, text in records:
            for url in URL_LIKE_RE.findall(text):
                before = len(endpoints["urls"])
                add_endpoint_value(endpoints, "urls", url)
                if len(endpoints["urls"]) != before:
                    add_clue(source, text)

            if not CALLBACK_SOURCE_HINT_RE.search(text):
                continue

            values = scoped_values.setdefault(source, {})
            for match in STRING_ASSIGN_RE.finditer(text):
                name, value = match.groups()
                value = value.strip()
                if not value:
                    continue
                if URL_LIKE_RE.fullmatch(value):
                    before = len(endpoints["urls"])
                    add_endpoint_value(endpoints, "urls", value)
                    if len(endpoints["urls"]) != before:
                        values[name] = value
                        global_values[name] = value
                        add_clue(source, text)
                    continue
                if is_probable_callback_domain(value):
                    before = len(endpoints["domains"])
                    add_endpoint_value(endpoints, "domains", value)
                    if len(endpoints["domains"]) != before:
                        values[name] = value
                        global_values[name] = value
                        add_clue(source, text)

            for domain in analyze_package.DOMAIN_RE.findall(text):
                before = len(endpoints["domains"])
                add_endpoint_value(endpoints, "domains", domain)
                if len(endpoints["domains"]) != before:
                    add_clue(source, text)

        for source, text in records:
            lookup = dict(global_values)
            lookup.update(scoped_values.get(source, {}))
            for match in CONCAT_EXPR_RE.finditer(text):
                prefix, name, suffix = match.groups()
                value = lookup.get(name)
                if not value:
                    continue
                candidate = f"{prefix}{value}{suffix}"
                before = len(endpoints["urls"])
                add_endpoint_value(endpoints, "urls", candidate)
                if len(endpoints["urls"]) != before:
                    add_clue(source, text)

        return {
            "urls": sorted(endpoints["urls"]),
            "domains": sorted(endpoints["domains"]),
            "ips": [],
            "emails": [],
        }, clues[:20]

    source_endpoints, source_clues = scan(preferred_records)
    if any(source_endpoints.values()) or preferred_records is code_records:
        return source_endpoints, source_clues
    return scan(code_records)


def sanitize_endpoints(endpoints: dict) -> dict:
    clean_urls = []
    clean_domains = set()
    for url in endpoints.get("urls", []):
        if url in IGNORED_URLS or analyze_package.is_ignored_public_url(url):
            continue
        host = urlparse(url).hostname
        if not host or not is_probable_callback_domain(host):
            continue
        clean_urls.append(url)
        clean_domains.add(host.lower())

    for domain in endpoints.get("domains", []):
        if is_probable_callback_domain(domain):
            clean_domains.add(domain.lower())

    return {
        "urls": sorted(dict.fromkeys(clean_urls)),
        "domains": sorted(clean_domains),
        "ips": endpoints.get("ips", []),
        "emails": endpoints.get("emails", []),
    }


def manifest_brand_tokens(manifest_info: dict) -> list[str]:
    values = []
    for key in ("package_name", "launcher_activity", "application_name"):
        value = manifest_info.get(key)
        if value:
            values.append(value)
    for section in ("activities", "services", "receivers", "providers"):
        for item in manifest_info.get(section, []):
            value = item.get("name")
            if value:
                values.append(value)

    tokens = set()
    for value in values:
        normalized = value.replace("\\", ".").replace("/", ".").replace("$", ".").lower()
        for token in TOKEN_SPLIT_RE.split(normalized):
            if len(token) < 4:
                continue
            if token in BRAND_TOKEN_STOPWORDS:
                continue
            if token.startswith(("android", "activity", "service", "receiver", "provider")):
                continue
            tokens.add(token)
    return sorted(tokens)


def is_public_service_host(host: str) -> bool:
    lowered = host.lower().rstrip(".")
    if analyze_package.is_ignored_public_host(lowered):
        return True
    if lowered in FINAL_PUBLIC_SERVICE_HOSTS:
        return True
    if any(keyword in lowered for keyword in FINAL_PUBLIC_SERVICE_KEYWORDS):
        return True
    return any(lowered.endswith(suffix) for suffix in FINAL_PUBLIC_SERVICE_SUFFIXES)


def host_matches_brand(host: str, brand_tokens: list[str]) -> bool:
    if not brand_tokens:
        return False
    lowered = host.lower().rstrip(".")
    labels = lowered.split(".")[:-1] or lowered.split(".")
    for label in labels:
        for token in brand_tokens:
            if token in label or label in token:
                return True
    return False


def final_url_suppression_reason(url: str, brand_tokens: list[str]) -> str | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return "invalid_url"

    host = (parsed.hostname or "").lower()
    if not host:
        return "invalid_url"
    if is_public_service_host(host):
        return "public_service_host"

    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    if FINAL_URL_NOISE_RE.search(path_and_query):
        return "policy_or_help_url"
    if FINAL_URL_NOISE_RE.search(url) and host_matches_brand(host, brand_tokens):
        return "policy_or_help_url"
    if INSTALLER_ARTIFACT_RE.search(path_and_query):
        labels = host.split(".")[:-1] or host.split(".")
        if not host_matches_brand(host, brand_tokens) or any("oss" in label or "cdn" in label or "download" in label for label in labels):
            return "download_artifact_url"
    return None


def final_domain_suppression_reason(domain: str, brand_tokens: list[str]) -> str | None:
    lowered = domain.lower().rstrip(".")
    if not lowered:
        return "invalid_domain"
    if is_public_service_host(lowered):
        return "public_service_host"
    labels = lowered.split(".")[:-1] or lowered.split(".")
    if not host_matches_brand(lowered, brand_tokens) and any("oss" in label or "cdn" in label or "download" in label for label in labels):
        return "storage_or_download_host"
    return None


def refine_callback_verdict(manifest_info: dict, selected: dict) -> dict:
    endpoints = sanitize_endpoints(selected.get("endpoints", {}))
    brand_tokens = manifest_brand_tokens(manifest_info)
    kept_urls: list[str] = []
    kept_domains: set[str] = set()
    suppressed_examples: list[dict] = []
    suppressed_count = 0

    for url in endpoints.get("urls", []):
        reason = final_url_suppression_reason(url, brand_tokens)
        if reason:
            suppressed_count += 1
            add_noise_example(suppressed_examples, {"candidate": url, "reason": reason, "stage": "final_verdict"})
            continue
        kept_urls.append(url)
        host = urlparse(url).hostname
        if host:
            kept_domains.add(host.lower())

    for domain in endpoints.get("domains", []):
        reason = final_domain_suppression_reason(domain, brand_tokens)
        if reason:
            suppressed_count += 1
            add_noise_example(suppressed_examples, {"candidate": domain, "reason": reason, "stage": "final_verdict"})
            continue
        kept_domains.add(domain.lower())

    keep_markers = [item.lower() for item in kept_urls] + sorted(kept_domains)
    suppressed_markers = [item["candidate"].lower() for item in suppressed_examples if item.get("candidate")]
    refined_clues = []
    for clue in selected.get("clues", [])[:20]:
        value = str(clue.get("value") or "").lower()
        if keep_markers and any(marker in value for marker in keep_markers):
            refined_clues.append(clue)
            continue
        if suppressed_markers and any(marker in value for marker in suppressed_markers):
            continue
        if not keep_markers:
            refined_clues.append(clue)

    return {
        "endpoints": {
            "urls": sorted(dict.fromkeys(kept_urls)),
            "domains": sorted(kept_domains),
            "ips": endpoints.get("ips", []),
            "emails": endpoints.get("emails", []),
        },
        "clues": refined_clues[:20],
        "suppressed_count": suppressed_count,
        "suppressed_examples": suppressed_examples,
        "brand_tokens": brand_tokens[:8],
    }


def collect_string_scan_phase(string_records: list[tuple[str, str]], manifest_info: dict) -> dict:
    prefixes = manifest_source_prefixes(manifest_info)

    def is_first_party_source(source: str) -> bool:
        normalized = source.replace("\\", "/")
        return any(normalized.startswith(prefix) for prefix in prefixes) or normalized.endswith("AndroidManifest.xml") or normalized.startswith(RESOURCE_ANALYSIS_PREFIXES)

    def new_bucket() -> dict:
        return {
            "endpoints": {"urls": set(), "domains": set(), "ips": set(), "emails": set()},
            "clues": [],
            "seen": set(),
            "suppressed_domain_count": 0,
            "suppressed_examples": [],
        }

    def add_clue(bucket: dict, source: str, text: str) -> None:
        clue = {"source": source, "value": text[:220]}
        key = (clue["source"], clue["value"])
        if key in bucket["seen"]:
            return
        bucket["seen"].add(key)
        bucket["clues"].append(clue)

    first_party = new_bucket()
    third_party = new_bucket()

    for source, text in string_records:
        bucket = first_party if is_first_party_source(source) else third_party
        changed = False
        for url in analyze_package.URL_RE.findall(text):
            before = len(bucket["endpoints"]["urls"])
            add_endpoint_value(bucket["endpoints"], "urls", url)
            changed = changed or len(bucket["endpoints"]["urls"]) != before
        for domain in analyze_package.DOMAIN_RE.findall(text):
            keep_domain, suppress_reason = string_scan_domain_disposition(source, text, domain)
            if not keep_domain:
                bucket["suppressed_domain_count"] += 1
                add_noise_example(
                    bucket["suppressed_examples"],
                    {
                        "source": source,
                        "candidate": domain,
                        "reason": suppress_reason,
                    },
                )
                continue
            before = len(bucket["endpoints"]["domains"])
            add_endpoint_value(bucket["endpoints"], "domains", domain)
            changed = changed or len(bucket["endpoints"]["domains"]) != before
        if changed or has_callback_like_context(source, text):
            add_clue(bucket, source, text)

    first_party_candidates = {
        "endpoints": sanitize_endpoints({key: sorted(value) for key, value in first_party["endpoints"].items()}),
        "clues": first_party["clues"][:20],
        "suppressed_domain_count": first_party["suppressed_domain_count"],
        "suppressed_examples": first_party["suppressed_examples"],
    }
    third_party_candidates = {
        "endpoints": sanitize_endpoints({key: sorted(value) for key, value in third_party["endpoints"].items()}),
        "clues": third_party["clues"][:20],
        "suppressed_domain_count": third_party["suppressed_domain_count"],
        "suppressed_examples": third_party["suppressed_examples"],
    }
    selected = first_party_candidates if any(first_party_candidates["endpoints"].values()) else third_party_candidates
    third_party_summary = {
        "url_count": len(third_party_candidates["endpoints"]["urls"]),
        "domain_count": len(third_party_candidates["endpoints"]["domains"]),
        "sample_urls": third_party_candidates["endpoints"]["urls"][:6],
        "sample_domains": third_party_candidates["endpoints"]["domains"][:6],
        "suppressed_domain_count": third_party_candidates["suppressed_domain_count"],
        "suppressed_examples": third_party_candidates["suppressed_examples"],
    }
    return {
        "notes": "第一阶段保留字符串级候选；其中一方候选优先展示，第三方库候选仅作摘要，并抑制明显包名、资源名和低上下文伪域名。",
        "first_party_candidates": first_party_candidates,
        "third_party_summary": third_party_summary,
        "endpoints": selected["endpoints"],
        "clues": selected["clues"],
    }


def collect_callback_config(triage: dict, string_records: list[tuple[str, str]], manifest_info: dict) -> dict:
    source_endpoints, source_clues = extract_callback_candidates_from_sources(string_records, manifest_info)
    string_scan = collect_string_scan_phase(string_records, manifest_info)

    code_inference = {
        "endpoints": sanitize_endpoints(source_endpoints),
        "clues": source_clues[:20],
    }
    selected_stage = "code_inference" if any(code_inference["endpoints"].values()) else "string_scan"
    selected = code_inference if selected_stage == "code_inference" else string_scan
    refined = refine_callback_verdict(manifest_info, selected)
    selection_reason = (
        "优先采用反编译代码推理结果，因为发现了一方源码中的域名常量与拼接 URL。"
        if selected_stage == "code_inference"
        else "未发现可靠的一方源码回连构造，暂以原始字符串检索结果作为候选。"
    )
    if selected_stage == "code_inference" and not any(refined["endpoints"].values()) and any(string_scan["endpoints"].values()):
        fallback = refine_callback_verdict(manifest_info, string_scan)
        if any(fallback["endpoints"].values()):
            refined = fallback
            selected = string_scan
            selected_stage = "string_scan_fallback"
            selection_reason = "反编译代码推理阶段主要命中公共服务域名或说明页面，最终回退到字符串阶段中仍保留的一方候选。"
    if refined["suppressed_count"]:
        selection_reason += f" 最终结论额外压制了 `{refined['suppressed_count']}` 条公共服务/说明页噪声候选。"
    return {
        "string_scan": string_scan,
        "code_inference": code_inference,
        "selection_reason": selection_reason,
        "verdict_refinement": {
            "selected_stage": selected_stage,
            "suppressed_count": refined["suppressed_count"],
            "suppressed_examples": refined["suppressed_examples"],
            "brand_tokens": refined["brand_tokens"],
        },
        "endpoints": refined["endpoints"],
        "clues": refined["clues"],
    }
