from __future__ import annotations

import zipfile
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from android_tooling import summarize_tooling
from pipeline.flow import label_confidence, label_function_name, label_stage
from pipeline.manifest import PackageView


def markdown_lines(report: dict) -> list[str]:
    sample = report["sample"]
    manifest = report["base_info"]
    environment = report["environment"]
    callback = report["callback_config"]
    string_scan = callback.get("string_scan", {"endpoints": {"urls": [], "domains": [], "ips": [], "emails": []}, "clues": []})
    code_inference = callback.get("code_inference", {"endpoints": {"urls": [], "domains": [], "ips": [], "emails": []}, "clues": []})
    string_scan_first_party = string_scan.get("first_party_candidates", {"endpoints": {"urls": [], "domains": [], "ips": [], "emails": []}, "clues": []})
    string_scan_third_party = string_scan.get("third_party_summary", {"url_count": 0, "domain_count": 0, "sample_urls": [], "sample_domains": []})
    sdk_keys = report.get("sdk_key_profile", {"notes": "", "keys": [], "vendors": [], "suppressed_candidates": 0, "suppressed_breakdown": {}})

    def fmt(values: list[str]) -> str:
        return ", ".join(f"`{item}`" for item in values) or "无"

    def fmt_limited(values: list[str], limit: int = 8) -> str:
        if not values:
            return "无"
        shown = values[:limit]
        rendered = ", ".join(f"`{item}`" for item in shown)
        if len(values) > limit:
            rendered += f" 等 `{len(values)}` 条"
        return rendered

    recommendation = (
        "环境已满足完整 APK 分析条件。"
        if environment["full_ready"]
        else "完整 APK 分析工具不完整；如不安装缺失工具，则以 best-effort 模式继续。"
    )
    lines = [
        "# Android 恶意应用静态分析报告",
        "",
        "## 1. 样本与基本信息",
        f"- 样本路径: `{sample['target']}`",
        f"- 包来源: `{sample['package_source']}`",
        f"- 包类型: `{sample['package_type']}`",
        f"- 分析模式: `{sample['analysis_mode']}`",
        f"- 风险等级: `{sample['risk_level']}` ({sample['risk_score']})",
        f"- 包名: `{manifest.get('package_name') or '未知'}`",
        f"- 主入口函数: `{manifest.get('main_entry_function') or '未知'}`",
        f"- Launcher Activity: `{manifest.get('launcher_activity') or '未知'}`",
        f"- Application 类: `{manifest.get('application_name') or '未知'}`",
        f"- 应用名称: `{manifest.get('app_label') or '未知'}`",
        f"- 图标引用: `{manifest.get('icon_ref') or '未知'}`",
    ]
    if report["icon_candidates"]:
        lines.append(f"- 图标候选: {', '.join(f'`{item['exported_to']}`' for item in report['icon_candidates'])}")
    lines.extend(
        [
            f"- 危险权限: {fmt(manifest.get('dangerous_permissions', []))}",
            f"- 特殊权限: {fmt(manifest.get('special_permissions', []))}",
            "",
            "## 2. 环境检查",
        ]
    )
    lines.extend(summarize_tooling(environment))
    lines.extend(
        [
            f"- 建议: {recommendation}",
            "",
            "## 3. 技术类型与业务功能分类",
            f"- 首要技术类型: `{label_function_name(report['technical_profile']['primary_type'])}`",
        ]
    )
    for item in report["technical_profile"]["types"]:
        lines.append(f"- 技术证据 `{label_function_name(item['name'])}`: {'; '.join(item['evidence'])}")
    if report["functional_profile"]:
        for item in report["functional_profile"]:
            lines.append(f"- 业务功能 `{label_function_name(item['name'])}`（{label_confidence(item['confidence'])}）: {'; '.join(item['evidence'])}")
    else:
        lines.append("- 业务功能: 没有类别超过恶意置信度阈值。")

    lines.extend(["", "## 4. 回连基础设施与加密线索", "### 第一阶段：原始字符串检索"])
    lines.append(f"- 说明: {string_scan.get('notes', '原始字符串检索结果仅作候选展示。')}")
    lines.append(f"- 一方候选 URLs: {fmt_limited(string_scan_first_party['endpoints']['urls'])}")
    lines.append(f"- 一方候选域名: {fmt_limited(string_scan_first_party['endpoints']['domains'])}")
    lines.append(f"- 一方候选 IPs: {fmt_limited(string_scan_first_party['endpoints']['ips'])}")
    if string_scan_first_party.get("suppressed_domain_count"):
        lines.append(f"- 一方伪域名抑制: 已压制 `{string_scan_first_party['suppressed_domain_count']}` 条明显包名/资源名/低上下文候选。")
    for item in string_scan_first_party["clues"][:4]:
        lines.append(f"- 一方字符串线索: `{item['source']}` -> `{item['value']}`")
    lines.append(f"- 三方/库候选摘要: URLs `{string_scan_third_party['url_count']}` 条，域名 `{string_scan_third_party['domain_count']}` 条")
    if string_scan_third_party.get("suppressed_domain_count"):
        lines.append(f"- 三方噪声抑制: 已压制 `{string_scan_third_party['suppressed_domain_count']}` 条明显无关候选。")
    if string_scan_third_party["sample_urls"]:
        lines.append(f"- 三方 URL 示例: {fmt(string_scan_third_party['sample_urls'])}")
    if string_scan_third_party["sample_domains"]:
        lines.append(f"- 三方域名示例: {fmt(string_scan_third_party['sample_domains'])}")

    lines.extend(["", "### 第二阶段：反编译代码推理"])
    lines.append(f"- URLs: {fmt(code_inference['endpoints']['urls'])}")
    lines.append(f"- 域名: {fmt(code_inference['endpoints']['domains'])}")
    lines.append(f"- IPs: {fmt(code_inference['endpoints']['ips'])}")
    for item in code_inference["clues"][:6]:
        lines.append(f"- 代码线索: `{item['source']}` -> `{item['value']}`")

    lines.extend(["", "### 最终采信结果"])
    lines.append(f"- 采信说明: {callback.get('selection_reason', '未提供')}")
    verdict_refinement = callback.get("verdict_refinement", {})
    if verdict_refinement.get("suppressed_count"):
        lines.append(f"- 终判噪声抑制: 已压制 `{verdict_refinement['suppressed_count']}` 条公共服务/说明页候选，详见缓存噪声日志。")
    lines.append(f"- URLs: {fmt(callback['endpoints']['urls'])}")
    lines.append(f"- 域名: {fmt(callback['endpoints']['domains'])}")
    lines.append(f"- IPs: {fmt(callback['endpoints']['ips'])}")
    for item in callback["clues"][:6]:
        lines.append(f"- 最终线索: `{item['source']}` -> `{item['value']}`")
    crypto = report["crypto_profile"]
    lines.append(f"- 加密算法: {fmt(crypto['algorithms'])}")
    lines.append(f"- 加密模式: {fmt(crypto['modes'])}")
    lines.append(f"- 解密/解码线索: {fmt(crypto['decryption_methods'])}")
    lines.extend(["", "### 第三方 SDK 调证 Key"])
    lines.append(f"- 说明: {sdk_keys.get('notes', '无')}")
    if sdk_keys.get("vendors"):
        lines.append(f"- 厂商概览: {', '.join(f'`{item['vendor']}` {item['count']} 项' for item in sdk_keys['vendors'])}")
    if sdk_keys.get("suppressed_candidates"):
        lines.append(f"- 噪声抑制: 已压制 `{sdk_keys['suppressed_candidates']}` 条低上下文、占位符或未解析资源引用候选。")
    if sdk_keys.get("keys"):
        for item in sdk_keys["keys"]:
            source_note = item["source"]
            if item.get("resolved_from"):
                source_note += f"（由 `{item['resolved_from']}` 解析）"
            lines.append(
                f"- `{item['vendor']}` / `{item['sdk_family']}` / `{item['key_type']}`（{label_confidence(item['confidence'])}）: `{item['value']}`，来源 `{source_note}`"
            )
    else:
        lines.append("- 未提取到可直接用于调证的第三方 SDK key 明文配置。")

    lines.extend(["", "## 5. 控制流与执行路径"])
    lines.append(f"- 概要: {report['execution_flow']['summary']}")
    for index, step in enumerate(report["execution_flow"]["steps"], start=1):
        lines.append(f"- 步骤 {index} [{label_stage(step['stage'])}]: {step['summary']}")
        lines.append(f"  证据: {fmt(step['evidence'])}")

    lines.extend(["", "## 6. 证据链"])
    for chain in report["evidence_chains"]:
        lines.append(f"### {chain['conclusion']}")
        lines.append("逻辑链:")
        for idx, item in enumerate(chain["logic_chain"], start=1):
            lines.append(f"{idx}. {item}")
        lines.append("证据:")
        for item in chain["evidence"]:
            lines.append(f"- `{item}`")

    lines.extend(
        [
            "",
            "## 7. 产物",
            f"- 回连配置导出: `{report['artifacts']['callback_config_json']}`",
            f"- 调试噪声日志: `{report['artifacts']['noise_log_json']}`",
            f"- Markdown 报告: `{report['artifacts']['markdown_report']}`",
            f"- DOCX 报告: `{report['artifacts']['docx_report']}`",
        ]
    )
    if report["limitations"]:
        lines.extend(["", "## 8. 局限性"])
        for item in report["limitations"]:
            lines.append(f"- {item}")
    return lines


def build_noise_log(report: dict) -> dict:
    sample = report.get("sample", {})
    callback = report.get("callback_config", {})
    string_scan = callback.get("string_scan", {})
    verdict_refinement = callback.get("verdict_refinement", {})
    first_party = string_scan.get("first_party_candidates", {})
    third_party = string_scan.get("third_party_summary", {})
    sdk_keys = report.get("sdk_key_profile", {})

    return {
        "notes": "仅用于缓存目录中的调试和查漏补缺，记录被抑制或未进入最终结论的 URL、域名与调证值候选。",
        "sample": {
            "target": sample.get("target"),
            "analysis_mode": sample.get("analysis_mode"),
            "generated_at": sample.get("generated_at"),
        },
        "callback_noise": {
            "selection_reason": callback.get("selection_reason"),
            "final_verdict_stage": verdict_refinement.get("selected_stage"),
            "final_verdict_suppressed_count": verdict_refinement.get("suppressed_count", 0),
            "final_verdict_suppressed_examples": verdict_refinement.get("suppressed_examples", []),
            "brand_tokens": verdict_refinement.get("brand_tokens", []),
            "first_party_suppressed_count": first_party.get("suppressed_domain_count", 0),
            "first_party_suppressed_examples": first_party.get("suppressed_examples", []),
            "third_party_url_examples": third_party.get("sample_urls", []),
            "third_party_domain_examples": third_party.get("sample_domains", []),
            "third_party_suppressed_count": third_party.get("suppressed_domain_count", 0),
            "third_party_suppressed_examples": third_party.get("suppressed_examples", []),
        },
        "sdk_key_noise": {
            "suppressed_candidates": sdk_keys.get("suppressed_candidates", 0),
            "suppressed_breakdown": sdk_keys.get("suppressed_breakdown", {}),
            "suppressed_examples": sdk_keys.get("suppressed_examples", []),
        },
    }


def write_minimal_docx(lines: list[str], output_path: Path) -> None:
    def paragraph_xml(text: str) -> str:
        return f"<w:p><w:r><w:t xml:space=\"preserve\">{xml_escape(text)}</w:t></w:r></w:p>"

    document_xml = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<w:document xmlns:wpc=\"http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas\" "
        "xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" "
        "xmlns:o=\"urn:schemas-microsoft-com:office:office\" "
        "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" "
        "xmlns:m=\"http://schemas.openxmlformats.org/officeDocument/2006/math\" "
        "xmlns:v=\"urn:schemas-microsoft-com:vml\" "
        "xmlns:wp14=\"http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing\" "
        "xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\" "
        "xmlns:w10=\"urn:schemas-microsoft-com:office:word\" "
        "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" "
        "xmlns:w14=\"http://schemas.microsoft.com/office/word/2010/wordml\" "
        "xmlns:wpg=\"http://schemas.microsoft.com/office/word/2010/wordprocessingGroup\" "
        "xmlns:wpi=\"http://schemas.microsoft.com/office/word/2010/wordprocessingInk\" "
        "xmlns:wne=\"http://schemas.microsoft.com/office/word/2006/wordml\" "
        "xmlns:wps=\"http://schemas.microsoft.com/office/word/2010/wordprocessingShape\" mc:Ignorable=\"w14 wp14\">"
        "<w:body>"
        + "".join(paragraph_xml(line) for line in lines)
        + "<w:sectPr><w:pgSz w:w=\"12240\" w:h=\"15840\"/><w:pgMar w:top=\"1440\" w:right=\"1440\" w:bottom=\"1440\" w:left=\"1440\" w:header=\"720\" w:footer=\"720\" w:gutter=\"0\"/></w:sectPr>"
        "</w:body></w:document>"
    )
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/><Override PartName=\"/docProps/core.xml\" ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\"/><Override PartName=\"/docProps/app.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.extended-properties+xml\"/></Types>")
        archive.writestr("_rels/.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\" Target=\"docProps/core.xml\"/><Relationship Id=\"rId3\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties\" Target=\"docProps/app.xml\"/></Relationships>")
        archive.writestr("docProps/core.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:dcmitype=\"http://purl.org/dc/dcmitype/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><dc:title>Android 恶意应用静态分析报告</dc:title><dc:creator>Codex</dc:creator><cp:lastModifiedBy>Codex</cp:lastModifiedBy></cp:coreProperties>")
        archive.writestr("docProps/app.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\" xmlns:vt=\"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\"><Application>Codex</Application></Properties>")
        archive.writestr("word/document.xml", document_xml)
        archive.writestr("word/_rels/document.xml.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>")


def export_icon_candidates(view: PackageView, entry_names: list[str], cache_dir: Path) -> list[dict]:
    import re

    icon_name_re = re.compile(r"(?:^|/)(?:ic_|icon|logo|launcher)", re.IGNORECASE)
    icon_dir = cache_dir / "icons"
    exported = []
    for name in entry_names:
        lower = name.lower()
        if not icon_name_re.search(lower):
            continue
        if not lower.endswith((".png", ".webp", ".jpg", ".jpeg", ".xml")):
            continue
        icon_dir.mkdir(parents=True, exist_ok=True)
        target = icon_dir / name.replace("/", "__")
        target.write_bytes(view.read_entry(name))
        exported.append({"source": name, "exported_to": str(target)})
        if len(exported) >= 6:
            break
    return exported
