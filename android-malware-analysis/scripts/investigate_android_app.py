#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import analyze_package
from android_tooling import detect_android_tooling
from pipeline.behaviors import classify_functions, detect_crypto, keyword_hits
from pipeline.callbacks import manifest_source_prefixes, preferred_analysis_records
from pipeline.callbacks import collect_callback_config
from pipeline.flow import build_evidence_chains, build_flow
from pipeline.frameworks import classify_frameworks
from pipeline.manifest import PackageView, find_manifest_entry, parse_manifest_bytes, parse_manifest_info
from pipeline.native import analyze_native_libs
from pipeline.report import build_noise_log, export_icon_candidates, markdown_lines, write_minimal_docx
from pipeline.sdk_keys import extract_third_party_sdk_keys

DANGEROUS_PERMISSIONS = {
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CALL_LOG",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
}
SPECIAL_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.BIND_DEVICE_ADMIN",
}


def build_output_layout(target: Path, output_dir: str | None) -> dict[str, Path]:
    base_name = target.resolve().stem if target.is_file() else target.resolve().name
    root = Path(output_dir).expanduser().resolve() if output_dir else target.parent.resolve()
    return {
        "root": root,
        "report_dir": root / "报告" / base_name,
        "cache_dir": root / "cache" / base_name,
    }


def choose_analysis_mode(requested_mode: str, tooling: dict) -> str:
    if requested_mode == "auto":
        return tooling["recommended_mode"]
    if requested_mode == "full" and not tooling["full_ready"]:
        missing = ", ".join(item["group"] for item in tooling["missing_groups"])
        raise SystemExit(f"Full mode requested, but required tool groups are missing: {missing}. Run check_android_tools.py first or rerun with --mode best-effort.")
    return requested_mode


def assemble_report(target: Path, cache_dir: Path, analysis_mode: str, tooling: dict) -> dict:
    triage = analyze_package.analyze_target(target)
    native_summary = {"so_files": [], "packers": [], "anti_analysis": [], "native_urls": []}
    with PackageView(target) as view:
        entries = list(view.iter_entries())
        entry_names = [name for name, _ in entries]
        manifest_entry = find_manifest_entry(entry_names)
        manifest_bytes = view.read_entry(manifest_entry) if manifest_entry else None
        if manifest_bytes:
            manifest_info = parse_manifest_info(
                parse_manifest_bytes(manifest_bytes),
                dangerous_permissions=DANGEROUS_PERMISSIONS,
                special_permissions=SPECIAL_PERMISSIONS,
            )
        else:
            manifest_info = {
                "package_name": None,
                "permissions": [],
                "dangerous_permissions": [],
                "special_permissions": [],
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
                "main_entry_function": None,
                "launcher_activity": None,
                "application_name": None,
                "app_label": None,
                "icon_ref": None,
            }

        string_records = []
        preferred_prefixes = manifest_source_prefixes(manifest_info)

        def entry_priority(item: tuple[str, int]) -> tuple[int, str]:
            name = item[0].replace("\\", "/")
            if manifest_entry and name == manifest_entry:
                return (0, name)
            if any(name.startswith(prefix) for prefix in preferred_prefixes):
                return (1, name)
            if name.startswith("sources/"):
                return (2, name)
            return (3, name)

        for name, size in sorted(entries, key=entry_priority):
            if not analyze_package.looks_scannable(name, size):
                continue
            try:
                blob = view.read_entry(name, analyze_package.MAX_SCAN_BYTES)
            except OSError:
                continue
            for text in analyze_package.normalized_strings(blob):
                string_records.append((name, text))
                if len(string_records) >= 40000:
                    break
            if len(string_records) >= 40000:
                break

        analysis_records = preferred_analysis_records(string_records, manifest_info)
        framework = classify_frameworks(entry_names, analysis_records, manifest_info)
        callback_config = collect_callback_config(triage, string_records, manifest_info)
        functions = classify_functions(triage, manifest_info, framework, keyword_hits(analysis_records), callback_config)
        crypto = detect_crypto(analysis_records)
        sdk_key_profile = extract_third_party_sdk_keys(string_records, manifest_info)
        icon_candidates = export_icon_candidates(view, entry_names, cache_dir)

        if triage.get("archive_summary", {}).get("native_libs"):
            with tempfile.TemporaryDirectory(prefix="android-native-") as tmpdir:
                native_summary = analyze_native_libs(view, entry_names, Path(tmpdir))

    flow = build_flow(manifest_info, framework, functions, crypto, callback_config, triage)
    evidence_chains = build_evidence_chains(framework, functions, callback_config, crypto, sdk_key_profile, flow, native_summary=native_summary)

    limitations = []
    if str(manifest_info.get("icon_ref") or "").startswith("@0x"):
        limitations.append("Manifest 图标为二进制资源引用；如需精确定位图标文件，仍可能需要解码 resources.arsc。")
    if triage.get("archive_summary", {}).get("native_libs"):
        limitations.append("样本包含 Native 库；若关键行为位于 C/C++ 层，字符串静态分析可能无法完整解释。")
    if native_summary.get("packers"):
        limitations.append(f"Native 库 strings 命中疑似加固或壳标记：{', '.join(native_summary['packers'])}。")
    if native_summary.get("anti_analysis"):
        limitations.append(f"Native 库 strings 命中反分析标记：{', '.join(native_summary['anti_analysis'])}。")
    if not any(callback_config["endpoints"].values()):
        limitations.append("未提取到明确的回连地址；配置可能来自远程下发、加密内容或运行时生成。")
    if analysis_mode == "best-effort" and tooling["missing_groups"]:
        limitations.append(f"由于缺少完整分析所需工具组，当前只能以 best-effort 模式运行：{', '.join(item['group'] for item in tooling['missing_groups'])}。")

    sample = {
        "target": str(target.resolve()),
        "package_source": getattr(view, "description", str(target)),
        "package_type": triage.get("package_type"),
        "risk_level": triage.get("risk_level"),
        "risk_score": triage.get("risk_score"),
        "analysis_mode": analysis_mode,
        "hashes": triage.get("hashes", {}),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return {
        "sample": sample,
        "environment": {key: value for key, value in tooling.items() if key != "tool_map"},
        "triage": triage,
        "base_info": manifest_info,
        "technical_profile": framework,
        "functional_profile": functions,
        "callback_config": callback_config,
        "crypto_profile": crypto,
        "sdk_key_profile": sdk_key_profile,
        "execution_flow": flow,
        "evidence_chains": evidence_chains,
        "icon_candidates": icon_candidates,
        "limitations": limitations,
        "artifacts": {},
    }


def write_outputs(report: dict, report_dir: Path, cache_dir: Path) -> dict:
    report_dir = report_dir.resolve()
    cache_dir = cache_dir.resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    analysis_json = cache_dir / "analysis.json"
    callback_json = cache_dir / "callback-config.json"
    noise_log_json = cache_dir / "noise-log.json"
    markdown_path = report_dir / "report.md"
    docx_path = report_dir / "report.docx"

    report["artifacts"] = {
        "report_dir": str(report_dir),
        "cache_dir": str(cache_dir),
        "analysis_json": str(analysis_json),
        "callback_config_json": str(callback_json),
        "noise_log_json": str(noise_log_json),
        "markdown_report": str(markdown_path),
        "docx_report": str(docx_path),
    }

    lines = markdown_lines(report)
    noise_log = build_noise_log(report)
    analysis_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    callback_json.write_text(json.dumps(report["callback_config"], indent=2, ensure_ascii=False), encoding="utf-8")
    noise_log_json.write_text(json.dumps(noise_log, indent=2, ensure_ascii=False), encoding="utf-8")
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_minimal_docx(lines, docx_path)
    return report["artifacts"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a standardized Android malicious app investigation pipeline and generate JSON/Markdown/DOCX artifacts.")
    parser.add_argument("target", help="Path to an APK/APKS/XAPK/ZIP or unpacked Android app directory.")
    parser.add_argument("--output-dir", help="Directory where cache artifacts (analysis.json, callback-config.json, noise-log.json) and report outputs (report.md, report.docx) will be written.")
    parser.add_argument("--mode", choices=["auto", "full", "best-effort"], default="auto", help="Use auto to pick full mode only when the required APK analysis tooling is available.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = Path(args.target).expanduser().resolve()
    layout = build_output_layout(target, args.output_dir)
    tooling = detect_android_tooling()
    analysis_mode = choose_analysis_mode(args.mode, tooling)
    report = assemble_report(target, layout["cache_dir"], analysis_mode, tooling)
    artifacts = write_outputs(report, layout["report_dir"], layout["cache_dir"])
    print(
        json.dumps(
            {
                "output_root": str(layout["root"]),
                "report_dir": str(layout["report_dir"]),
                "cache_dir": str(layout["cache_dir"]),
                "artifacts": artifacts,
                "analysis_mode": analysis_mode,
                "full_ready": tooling["full_ready"],
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
