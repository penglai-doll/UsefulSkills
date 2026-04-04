from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import analyze_package

PACKER_MARKERS = {
    "Bangcle": re.compile(r"bangcle|libsecexe|libexecmain", re.IGNORECASE),
    "360": re.compile(r"ijiami|libjiagu|qihoo", re.IGNORECASE),
    "Tencent Legu": re.compile(r"legu|libshella|libshell", re.IGNORECASE),
    "iJiami": re.compile(r"ijiami|libexec", re.IGNORECASE),
}
ANTI_ANALYSIS_MARKERS = {
    "frida": re.compile(r"\bfrida\b", re.IGNORECASE),
    "xposed": re.compile(r"\bxposed\b", re.IGNORECASE),
    "substrate": re.compile(r"substrate", re.IGNORECASE),
    "magisk": re.compile(r"\bmagisk\b", re.IGNORECASE),
}
ASCII_STRINGS_RE = re.compile(rb"[ -~]{6,}")


def _extract_strings(blob: bytes) -> list[str]:
    return [match.decode("utf-8", errors="replace") for match in ASCII_STRINGS_RE.findall(blob)]


def _run_strings(path: Path) -> list[str]:
    strings_bin = shutil.which("strings")
    if not strings_bin:
        return _extract_strings(path.read_bytes())
    result = subprocess.run([strings_bin, "-a", "-n", "6", str(path)], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        return _extract_strings(path.read_bytes())
    return [line for line in result.stdout.splitlines() if line]


def analyze_native_libs(view, entry_names: list[str], temp_dir: Path) -> dict:
    so_files = [name for name in entry_names if name.lower().endswith(".so")]
    summary = {
        "so_files": so_files,
        "packers": [],
        "anti_analysis": [],
        "native_urls": [],
    }
    if not so_files:
        return summary

    extracted_dir = temp_dir / "native"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    packers = set()
    anti = set()
    urls = set()
    for name in so_files:
        local_path = extracted_dir / Path(name).name
        local_path.write_bytes(view.read_entry(name))
        for value in _run_strings(local_path):
            for packer_name, pattern in PACKER_MARKERS.items():
                if pattern.search(value):
                    packers.add(packer_name)
            for anti_name, pattern in ANTI_ANALYSIS_MARKERS.items():
                if pattern.search(value):
                    anti.add(anti_name)
            for url in analyze_package.URL_RE.findall(value):
                if not analyze_package.is_ignored_public_url(url):
                    urls.add(url)

    summary["packers"] = sorted(packers)
    summary["anti_analysis"] = sorted(anti)
    summary["native_urls"] = sorted(urls)[:10]
    return summary
