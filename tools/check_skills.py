#!/usr/bin/env python3
"""Read-only checks for repository skill metadata, links, versions and syntax."""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path
from urllib.parse import unquote


def prose_lines(text: str):
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        marker = re.match(r"^\s*(`{3,}|~{3,})(.*)$", line)
        if marker:
            ticks, tail = marker.groups()
            if fence is None:
                fence = ticks
            elif ticks[0] == fence[0] and len(ticks) >= len(fence) and not tail.strip():
                fence = None
            continue
        if fence is None:
            yield number, line


def check(root: Path) -> dict:
    errors = []
    releases = {}
    script_count = 0
    skills = sorted(path.parent for path in root.glob("*/SKILL.md"))
    if not skills:
        errors.append("No skills found")
    for skill in skills:
        text = (skill / "SKILL.md").read_text(encoding="utf-8")
        front = re.match(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|$)", text, re.S)
        fields = re.findall(r"^([a-z_]+):\s*(.+)$", front.group(1), re.M) if front else []
        if len(fields) != 2 or {key for key, _ in fields} != {"name", "description"}:
            errors.append(f"{skill.name}: frontmatter must contain exactly name and description")
        metadata = {key: value.strip().strip('\"\'') for key, value in fields}
        if metadata.get("name") != skill.name or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", skill.name):
            errors.append(f"{skill.name}: name does not match directory")
        if not metadata.get("description") or len(metadata.get("description", "")) > 1024:
            errors.append(f"{skill.name}: description missing or too long")
        versions = re.findall(r"^Skill release: `([0-9]+\.[0-9]+\.[0-9]+)`", text, re.M)
        if len(versions) != 1:
            errors.append(f"{skill.name}: exactly one patch release declaration required")
        else:
            releases[skill.name] = versions[0]
        agent = skill / "agents" / "openai.yaml"
        if not agent.is_file():
            errors.append(f"{skill.name}: agents/openai.yaml missing")
        else:
            agent_text = agent.read_text(encoding="utf-8")
            if "$" + skill.name not in agent_text:
                errors.append(f"{skill.name}: agent prompt does not reference the skill")
            short = re.search(r'^\s*short_description:\s*"([^"\n]+)"\s*$', agent_text, re.M)
            if not short or not 25 <= len(short.group(1)) <= 64:
                errors.append(f"{skill.name}: short_description must be 25-64 characters")
        documents = [skill / "SKILL.md"] + sorted((skill / "references").rglob("*.md"))
        if (skill / "PURPOSE.md").exists():
            documents.append(skill / "PURPOSE.md")
        for document in documents:
            for number, line in prose_lines(document.read_text(encoding="utf-8")):
                for target in re.findall(r"\[[^\]\n]*\]\(([^)\n]+)\)", line):
                    target = target.strip().split(' "', 1)[0].strip("<>")
                    if target.startswith("#") or re.match(r"[a-z][a-z0-9+.-]*:", target, re.I):
                        continue
                    local = unquote(target.split("#", 1)[0])
                    if local and not (document.parent / local).exists():
                        errors.append(f"{document.relative_to(root)}:{number}: missing link {target}")
        for script in sorted((skill / "scripts").rglob("*.py")):
            script_count += 1
            try:
                compile(script.read_bytes(), str(script), "exec")
            except (SyntaxError, OSError) as exc:
                errors.append(f"{script.relative_to(root)}: {exc}")
    if (root / "writing-helper" / "scripts").exists():
        errors.append("writing-helper must remain documentation-only")
    readme = root / "README.md"
    if readme.exists():
        rows = readme.read_text(encoding="utf-8").splitlines()
        for name, release in releases.items():
            version_rows = [row for row in rows if f"](./{name}/)" in row]
            if len(version_rows) != 1 or f"`{release}`" not in version_rows[0]:
                errors.append(f"{name}: README release table does not match SKILL.md")
    machine = root / "android-malware-analysis" / "scripts" / "pipeline" / "versioning.py"
    if machine.exists():
        for node in ast.parse(machine.read_bytes()).body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "SKILL_RELEASE" for t in node.targets):
                if ast.literal_eval(node.value) != releases.get("android-malware-analysis"):
                    errors.append("Android machine and entry release versions differ")
    return {"ok": not errors, "skill_count": len(skills), "python_scripts": script_count,
            "releases": releases, "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = check(args.root.resolve())
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
