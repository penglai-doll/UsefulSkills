"""Synthetic, disposable evidence fixtures used by the acceptance suite."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
from pathlib import Path


FIXTURES = Path(__file__).with_name("fixtures")


def write_evidence_set(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    payload = b"WINDOWS-LOADER-SYNTHETIC-EVIDENCE\x00" * 8
    files = {
        "raw": directory / "evidence.raw",
        "dd": directory / "evidence.dd",
        "img": directory / "evidence.img",
        "vhd": directory / "evidence.vhd",
        "vhdx": directory / "evidence.vhdx",
        "single_e01": directory / "standalone.E01",
        "split_e01": directory / "evidence.E01",
        "split_e02": directory / "evidence.E02",
        "invalid": directory / "evidence.unsupported",
    }
    for key, path in files.items():
        path.write_bytes(payload + key.encode("ascii"))
    shutil.copyfile(FIXTURES / "standalone.E01", files["single_e01"])
    shutil.copyfile(FIXTURES / "split.E01", files["split_e01"])
    shutil.copyfile(FIXTURES / "split.E02", files["split_e02"])
    return files


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_windows_root(directory: Path, install_name: str = "C") -> Path:
    root = directory / install_name
    paths = [
        "Windows/System32/config/SOFTWARE",
        "Windows/ServiceProfiles/LocalService/AppData/Local/FooService/config.json",
        "Windows/ServiceProfiles/NetworkService/AppData/Roaming/FooService/config.json",
        "Users/Alice/AppData/Roaming/FooChat/config.json",
        "Users/Alice/AppData/Local/FooChat/cache.db",
        "Users/Alice/AppData/Local/Packages/FooChat_123abc/LocalState/settings.json",
        "Users/Default/AppData/Roaming/FooChat/template.json",
        "ProgramData/FooChat/config.ini",
        "Program Files/FooChat/FooChat.exe",
        "Program Files (x86)/FooChat/FooChat.exe",
        "Tools/Portable/FooChat/settings.xml",
    ]
    for relative in paths:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("chat.example.test\n", encoding="utf-8")
    return root


def make_long_path(root: Path) -> Path:
    segments = ["longpart" + str(index).zfill(2) for index in range(35)]
    path = root.joinpath("Users", "Alice", "AppData", "Roaming", *segments, "config.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"long_path": true}', encoding="utf-8")
    return path


def make_reparse_link(root: Path, external: Path) -> Path | None:
    target = external / "outside-secret.txt"
    external.mkdir(parents=True, exist_ok=True)
    target.write_text("MUST-NOT-BE-INDEXED", encoding="utf-8")
    link = root / "Users" / "Alice" / "AppData" / "Roaming" / "Junction"
    try:
        os.symlink(external, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        return None
    return link


def copy_structured_fixtures(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in ("sample.json", "sample.ini", "sample.xml", "sample.evtx.json", "sample_registry.dat"):
        target = directory / name
        shutil.copyfile(FIXTURES / name, target)
        files[name] = target

    database = directory / "History.sqlite"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)"
        )
        connection.execute(
            "INSERT INTO urls VALUES (?, ?, ?, ?)",
            ("https://chat.example.test/login", "FooChat Login", 7, 13380163200000000),
        )
        connection.commit()
    finally:
        connection.close()
    files["sqlite"] = database
    return files
