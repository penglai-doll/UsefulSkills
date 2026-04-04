from __future__ import annotations

import io
import struct
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import analyze_package

ANDROID_NS = "http://schemas.android.com/apk/res/android"
RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


def choose_primary_apk(names: list[str]) -> str:
    ranked = sorted(names, key=lambda item: (0 if Path(item).name.lower() == "base.apk" else 1, len(item), item.lower()))
    return ranked[0]


def find_manifest_entry(entry_names: list[str]) -> str | None:
    normalized = [name.replace("\\", "/") for name in entry_names]
    if "AndroidManifest.xml" in normalized:
        return "AndroidManifest.xml"
    preferred = [
        "resources/AndroidManifest.xml",
        "original/AndroidManifest.xml",
    ]
    for candidate in preferred:
        if candidate in normalized:
            return candidate
    matches = [name for name in normalized if name.endswith("/AndroidManifest.xml")]
    if not matches:
        return None
    return sorted(matches, key=lambda item: (len(item.split("/")), len(item), item.lower()))[0]


class PackageView:
    def __init__(self, target: Path):
        self.target = target
        self.description = str(target)
        self._closeables = []
        self._temp_dirs = []
        self._kind = "directory"
        self._base = target

        self._open_target(target, str(target))

    def _open_target(self, target: Path, description: str) -> None:
        if target.is_dir():
            self._kind = "directory"
            self._base = target
            self.description = description
            return

        try:
            self._open_zip_target(target, description)
        except (ValueError, zipfile.BadZipFile, NotImplementedError, OSError):
            if self._open_target_with_7z(target, description):
                return
            raise ValueError(f"{target} is not a supported directory or Android archive.")

    def _open_zip_target(self, target: Path, description: str) -> None:
        if not zipfile.is_zipfile(target):
            raise ValueError(f"{target} is not a supported directory or Android archive.")

        root_zip = zipfile.ZipFile(target)
        nested_zip = None
        try:
            root_names = [info.filename for info in root_zip.infolist() if not info.is_dir()]
            if "AndroidManifest.xml" in root_names:
                self._kind = "zip"
                self._zip = root_zip
                self._closeables.append(root_zip)
                self.description = description
                return

            apk_names = [name for name in root_names if name.lower().endswith(".apk")]
            if apk_names:
                primary = choose_primary_apk(apk_names)
                nested_zip = zipfile.ZipFile(io.BytesIO(root_zip.read(primary)))
                self._kind = "nested-zip"
                self._zip = nested_zip
                self._closeables.extend([root_zip, nested_zip])
                self.description = f"{description}!/{primary}"
                return

            self._kind = "zip"
            self._zip = root_zip
            self._closeables.append(root_zip)
            self.description = description
        except Exception:
            root_zip.close()
            if nested_zip is not None:
                nested_zip.close()
            raise

    def _open_target_with_7z(self, target: Path, description: str) -> bool:
        temp_dir = tempfile.TemporaryDirectory(prefix="apk-view-7z-")
        success, _detail = analyze_package.extract_archive_with_7z(target, Path(temp_dir.name))
        if not success:
            temp_dir.cleanup()
            return False

        self._temp_dirs.append(temp_dir)
        extracted_root = Path(temp_dir.name)
        if (extracted_root / "AndroidManifest.xml").exists():
            self._kind = "directory"
            self._base = extracted_root
            self.description = f"{description} (7z-extracted)"
            return True

        top_level_apks = [item for item in extracted_root.iterdir() if item.is_file() and item.suffix.lower() == ".apk"]
        if top_level_apks:
            primary_name = choose_primary_apk([item.name for item in top_level_apks])
            primary_path = extracted_root / primary_name
            self._open_target(primary_path, f"{description}!/{primary_name} (7z-extracted)")
            return True

        self._kind = "directory"
        self._base = extracted_root
        self.description = f"{description} (7z-extracted)"
        return True

    def _reset_to_7z_view(self) -> None:
        for handle in reversed(self._closeables):
            handle.close()
        self._closeables.clear()
        for temp_dir in reversed(self._temp_dirs):
            temp_dir.cleanup()
        self._temp_dirs.clear()
        self._open_target_with_7z(self.target, str(self.target))

    def __enter__(self) -> "PackageView":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        for handle in reversed(self._closeables):
            handle.close()
        for temp_dir in reversed(self._temp_dirs):
            temp_dir.cleanup()

    def iter_entries(self):
        if self._kind == "directory":
            for path in sorted(self._base.rglob("*")):
                if path.is_file():
                    yield path.relative_to(self._base).as_posix(), path.stat().st_size
            return
        for info in self._zip.infolist():
            if not info.is_dir():
                yield info.filename.replace("\\", "/"), info.file_size

    def read_entry(self, name: str, limit: int | None = None) -> bytes:
        if self._kind == "directory":
            data = (self._base / name).read_bytes()
        else:
            try:
                data = self._zip.read(name)
            except NotImplementedError:
                self._reset_to_7z_view()
                data = (self._base / name).read_bytes() if self._kind == "directory" else self._zip.read(name)
        return data if limit is None else data[:limit]


def decode_length8(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80:
        return ((first & 0x7F) << 7) + data[offset + 1], 2
    return first, 1


def decode_length16(data: bytes, offset: int) -> tuple[int, int]:
    first = struct.unpack_from("<H", data, offset)[0]
    if first & 0x8000:
        second = struct.unpack_from("<H", data, offset + 2)[0]
        return ((first & 0x7FFF) << 15) + second, 4
    return first, 2


def parse_string_pool(data: bytes, offset: int) -> tuple[list[str], int]:
    _, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
    string_count, _, flags, strings_start, _ = struct.unpack_from("<IIIII", data, offset + 8)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{string_count}I", data, offset + header_size)
    base = offset + strings_start
    strings = []
    for item_offset in offsets:
        cursor = base + item_offset
        if utf8:
            _, skip_chars = decode_length8(data, cursor)
            byte_len, skip_bytes = decode_length8(data, cursor + skip_chars)
            raw = data[cursor + skip_chars + skip_bytes : cursor + skip_chars + skip_bytes + byte_len]
            strings.append(raw.decode("utf-8", errors="replace"))
        else:
            char_len, skip = decode_length16(data, cursor)
            raw = data[cursor + skip : cursor + skip + char_len * 2]
            strings.append(raw.decode("utf-16le", errors="replace"))
    return strings, chunk_size


def pool_get(strings: list[str], index: int) -> str | None:
    if index == 0xFFFFFFFF or index < 0 or index >= len(strings):
        return None
    return strings[index]


def typed_value_to_text(data_type: int, data_value: int, strings: list[str]) -> str:
    if data_type == TYPE_STRING:
        return pool_get(strings, data_value) or ""
    if data_type == TYPE_REFERENCE:
        return f"@0x{data_value:08x}"
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if data_value else "false"
    if data_type == TYPE_INT_HEX:
        return f"0x{data_value:08x}"
    if data_type == TYPE_INT_DEC:
        return str(data_value)
    return f"0x{data_value:08x}"


def parse_binary_manifest(data: bytes) -> dict:
    chunk_type, header_size, _ = struct.unpack_from("<HHI", data, 0)
    if chunk_type != RES_XML_TYPE:
        raise ValueError("Not a binary AndroidManifest.xml blob.")

    offset = header_size
    strings: list[str] = []
    uri_prefix_map: dict[str, str] = {}
    stack: list[dict] = []
    root: dict | None = None

    while offset < len(data):
        chunk_type, _, chunk_size = struct.unpack_from("<HHI", data, offset)
        if chunk_type == RES_STRING_POOL_TYPE:
            strings, _ = parse_string_pool(data, offset)
        elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            pass
        elif chunk_type in {RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE}:
            prefix_idx, uri_idx = struct.unpack_from("<II", data, offset + 16)
            prefix = pool_get(strings, prefix_idx) or ""
            uri = pool_get(strings, uri_idx) or ""
            if prefix and uri:
                uri_prefix_map[uri] = prefix
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            ns_idx, name_idx = struct.unpack_from("<II", data, offset + 16)
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, offset + 24)
            name = pool_get(strings, name_idx) or "unknown"
            node = {"name": name, "attrs": {}, "children": []}
            attr_offset = offset + 16 + attr_start
            for i in range(attr_count):
                cursor = attr_offset + (i * attr_size)
                attr_ns, attr_name, raw_value = struct.unpack_from("<III", data, cursor)
                _, _, data_type, data_value = struct.unpack_from("<HBBI", data, cursor + 12)
                namespace = pool_get(strings, attr_ns)
                attr_local = pool_get(strings, attr_name) or "unknown"
                attr_name_text = f"{uri_prefix_map.get(namespace, '')}:{attr_local}".lstrip(":") if namespace else attr_local
                attr_value = pool_get(strings, raw_value) if raw_value != 0xFFFFFFFF else typed_value_to_text(data_type, data_value, strings)
                node["attrs"][attr_name_text] = attr_value or ""
            if stack:
                stack[-1]["children"].append(node)
            else:
                root = node
            stack.append(node)
        elif chunk_type == RES_XML_END_ELEMENT_TYPE and stack:
            stack.pop()
        offset += chunk_size

    if root is None:
        raise ValueError("Failed to parse manifest tree.")
    return root


def plain_node_from_etree(elem: ET.Element) -> dict:
    attrs = {}
    for key, value in elem.attrib.items():
        if key.startswith("{"):
            namespace, _, local = key[1:].partition("}")
            attrs[f"android:{local}" if namespace == ANDROID_NS else local] = value
        else:
            attrs[key] = value
    return {"name": elem.tag.rsplit("}", 1)[-1], "attrs": attrs, "children": [plain_node_from_etree(child) for child in list(elem)]}


def parse_manifest_bytes(data: bytes) -> dict:
    stripped = data.lstrip()
    if stripped.startswith(b"<") or stripped.startswith(b"<?xml"):
        root = ET.fromstring(data.decode("utf-8", errors="replace"))
        return plain_node_from_etree(root)
    return parse_binary_manifest(data)


def get_attr(node: dict, name: str) -> str | None:
    return node["attrs"].get(name) or node["attrs"].get(f"android:{name}")


def resolve_component_name(package_name: str, value: str | None) -> str | None:
    if not value:
        return None
    if value.startswith("."):
        return f"{package_name}{value}"
    if "." not in value:
        return f"{package_name}.{value}"
    return value


def parse_manifest_info(
    manifest_root: dict,
    dangerous_permissions: set[str],
    special_permissions: set[str],
) -> dict:
    package_name = manifest_root["attrs"].get("package", "")
    info = {
        "package_name": package_name,
        "version_name": get_attr(manifest_root, "versionName"),
        "version_code": get_attr(manifest_root, "versionCode"),
        "permissions": [],
        "dangerous_permissions": [],
        "special_permissions": [],
        "application_name": None,
        "app_label": None,
        "icon_ref": None,
        "min_sdk": None,
        "target_sdk": None,
        "launcher_activity": None,
        "main_entry_function": None,
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }

    for child in manifest_root["children"]:
        if child["name"] in {"uses-permission", "uses-permission-sdk-23"}:
            permission = get_attr(child, "name")
            if permission:
                info["permissions"].append(permission)
                if permission in dangerous_permissions:
                    info["dangerous_permissions"].append(permission)
                if permission in special_permissions:
                    info["special_permissions"].append(permission)
        elif child["name"] == "uses-sdk":
            info["min_sdk"] = get_attr(child, "minSdkVersion")
            info["target_sdk"] = get_attr(child, "targetSdkVersion")
        elif child["name"] == "application":
            info["application_name"] = resolve_component_name(package_name, get_attr(child, "name"))
            info["app_label"] = get_attr(child, "label")
            info["icon_ref"] = get_attr(child, "icon")
            for component in child["children"]:
                kind = component["name"]
                if kind not in {"activity", "activity-alias", "service", "receiver", "provider"}:
                    continue
                record = {
                    "name": resolve_component_name(package_name, get_attr(component, "name")),
                    "exported": get_attr(component, "exported"),
                    "enabled": get_attr(component, "enabled"),
                    "permission": get_attr(component, "permission"),
                    "actions": [],
                    "categories": [],
                }
                for intent_filter in [item for item in component["children"] if item["name"] == "intent-filter"]:
                    for action in [item for item in intent_filter["children"] if item["name"] == "action"]:
                        if get_attr(action, "name"):
                            record["actions"].append(get_attr(action, "name"))
                    for category in [item for item in intent_filter["children"] if item["name"] == "category"]:
                        if get_attr(category, "name"):
                            record["categories"].append(get_attr(category, "name"))
                target = {"activity": "activities", "activity-alias": "activities", "service": "services", "receiver": "receivers", "provider": "providers"}[kind]
                info[target].append(record)
                if "android.intent.action.MAIN" in record["actions"] and "android.intent.category.LAUNCHER" in record["categories"] and not info["launcher_activity"]:
                    info["launcher_activity"] = record["name"]

    if info["launcher_activity"]:
        info["main_entry_function"] = f"{info['launcher_activity']}.onCreate(...)"
    elif info["application_name"]:
        info["main_entry_function"] = f"{info['application_name']}.onCreate(...)"
    return info
