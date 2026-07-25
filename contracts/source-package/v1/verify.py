#!/usr/bin/env python3
"""Validate and copy the frozen Shimpz source-package v1 authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = "contract-files.sha256"
AUTHORITY_FILES = ("README.md", "contract.json", "vectors.json", "verify.py")
BLOCK_BYTES = 512


class ContractViolationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Content:
    unit: bytes
    count: int = 1

    @property
    def size(self) -> int:
        return len(self.unit) * self.count

    def materialize(self) -> bytes:
        return self.unit * self.count


@dataclass(frozen=True)
class SourceEntry:
    path: str
    content: Content


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    is_directory: bool
    content: Content


def fail(message: str) -> None:
    raise SystemExit(message)


def load_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"{path.name} is not valid JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.name} must contain a JSON object")
    return value


def require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    return value


def require_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{label} must be a non-negative integer")
    return value


def contract_sections(contract: dict[str, object]) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    source_tree = require_object(contract.get("source_tree"), "contract.source_tree")
    path = require_object(contract.get("path"), "contract.path")
    limits = require_object(contract.get("limits"), "contract.limits")
    return source_tree, path, limits


def require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        fail(f"{label} must be {expected!r}")


def validate_contract(contract: dict[str, object]) -> None:
    source_tree, path, limits = contract_sections(contract)
    archive = require_object(contract.get("archive"), "contract.archive")
    metadata = require_object(archive.get("metadata"), "contract.archive.metadata")
    require_equal(contract.get("media_type"), "application/vnd.shimpz.source.v1+tar", "contract.media_type")
    require_equal(source_tree.get("author_entry_type"), "regular_file", "source_tree.author_entry_type")
    require_equal(
        source_tree.get("directory_policy"),
        "synthesize_nonempty_parents",
        "source_tree.directory_policy",
    )
    require_equal(source_tree.get("empty_directories"), "omit", "source_tree.empty_directories")
    require_equal(source_tree.get("unknown_root_policy"), "reject", "source_tree.unknown_root_policy")
    expected_path = {
        "encoding": "ASCII",
        "separator": "/",
        "normalization": "none",
        "absolute_paths": "reject",
        "empty_dot_and_parent_segments": "reject",
        "collision_key": "ASCII_A_Z_to_a_z",
        "exact_and_collision_duplicates": "reject",
    }
    for key, expected in expected_path.items():
        require_equal(path.get(key), expected, f"contract.path.{key}")
    require_equal(set(limits), {
        "package_bytes",
        "regular_files",
        "single_file_bytes",
        "path_bytes",
        "path_components",
        "ustar_name_bytes",
        "ustar_prefix_bytes",
    }, "contract.limits keys")
    expected_archive = {
        "format": "POSIX_ustar",
        "compression": "none",
        "block_bytes": BLOCK_BYTES,
        "end_zero_blocks": 2,
        "entry_order": "canonical_path_ASCII_byte_ascending",
        "directory_header_trailing_slash": False,
        "numeric_fields": "zero_padded_octal_with_trailing_NUL",
        "checksum_field": "six_zero_padded_octal_digits_NUL_space",
        "file_padding": "zero_to_512_byte_boundary",
    }
    for key, expected in expected_archive.items():
        require_equal(archive.get(key), expected, f"contract.archive.{key}")
    require_equal(
        archive.get("path_encoding"),
        {
            "short": "full_path_in_name_when_at_most_100_bytes",
            "long": "rightmost_slash_prefix_and_basename",
            "extensions": "reject",
        },
        "contract.archive.path_encoding",
    )
    for key in ("uname", "gname", "linkname"):
        require_equal(metadata.get(key), "", f"contract.archive.metadata.{key}")


def content_from(raw: dict[str, object], label: str) -> Content:
    has_text = "text" in raw
    has_repeat = "repeat" in raw
    if has_text == has_repeat:
        fail(f"{label} must define exactly one of text or repeat")
    if has_text:
        text = raw["text"]
        if not isinstance(text, str):
            fail(f"{label}.text must be a string")
        return Content(text.encode())
    repeat = require_object(raw["repeat"], f"{label}.repeat")
    unit = repeat.get("byte")
    count = require_integer(repeat.get("count"), f"{label}.repeat.count")
    if not isinstance(unit, str) or len(unit.encode()) != 1:
        fail(f"{label}.repeat.byte must be one ASCII byte")
    return Content(unit.encode(), count)


def source_entry_from(raw: object, label: str) -> SourceEntry:
    entry = require_object(raw, label)
    path = entry.get("path")
    entry_type = entry.get("type")
    if not isinstance(path, str) or not isinstance(entry_type, str):
        fail(f"{label} requires string path and type")
    if entry_type != "regular_file":
        raise ContractViolationError("special_file")
    return SourceEntry(path, content_from(entry, label))


def generated_entries(raw: object, label: str) -> list[SourceEntry]:
    generator = require_object(raw, label)
    strings = {}
    for key in ("root", "prefix", "suffix", "text"):
        value = generator.get(key)
        if not isinstance(value, str):
            fail(f"{label}.{key} must be a string")
        strings[key] = value
    start = require_integer(generator.get("start"), f"{label}.start")
    count = require_integer(generator.get("count"), f"{label}.count")
    width = require_integer(generator.get("width"), f"{label}.width")
    content = Content(strings["text"].encode())
    return [
        SourceEntry(
            f"{strings['root']}/{strings['prefix']}{index:0{width}d}{strings['suffix']}",
            content,
        )
        for index in range(start, start + count)
    ]


def expand_case(case: dict[str, object]) -> list[SourceEntry]:
    entries = [
        source_entry_from(raw, f"{case.get('name')}.entries[{index}]")
        for index, raw in enumerate(require_list(case.get("entries"), f"{case.get('name')}.entries"))
    ]
    generators = require_list(case.get("generate", []), f"{case.get('name')}.generate")
    for index, raw in enumerate(generators):
        entries.extend(generated_entries(raw, f"{case.get('name')}.generate[{index}]"))
    return entries


def ascii_collision_key(path: str) -> str:
    return path.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))


def split_ustar_path(path: str, limits: dict[str, object]) -> tuple[str, str]:
    encoded = path.encode("ascii")
    max_path = require_integer(limits.get("path_bytes"), "contract.limits.path_bytes")
    max_name = require_integer(limits.get("ustar_name_bytes"), "contract.limits.ustar_name_bytes")
    max_prefix = require_integer(limits.get("ustar_prefix_bytes"), "contract.limits.ustar_prefix_bytes")
    if len(encoded) > max_path:
        raise ContractViolationError("path_too_long")
    if len(encoded) <= max_name:
        return "", path
    if "/" not in path:
        raise ContractViolationError("ustar_name_too_long")
    prefix, name = path.rsplit("/", 1)
    if len(prefix.encode("ascii")) > max_prefix:
        raise ContractViolationError("ustar_prefix_too_long")
    if len(name.encode("ascii")) > max_name:
        raise ContractViolationError("ustar_name_too_long")
    return prefix, name


def validate_path(path: str, path_rules: dict[str, object], limits: dict[str, object]) -> list[str]:
    try:
        path.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ContractViolationError("non_ascii_path") from exc
    if path.startswith("/"):
        raise ContractViolationError("absolute_path")
    parts = path.split("/")
    if any(part in {".", ".."} for part in parts):
        raise ContractViolationError("traversal")
    pattern = path_rules.get("segment_pattern")
    if not isinstance(pattern, str) or any(not part or re.fullmatch(pattern, part) is None for part in parts):
        raise ContractViolationError("invalid_path_segment")
    max_components = require_integer(limits.get("path_components"), "contract.limits.path_components")
    if len(parts) > max_components:
        raise ContractViolationError("path_too_deep")
    split_ustar_path(path, limits)
    return parts


def validate_allowlist(path: str, parts: list[str], source_tree: dict[str, object]) -> None:
    required = require_list(source_tree.get("required_root_files"), "contract.source_tree.required_root_files")
    if path in required:
        return
    power = require_object(source_tree.get("required_direct_power"), "contract.source_tree.required_direct_power")
    power_directory = power.get("directory")
    power_pattern = power.get("filename_pattern")
    if parts[0] == power_directory:
        if len(parts) != 2:
            raise ContractViolationError("nested_power")
        if not isinstance(power_pattern, str) or re.fullmatch(power_pattern, parts[1]) is None:
            raise ContractViolationError("invalid_entry")
        return
    optional = require_list(source_tree.get("optional_roots"), "contract.source_tree.optional_roots")
    if parts[0] in optional and len(parts) >= 2:
        return
    raise ContractViolationError("unknown_root")


def validate_required(entries: list[SourceEntry], source_tree: dict[str, object]) -> None:
    paths = {entry.path for entry in entries}
    required = require_list(source_tree.get("required_root_files"), "contract.source_tree.required_root_files")
    if any(path not in paths for path in required):
        raise ContractViolationError("missing_required_file")
    power = require_object(source_tree.get("required_direct_power"), "contract.source_tree.required_direct_power")
    directory = power.get("directory")
    minimum = require_integer(power.get("minimum_files"), "contract.source_tree.required_direct_power.minimum_files")
    if sum(path.startswith(f"{directory}/") for path in paths) < minimum:
        raise ContractViolationError("missing_power")


def validate_entries(
    entries: list[SourceEntry],
    contract: dict[str, object],
) -> tuple[list[SourceEntry], dict[str, tuple[str, str]]]:
    source_tree, path_rules, limits = contract_sections(contract)
    seen_paths: set[str] = set()
    collision_paths: dict[str, str] = {}
    splits: dict[str, tuple[str, str]] = {}
    for entry in entries:
        parts = validate_path(entry.path, path_rules, limits)
        if entry.path in seen_paths:
            raise ContractViolationError("duplicate_path")
        collision_key = ascii_collision_key(entry.path)
        if collision_key in collision_paths:
            raise ContractViolationError("case_collision")
        validate_allowlist(entry.path, parts, source_tree)
        seen_paths.add(entry.path)
        collision_paths[collision_key] = entry.path
        splits[entry.path] = split_ustar_path(entry.path, limits)
    validate_required(entries, source_tree)
    max_files = require_integer(limits.get("regular_files"), "contract.limits.regular_files")
    if len(entries) > max_files:
        raise ContractViolationError("file_count_exceeded")
    max_file = require_integer(limits.get("single_file_bytes"), "contract.limits.single_file_bytes")
    if any(entry.content.size > max_file for entry in entries):
        raise ContractViolationError("single_file_too_large")
    return entries, splits


def archive_entries(entries: list[SourceEntry], limits: dict[str, object]) -> list[ArchiveEntry]:
    directories: set[str] = set()
    for entry in entries:
        parts = entry.path.split("/")
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    records = [ArchiveEntry(path, True, Content(b"")) for path in directories]
    records.extend(ArchiveEntry(entry.path, False, entry.content) for entry in entries)
    records.sort(key=lambda entry: entry.path.encode("ascii"))
    for record in records:
        split_ustar_path(record.path, limits)
    return records


def padded_size(size: int) -> int:
    return ((size + BLOCK_BYTES - 1) // BLOCK_BYTES) * BLOCK_BYTES


def canonical_records(entries: list[SourceEntry], contract: dict[str, object]) -> list[ArchiveEntry]:
    _, _, limits = contract_sections(contract)
    records = archive_entries(entries, limits)
    package_size = (len(records) * BLOCK_BYTES) + sum(
        padded_size(record.content.size) for record in records
    ) + (2 * BLOCK_BYTES)
    maximum = require_integer(limits.get("package_bytes"), "contract.limits.package_bytes")
    if package_size > maximum:
        raise ContractViolationError("package_too_large")
    return records


def octal_field(value: int, width: int) -> bytes:
    encoded = f"{value:0{width - 1}o}\0".encode("ascii")
    if len(encoded) != width:
        fail(f"value {value} does not fit a {width}-byte ustar numeric field")
    return encoded


def put(header: bytearray, offset: int, width: int, value: bytes) -> None:
    if len(value) > width:
        fail(f"ustar field at offset {offset} exceeds {width} bytes")
    header[offset : offset + width] = value.ljust(width, b"\0")


def build_header(record: ArchiveEntry, contract: dict[str, object]) -> bytes:
    _, _, limits = contract_sections(contract)
    archive = require_object(contract.get("archive"), "contract.archive")
    metadata = require_object(archive.get("metadata"), "contract.archive.metadata")
    prefix, name = split_ustar_path(record.path, limits)
    header = bytearray(BLOCK_BYTES)
    put(header, 0, 100, name.encode("ascii"))
    mode_key = "directory_mode" if record.is_directory else "file_mode"
    put(header, 100, 8, octal_field(require_integer(metadata.get(mode_key), f"metadata.{mode_key}"), 8))
    put(header, 108, 8, octal_field(require_integer(metadata.get("uid"), "metadata.uid"), 8))
    put(header, 116, 8, octal_field(require_integer(metadata.get("gid"), "metadata.gid"), 8))
    put(header, 124, 12, octal_field(record.content.size, 12))
    put(header, 136, 12, octal_field(require_integer(metadata.get("mtime"), "metadata.mtime"), 12))
    put(header, 148, 8, b"        ")
    type_key = "directory_typeflag" if record.is_directory else "file_typeflag"
    typeflag = metadata.get(type_key)
    if not isinstance(typeflag, str) or len(typeflag) != 1:
        fail(f"metadata.{type_key} must be one ASCII character")
    put(header, 156, 1, typeflag.encode("ascii"))
    put(header, 257, 6, bytes.fromhex(str(metadata.get("magic_hex"))))
    put(header, 263, 2, str(metadata.get("version")).encode("ascii"))
    put(header, 329, 8, octal_field(require_integer(metadata.get("devmajor"), "metadata.devmajor"), 8))
    put(header, 337, 8, octal_field(require_integer(metadata.get("devminor"), "metadata.devminor"), 8))
    put(header, 345, 155, prefix.encode("ascii"))
    checksum = f"{sum(header):06o}\0 ".encode("ascii")
    put(header, 148, 8, checksum)
    return bytes(header)


def build_archive(records: list[ArchiveEntry], contract: dict[str, object]) -> bytes:
    chunks: list[bytes] = []
    for record in records:
        chunks.append(build_header(record, contract))
        content = record.content.materialize()
        chunks.append(content)
        chunks.append(bytes(padded_size(len(content)) - len(content)))
    chunks.append(bytes(2 * BLOCK_BYTES))
    return b"".join(chunks)


def check_expected_split(case: dict[str, object], splits: dict[str, tuple[str, str]]) -> None:
    expected = case.get("expected_ustar")
    if expected is None:
        return
    value = require_object(expected, f"{case.get('name')}.expected_ustar")
    path = value.get("path")
    prefix = value.get("prefix")
    name = value.get("name")
    if not all(isinstance(item, str) for item in (path, prefix, name)):
        fail(f"{case.get('name')}.expected_ustar must contain string path, prefix, and name")
    if splits.get(path) != (prefix, name):
        fail(f"{case.get('name')} does not produce its expected ustar path split")


def verify_valid_case(case: dict[str, object], contract: dict[str, object]) -> None:
    entries, splits = validate_entries(expand_case(case), contract)
    check_expected_split(case, splits)
    archive = build_archive(canonical_records(entries, contract), contract)
    actual = hashlib.sha256(archive).hexdigest()
    expected = case.get("sha256")
    if expected != actual:
        fail(f"{case.get('name')} archive SHA-256 is {actual}, expected {expected}")


def verify_invalid_case(case: dict[str, object], contract: dict[str, object], codes: set[str]) -> None:
    expected = case.get("error")
    if not isinstance(expected, str) or expected not in codes:
        fail(f"{case.get('name')} has an unknown expected rejection code")
    try:
        entries, _ = validate_entries(expand_case(case), contract)
        canonical_records(entries, contract)
    except ContractViolationError as exc:
        if exc.code != expected:
            fail(f"{case.get('name')} returned {exc.code}, expected {expected}")
    else:
        fail(f"{case.get('name')} was unexpectedly accepted")


def verify_vectors(contract: dict[str, object], vectors: dict[str, object]) -> None:
    if vectors.get("version") != contract.get("version") or contract.get("version") != 1:
        fail("contract and vector versions must both be 1")
    raw_codes = require_list(contract.get("rejection_codes"), "contract.rejection_codes")
    if not all(isinstance(code, str) for code in raw_codes):
        fail("contract.rejection_codes must contain strings")
    codes = set(raw_codes)
    cases = require_list(vectors.get("cases"), "vectors.cases")
    names: set[str] = set()
    for index, raw in enumerate(cases):
        case = require_object(raw, f"vectors.cases[{index}]")
        name = case.get("name")
        valid = case.get("valid")
        if not isinstance(name, str) or not name or name in names or not isinstance(valid, bool):
            fail(f"vectors.cases[{index}] has an invalid or duplicate name/valid flag")
        names.add(name)
        if valid:
            verify_valid_case(case, contract)
        else:
            verify_invalid_case(case, contract, codes)


def manifest_rows() -> list[tuple[str, str]]:
    try:
        lines = (HERE / MANIFEST).read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        fail(f"{MANIFEST} cannot be read: {exc}")
    rows: list[tuple[str, str]] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None:
            fail(f"{MANIFEST} contains an invalid row")
        rows.append((match[2], match[1]))
    if [name for name, _ in rows] != sorted(AUTHORITY_FILES):
        fail(f"{MANIFEST} must list every authority file in sorted order")
    return rows


def verify_authority() -> None:
    for name, expected in manifest_rows():
        path = HERE / name
        if path.is_symlink() or not path.is_file():
            fail(f"{name} is missing, special, or symlinked")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            fail(f"{name} SHA-256 is {actual}, expected {expected}")


def sync_authority(target: Path) -> None:
    if target.resolve() == HERE:
        fail("sync target must differ from the authority directory")
    if target.is_symlink():
        fail("sync target may not be a symlink")
    target.mkdir(parents=True, exist_ok=True)
    allowed = {*AUTHORITY_FILES, MANIFEST}
    for child in target.iterdir():
        if child.name not in allowed or child.is_symlink() or not child.is_file():
            fail(f"sync target contains unknown or special entry: {child.name}")
    for name in sorted(allowed):
        destination = target / name
        if destination.is_symlink():
            fail(f"sync destination may not be a symlink: {name}")
        shutil.copyfile(HERE / name, destination)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sync", type=Path, metavar="DIRECTORY", help="copy the verified authority into DIRECTORY")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    verify_authority()
    contract = load_object(HERE / "contract.json")
    vectors = load_object(HERE / "vectors.json")
    validate_contract(contract)
    verify_vectors(contract, vectors)
    if args.sync is not None:
        sync_authority(args.sync)
        print(f"source-package v1 authority synchronized to {args.sync}")
        return
    print("source-package v1 authority and golden vectors are valid")


if __name__ == "__main__":
    main()
