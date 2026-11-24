#!/usr/bin/env python3
"""Verify that this public repository contains exactly its declared surface."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


GLOB_CHARACTERS = frozenset("*?[]")
UNEXPECTED_LINE_SEPARATORS = frozenset({"\v", "\f", "\r", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"})


class ManifestError(ValueError):
    """The public-surface manifest is malformed or unsafe."""


def parse_manifest(contents: str) -> tuple[str, ...]:
    """Parse exact repository-relative paths from a PUBLIC_SURFACE manifest."""
    entries: list[str] = []
    seen: set[str] = set()
    for index, character in enumerate(contents):
        if character in UNEXPECTED_LINE_SEPARATORS:
            line_number = contents.count("\n", 0, index) + 1
            raise ManifestError(f"line {line_number}: unexpected line separator")
    lines = contents.split("\n")
    if lines[-1] == "":
        lines.pop()
    for line_number, raw in enumerate(lines, start=1):
        if not raw:
            raise ManifestError(f"line {line_number}: blank entry")
        if raw != raw.strip():
            raise ManifestError(f"line {line_number}: leading or trailing whitespace")
        if any(ord(character) < 32 or ord(character) == 127 for character in raw):
            raise ManifestError(f"line {line_number}: control character in path")
        if "\\" in raw:
            raise ManifestError(f"line {line_number}: backslash is not allowed")
        if raw.endswith("/"):
            raise ManifestError(f"line {line_number}: directory entries are not allowed")
        if any(character in GLOB_CHARACTERS for character in raw):
            raise ManifestError(f"line {line_number}: glob syntax is not allowed")

        path = PurePosixPath(raw)
        if path.is_absolute() or raw == "." or path.as_posix() != raw:
            raise ManifestError(f"line {line_number}: path is not a canonical relative file")
        if any(component in {".", ".."} or component.casefold() == ".git" for component in path.parts):
            raise ManifestError(f"line {line_number}: unsafe path component")
        if raw in seen:
            raise ManifestError(f"line {line_number}: duplicate entry")
        entries.append(raw)
        seen.add(raw)

    if not entries:
        raise ManifestError("manifest has no entries")
    return tuple(entries)


def _tracked_path(record: bytes) -> str:
    """Decode and validate one path from a NUL-delimited index record."""
    try:
        path = record.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ManifestError("tracked entry path is not valid UTF-8") from error
    try:
        # Apply the same canonical, non-ambiguous path requirements as the
        # manifest.  This keeps an unusual index path from becoming an
        # implicit extension of the public surface.
        parse_manifest(f"{path}\n")
    except ManifestError as error:
        raise ManifestError("unsafe tracked entry path") from error
    return path


def _parse_index_records(output: bytes) -> tuple[tuple[str, str], ...]:
    """Parse strict ``git ls-files -s -z`` output into ``(oid, path)`` pairs."""
    if not output.endswith(b"\0"):
        raise ManifestError("malformed tracked-entry stream: missing NUL terminator")

    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for record in output[:-1].split(b"\0"):
        if not record:
            raise ManifestError("malformed tracked-entry stream: empty record")
        if record.count(b"\t") != 1:
            raise ManifestError("malformed tracked entry: expected one header/path separator")
        header, raw_path = record.split(b"\t", 1)
        fields = header.split(b" ")
        if len(fields) != 3 or any(not field for field in fields):
            raise ManifestError("malformed tracked entry header")
        mode, raw_oid, stage = fields
        if mode not in {b"100644", b"100755"}:
            try:
                display_mode = mode.decode("ascii")
            except UnicodeDecodeError:
                display_mode = repr(mode)
            raise ManifestError(f"non-regular tracked entry (mode {display_mode})")
        if stage != b"0":
            raise ManifestError("stage-conflicted tracked entry")
        if len(raw_oid) not in {40, 64} or any(byte not in b"0123456789abcdef" for byte in raw_oid):
            raise ManifestError("malformed tracked entry object ID")

        path = _tracked_path(raw_path)
        if path in seen:
            raise ManifestError("duplicate tracked entry")
        seen.add(path)
        entries.append((raw_oid.decode("ascii"), path))
    return tuple(entries)


def tracked_files(root: Path) -> tuple[str, ...]:
    """Return the exact safe set of regular blob paths tracked in *root*."""
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-s", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    entries = _parse_index_records(completed.stdout)
    for object_id, _ in entries:
        object_type = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-t", object_id],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if object_type.returncode or object_type.stdout != b"blob\n":
            raise ManifestError("tracked entry object is not a blob")
    return tuple(path for _, path in entries)


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    try:
        expected = parse_manifest((root / "PUBLIC_SURFACE").read_bytes().decode("utf-8"))
        actual = tracked_files(root)
        specification = (root / "docs/zkm_specification.md").read_text(encoding="utf-8")
        references = re.findall(r"\[`docs/zkm_nonfinancial_profiles\.md`\]\(([^)]+)\)", specification)
        if references != ["zkm_nonfinancial_profiles.md", "zkm_nonfinancial_profiles.md"]:
            raise ManifestError("public specification companion references differ from reviewed paths")
        framework = (root / "docs/zkm_nonfinancial_profiles.md").read_text(encoding="utf-8")
        if re.findall(r"\]\(([^)]+)\)", framework) != ["zkm_specification.md"]:
            raise ManifestError("public framework links differ from reviewed snapshot scope")
    except ManifestError as error:
        print(f"PUBLIC_SURFACE invalid: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError, subprocess.SubprocessError):
        print("PUBLIC_SURFACE validation failed: repository inspection error", file=sys.stderr)
        return 1

    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        if missing:
            print(f"PUBLIC_SURFACE missing tracked file count: {len(missing)}", file=sys.stderr)
        if unexpected:
            print(
                f"PUBLIC_SURFACE unexpected tracked file count: {len(unexpected)}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
