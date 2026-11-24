#!/usr/bin/env python3
"""Offline, fail-closed license and dependency identity gate for ZKM sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


class CheckFailure(Exception):
    """A deliberately non-sensitive verification failure."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_digest(root: Path) -> str:
    """Match the reviewed digest format: sorted sha256/path records."""

    if not root.is_dir():
        raise CheckFailure("required dependency directory is unavailable")
    records: list[tuple[str, str]] = []
    for directory, names, files in os.walk(root, topdown=True):
        current = Path(directory)
        names[:] = sorted(name for name in names if name not in {".git", "target", ".DS_Store"})
        for name in sorted(files):
            if name == ".DS_Store":
                continue
            path = current / name
            if not path.is_file() or path.is_symlink():
                continue
            relative = "./" + path.relative_to(root).as_posix()
            records.append((relative, sha256_file(path)))
    if not records:
        raise CheckFailure("required dependency directory contains no regular files")
    contents = b"".join(f"{digest}  {relative}\n".encode("ascii") for relative, digest in sorted(records))
    return hashlib.sha256(contents).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def load_lock(path: Path) -> dict[str, Any]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CheckFailure("license lock is missing or invalid") from error
    require(isinstance(lock, dict), "license lock has an invalid top-level value")
    require(lock.get("schema") == "zkm:third-party-license-lock:v1", "license lock schema is unsupported")
    require(isinstance(lock.get("first_party"), dict), "license lock first-party section is invalid")
    require(isinstance(lock.get("dependencies"), list), "license lock dependency section is invalid")
    return lock


def nargo_declarations(root: Path) -> dict[tuple[str, str, str, str], set[str]]:
    declarations: dict[tuple[str, str, str, str], set[str]] = {}
    for manifest in sorted(root.rglob("Nargo.toml")):
        if any(part in {".git", "target"} for part in manifest.parts):
            continue
        relative = manifest.relative_to(root).as_posix()
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise CheckFailure("a Nargo manifest is unreadable or invalid") from error
        dependencies = data.get("dependencies", {})
        require(isinstance(dependencies, dict), "a Nargo manifest has an invalid dependency table")
        for dependency, spec in dependencies.items():
            if isinstance(spec, str):
                raise CheckFailure("a Nargo dependency uses an unsupported declaration")
            require(isinstance(spec, dict), "a Nargo dependency uses an invalid declaration")
            if "path" in spec:
                require(set(spec) == {"path"}, "a local Nargo dependency has unexpected fields")
                continue
            git = spec.get("git")
            tag = spec.get("tag")
            directory = spec.get("directory", "")
            require(isinstance(git, str) and isinstance(tag, str) and isinstance(directory, str), "an external Nargo dependency is incomplete")
            require(set(spec) <= {"git", "tag", "directory"}, "an external Nargo dependency has unsupported fields")
            declarations.setdefault((dependency, git, tag, directory), set()).add(relative)
    return declarations


EVIDENCE_ALLOWED = {
    "noir-lang/sha256": {
        "kind": "upstream-later-revision",
        "repository": "https://github.com/noir-lang/sha256",
        "commit": "50f5fda729d94848aabcd9d54dc7751460e9143a",
    },
}
EVIDENCE_KEYS = {
    "kind", "repository", "commit", "path", "blob", "sha256",
    "vendored_copy", "accepted_by", "accepted_on", "rationale",
}


def is_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def check_license_evidence(root: Path, dependency_id: str, evidence: Any) -> None:
    expected = EVIDENCE_ALLOWED.get(dependency_id)
    require(expected is not None, f"license evidence is not permitted for: {dependency_id}")
    require(isinstance(evidence, dict) and set(evidence) == EVIDENCE_KEYS, "license evidence has unexpected or missing fields")
    for key, value in expected.items():
        require(evidence.get(key) == value, f"license evidence {key} does not match the reviewed value")
    require(is_hex(evidence["commit"], 40) and is_hex(evidence["blob"], 40), "license evidence has an invalid git identifier")
    require(is_hex(evidence["sha256"], 64), "license evidence has an invalid digest")
    require(all(isinstance(evidence[key], str) and evidence[key] for key in ("path", "accepted_by", "accepted_on", "rationale")),
            "license evidence has an invalid text field")
    copy = evidence["vendored_copy"]
    require(isinstance(copy, str) and copy, "license evidence has no vendored copy")
    relative = Path(copy)
    require(not relative.is_absolute() and ".." not in relative.parts, "license evidence vendored copy path is unsafe")
    path = root / relative
    require(path.resolve().is_relative_to(root.resolve()), "license evidence vendored copy escapes the root")
    require(path.is_file() and not path.is_symlink(), "license evidence vendored copy is not a regular file")
    require(sha256_file(path) == evidence["sha256"], "license evidence vendored copy does not match the reviewed digest")
    data = path.read_bytes()
    blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    require(blob == evidence["blob"], "license evidence vendored copy does not match the upstream git blob")


def static_check(root: Path, lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    first_party = lock["first_party"]
    require(set(first_party) == {"LICENSE", "NOTICE"}, "license lock first-party inventory is incomplete")
    for name, expected in first_party.items():
        require(isinstance(expected, str) and len(expected) == 64, "license lock contains an invalid first-party digest")
        path = root / name
        require(path.is_file() and sha256_file(path) == expected, "first-party license material does not match the reviewed lock")

    dependencies = lock["dependencies"]
    indexed: dict[str, dict[str, Any]] = {}
    for entry in dependencies:
        require(isinstance(entry, dict) and isinstance(entry.get("id"), str), "license lock contains an invalid dependency entry")
        dependency_id = entry["id"]
        require(dependency_id not in indexed, "license lock contains duplicate dependency entries")
        require(entry.get("license_status") != "unresolved", f"unresolved license material: {dependency_id}")
        require(entry.get("spdx") in {"Apache-2.0", "MIT OR Apache-2.0"}, "license lock contains a non-approved SPDX expression")
        require(isinstance(entry.get("licenses"), dict), "license lock has no license-file inventory")
        if "license_evidence" in entry:
            check_license_evidence(root, dependency_id, entry["license_evidence"])
        else:
            require(entry["licenses"], "license lock has no license-file inventory")
        require(all(isinstance(value, str) and len(value) == 64 for value in entry["licenses"].values()), "license lock contains an invalid license digest")
        indexed[dependency_id] = entry

    expected_nargo = {
        ("sha256", "https://github.com/noir-lang/sha256", "v0.3.0", ""): ("noir-lang/sha256", {"aztec/vendor/zka/aztec/zka_aztec_lib/Nargo.toml"}),
        ("poseidon", "https://github.com/noir-lang/poseidon", "v0.3.0", ""): ("noir-lang/poseidon", {"noir/zkm_lib/Nargo.toml", "aztec/vendor/zka/noir/zka_lib/Nargo.toml"}),
        ("aztec", "https://github.com/aztec-labs-eng/aztec-nr", "v6.0.0", "aztec"): (
            "aztec-labs-eng/aztec-nr",
            {
                "aztec/zkm_aztec_lib/Nargo.toml", "aztec/zkm_mandate_aztec/Nargo.toml",
                *{f"aztec/vendor/zka/aztec/{name}/Nargo.toml" for name in (
                    "zka_authwit_test_proxy", "zka_aztec_lib", "zka_credential_aztec", "zka_transfer_aztec"
                )},
            },
        ),
    }
    observed_nargo = nargo_declarations(root)
    require(set(observed_nargo) == set(expected_nargo), "external Nargo dependency inventory does not match the reviewed lock")
    for key, (dependency_id, declaration_paths) in expected_nargo.items():
        entry = indexed.get(dependency_id)
        require(entry is not None and entry.get("kind") == "nargo-git", "external Nargo dependency is absent from the reviewed lock")
        require(entry.get("git") == key[1] and entry.get("tag") == key[2] and set(entry.get("declarations", [])) == declaration_paths, "external Nargo dependency declaration drifted")
        require(observed_nargo[key] == declaration_paths, "external Nargo dependency use drifted")
        require(isinstance(entry.get("commit"), str) and len(entry["commit"]) == 40, "external Nargo dependency is not commit-bound")
        require(isinstance(entry.get("source_sha256"), str) and len(entry["source_sha256"]) == 64, "external Nargo dependency has no source digest")

    try:
        soldeer = tomllib.loads((root / "soldeer.lock").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CheckFailure("Soldeer lock is missing or invalid") from error
    entries = soldeer.get("dependencies")
    require(isinstance(entries, list) and len(entries) == 1 and isinstance(entries[0], dict), "Soldeer dependency inventory does not match the reviewed lock")
    forge = indexed.get("forge-std")
    require(forge is not None and forge.get("kind") == "soldeer", "Soldeer dependency is absent from the reviewed lock")
    observed = entries[0]
    require(
        observed == {
            "name": "forge-std",
            "version": forge.get("version"),
            "url": forge.get("url"),
            "checksum": forge.get("archive_sha256"),
            "integrity": forge.get("integrity"),
        },
        "Soldeer dependency declaration drifted",
    )
    require(set(forge.get("declarations", [])) == {"soldeer.lock"}, "Soldeer declaration inventory drifted")
    require(
        set(indexed)
        == {"AztecProtocol/aztec-packages", "noir-lang/sha256", "noir-lang/poseidon-v0.4.0", "noir-lang/poseidon", "forge-std", "aztec-labs-eng/aztec-nr", "pyramidal-io/ZKA.dev"},
        "license lock contains an unreferenced dependency",
    )
    vendored = indexed["pyramidal-io/ZKA.dev"]
    require(vendored.get("kind") == "vendored" and vendored.get("path") == "aztec/vendor/zka",
            "ZKA must use the reviewed local snapshot")
    require(set(vendored.get("declarations", [])) == {"aztec/zkm_mandate_aztec/Nargo.toml"},
            "vendored ZKA declaration inventory drifted")
    golden = dict(line.split("=", 1) for line in
                  (root / "aztec/scripts/zka-main.source.sha256").read_text().splitlines())
    require(all(vendored.get(key) == golden[key] for key in ("commit", "tree", "source_sha256")),
            "vendored ZKA provenance drifted")
    verified = subprocess.run(["bash", str(root / "aztec/scripts/check-zka-source-integrity.sh")],
                              capture_output=True, check=False)
    require(verified.returncode == 0, "vendored ZKA source integrity failed")
    runtime_check(root / vendored["path"], vendored)
    return indexed


def runtime_check(directory: Path, entry: dict[str, Any]) -> None:
    if "source_sha256" in entry:
        require(source_digest(directory) == entry["source_sha256"], "dependency source does not match the reviewed digest")
    for relative, expected in entry["licenses"].items():
        path = directory / relative
        require(path.is_file() and sha256_file(path) == expected, "dependency license bytes do not match the reviewed lock")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--profile", choices=("static", "noir-solidity", "aztec"), default="static")
    parser.add_argument("--poseidon-dir", type=Path)
    parser.add_argument("--forge-std-dir", type=Path)
    parser.add_argument("--aztec-dir", type=Path)
    parser.add_argument("--zka-dir", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        root = args.root.resolve()
        lock_path = args.lock or root / "THIRD_PARTY_LICENSES.json"
        entries = static_check(root, load_lock(lock_path))
        if args.profile == "noir-solidity":
            require(args.poseidon_dir is not None and args.forge_std_dir is not None, "noir-solidity profile requires both dependency directories")
            runtime_check(args.poseidon_dir, entries["noir-lang/poseidon"])
            runtime_check(args.forge_std_dir, entries["forge-std"])
        elif args.profile == "aztec":
            require(
                args.aztec_dir is not None,
                "aztec profile requires the Aztec dependency directory",
            )
            runtime_check(args.aztec_dir, entries["aztec-labs-eng/aztec-nr"])
            for repo, tag, entry_id in (
                ("AztecProtocol/aztec-packages", "v6.0.0", "AztecProtocol/aztec-packages"),
                ("noir-lang/poseidon", "v0.4.0", "noir-lang/poseidon-v0.4.0"),
                ("noir-lang/sha256", "v0.3.0", "noir-lang/sha256"),
            ):
                runtime_check(Path.home() / "nargo/github.com" / repo / tag, entries[entry_id])
            if args.zka_dir is not None:
                require(args.zka_dir.resolve() == (root / "aztec/vendor/zka").resolve(),
                        "ZKA directory must be the verified local snapshot")
    except (CheckFailure, OSError, ValueError, KeyError) as error:
        print(f"third-party license check failed: {error}", file=sys.stderr)
        return 1
    print(f"third-party license check passed ({args.profile})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
