#!/usr/bin/env python3
"""Generate the current ZKM public-input encoder documents from the registry."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_RELATIVE = Path("protocol-family/zkm-statement-registry-v1.json")
ENCODERS_RELATIVE = Path("schemas/public-inputs")
SCALAR_TYPES = {"Field", "bool", "u8", "u16", "u32", "u64", "u128"}


def expected_documents(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return one declarative encoder for each current statement, without I/O."""
    if not isinstance(registry, dict):
        raise ValueError("statement registry must be an object")
    statement_set = registry.get("statement_set_id")
    if not isinstance(statement_set, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", statement_set):
        raise ValueError("invalid statement_set_id")
    toolchain = registry.get("toolchain")
    if not isinstance(toolchain, dict) or set(toolchain) != {"nargo", "barretenberg"}:
        raise ValueError("encoder requires the pinned nargo and barretenberg toolchain")
    if any(not isinstance(value, str) or not value for value in toolchain.values()):
        raise ValueError("invalid toolchain pin")
    statements = registry.get("statements")
    if not isinstance(statements, list) or not statements:
        raise ValueError("registry has no current statements")
    result: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()
    seen_keys: set[str] = set()
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("status") != "current":
            raise ValueError("encoder inventory may contain only current statements")
        identifier, package = statement.get("id"), statement.get("circuit_package")
        if not isinstance(identifier, str) or not re.fullmatch(r"zkm:[a-z0-9-]+:v[1-9][0-9]*", identifier):
            raise ValueError("invalid statement identifier")
        if not isinstance(package, str) or not re.fullmatch(r"zkm_[a-z0-9_]+", package):
            raise ValueError("invalid circuit package")
        filename = f"{package}.json"
        if identifier in seen_ids or filename in result:
            raise ValueError("duplicate statement or circuit package")
        seen_ids.add(identifier)
        vk_hash = statement.get("vk_hash")
        if not isinstance(vk_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", vk_hash):
            raise ValueError(f"{identifier}: invalid default-target vk_hash")
        if vk_hash in seen_keys:
            raise ValueError("distinct statements must not share a verification key")
        seen_keys.add(vk_hash)
        inputs = statement.get("public_inputs")
        if not isinstance(inputs, list) or not inputs:
            raise ValueError(f"{identifier}: missing public inputs")
        if type(statement.get("public_input_count")) is not int or statement["public_input_count"] != len(inputs):
            raise ValueError(f"{identifier}: public input count differs from scalar vector")
        fields: list[dict[str, Any]] = []
        names: set[str] = set()
        for index, item in enumerate(inputs):
            if not isinstance(item, dict) or type(item.get("index")) is not int or item["index"] != index:
                raise ValueError(f"{identifier}: public input indices must be contiguous declaration order")
            name, abi_type = item.get("name"), item.get("abi_type")
            if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", name) or name in names:
                raise ValueError(f"{identifier}: invalid or duplicate snake_case public input name")
            if not isinstance(abi_type, str) or abi_type not in SCALAR_TYPES:
                raise ValueError(f"{identifier}: unsupported ABI type {abi_type!r}; review encoding before extension")
            names.add(name)
            fields.append({"index": index, "offset": index, "name": name, "abiType": abi_type, "fieldElements": 1})
        result[filename] = {
            "version": "zkm:public-inputs:v1",
            "circuit": package,
            "statement": identifier,
            "statementSetId": statement_set,
            "vkIdentifier": {"scheme": "ultra_honk", "transcript_target": "noir-recursive", "vk_hash": "0x" + vk_hash},
            "toolchain": dict(toolchain),
            "proofSystem": "ultra_honk",
            "curve": "BN254",
            "encoding": {
                "fieldElement": "Canonical BN254 scalar field element as 32-byte big-endian; reject out-of-field values without reduction",
                "jsonValue": "Lowercase 0x-prefixed 64-hex-character string for every public input, including booleans and integers",
                "order": f"Declaration order of pub parameters in noir/{package}/src/main.nr main(); never sort object keys to flatten",
                "names": "Exact registry/Noir snake_case names; reject missing, extra, duplicate or alias members",
                "booleans": "false = 0, true = 1; reject other decoded values",
                "integers": "Unsigned integers are zero-extended into one field element; reject values outside the abiType range",
            },
            "totalFieldElements": len(fields),
            "publicInputs": fields,
        }
    return result


def render_document(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def load_registry(root: Path) -> dict[str, Any]:
    return json.loads((root / REGISTRY_RELATIVE).read_text(encoding="utf-8"))


def encoder_directory(root: Path) -> Path:
    directory = root / ENCODERS_RELATIVE
    if directory.parent.is_symlink() or directory.is_symlink():
        raise ValueError("encoder directory must not be a symlink")
    return directory


def check_inventory(directory: Path, expected: dict[str, dict[str, Any]]) -> None:
    actual = {path.name for path in directory.glob("*.json")}
    extra = actual - expected.keys()
    if extra:
        raise ValueError("unexpected encoder documents: " + ", ".join(sorted(extra)))


def check_encoders(root: Path, registry: dict[str, Any] | None = None) -> None:
    expected = expected_documents(load_registry(root) if registry is None else registry)
    directory = encoder_directory(root)
    check_inventory(directory, expected)
    for filename, document in expected.items():
        path = directory / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or non-regular encoder document: {filename}")
        if path.read_bytes() != render_document(document):
            raise ValueError(f"stale encoder document: {filename}; regenerate with scripts/generate_zkm_public_input_encoders.py --write")


def write_encoders(root: Path, registry: dict[str, Any] | None = None) -> None:
    expected = expected_documents(load_registry(root) if registry is None else registry)
    directory = encoder_directory(root)
    check_inventory(directory, expected)
    for filename in expected:
        path = directory / filename
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError(f"non-regular encoder destination: {filename}")
    directory.mkdir(parents=True, exist_ok=True)
    for filename, document in expected.items():
        (directory / filename).write_bytes(render_document(document))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="check exact encoder bytes and inventory without writing")
    mode.add_argument("--write", action="store_true", help="regenerate the current encoder documents (the default)")
    args = parser.parse_args(argv)
    try:
        if args.check:
            check_encoders(ROOT)
        else:
            write_encoders(ROOT)
    except (ValueError, OSError) as error:
        print(f"ZKM public-input encoders FAILED: {error}", file=sys.stderr)
        return 1
    print("ZKM public-input encoders: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
