#!/usr/bin/env python3
"""Fail-closed checks for the ZKM statement/verification-key registry.

WHY THIS EXISTS
===============
ZKM's spec version is `0.1.0-draft` for every revision, including the breaking
rev 10 (both v1 transition statements retired, public vectors regrown 13 -> 14
and 8 -> 9, revocation tree replaced, every verification key re-blessed). Family
epoch zka:protocol-family:2026-08-15.1 addressed that by pinning ZKM as
`protocols.zkm.version = "0.1.0-draft (rev 10)"` -- version plus revision label.

Two gaps survive that fix:

  1. the label is prose. It pins a revision NAME, not a verification key, a
     public-input vector, a bytecode digest or a toolchain -- all of which can
     move within a revision without moving anything the epoch pins; and
  2. nothing in the manifest compels a LATER breaking revision to advance the
     label: the epoch's revision assertion is satisfied by rev 10's changelog
     row, which is historical and stays true forever.

`protocol-family/zkm-statement-registry-v1.json` closes both: a ZKM-owned file
whose sha256 (and whose `statement_set_id`) moves whenever the statement/ABI/VK
surface moves. This script is what makes that promise true rather than
aspirational -- it re-derives the registry's claims from their sources on every
CI run:

  * verification keys, opcode counts and bytecode digests from the blessed
    structural goldens (`noir/scripts/goldens/circuits.txt`);
  * public-input vectors from each circuit's own `fn main` declaration order;
  * the toolchain pins from `.noir-version` (VK hashes are toolchain-bound);
  * statement identifiers from the specification's own §5 enumeration;
  * the family epoch, the declared `protocols.zkm` version and its revision
    label from the scanner-clean projected family manifest -- the label must be neither
    ahead of the revision ZKM has published nor behind `last_breaking_revision`;
  * `statement_set_id` recomputed from the security-relevant projection, and
    the revision history's breaking/non-breaking classification checked
    against it.

Everything it needs is a checked-in file, so it runs in the cheap tier of the
gate -- no nargo, no bb, no proving.

NOTE ON PUBLIC SNAPSHOT GATE WIRING: this script deliberately does NOT assert
its own step in the workflow. A check that guards its own wiring is vacuous the
moment the step is deleted. The public snapshot runs this checker directly; its
scanner-clean surface intentionally omits the standalone AFP-KDC fixture and
the private checker that verifies that fixture.

Usage:
    python3 scripts/check-zkm-statement-registry.py
    python3 scripts/check-zkm-statement-registry.py --self-test
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from validate_protocol_family import pending_republish_from_lock
from generate_zkm_public_input_encoders import check_encoders


REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = REPO_ROOT / "protocol-family/zkm-statement-registry-v1.json"
GOLDENS_PATH = REPO_ROOT / "noir/scripts/goldens/circuits.txt"
NOIR_VERSION_PATH = REPO_ROOT / ".noir-version"
SPEC_PATH = REPO_ROOT / "docs/zkm_specification.md"
CUTOVER_PATH = REPO_ROOT / "docs/zkm_v1_to_v2_cutover.md"
MANIFEST_PATH = REPO_ROOT / "protocol-family/interface-manifest-v1.json"
SNAPSHOT_LOCK_PATH = REPO_ROOT / "protocol-family/snapshot-lock.json"

REGISTRY_FORMAT = "zkm:statement-registry:v1"
STATEMENT_SET_DOMAIN = b"zkm:statement-set:v1"

# The canonical family package reserves these paths. This scanner-clean public
# snapshot projects its manifest and lock while retaining the schema, vectors,
# and validator as selected source bytes. The ZKM-owned registry must not
# claim a canonical-family path as its own authority path.
CANONICAL_FAMILY_PATHS = frozenset(
    {
        "protocol-family/interface-manifest-v1.json",
        "protocol-family/interface-manifest-v1.schema.json",
        "protocol-family/golden-vectors-v1.json",
        "protocol-family/snapshot-lock.json",
        "scripts/validate_protocol_family.py",
    }
)

# Fields of a statement entry that the statement_set_id commits to. Prose
# (`note`) is deliberately excluded: an editorial edit is not a protocol
# change, and an id that moved on prose would train reviewers to re-bless it.
STATEMENT_ID_FIELDS = (
    "id",
    "circuit_package",
    "status",
    "current_since_revision",
    "supersedes",
    "value_moving",
    "public_input_count",
    "public_inputs",
    "vk_hash",
    "acir_opcode_count",
    "bytecode_sha256",
)
RETIRED_ID_FIELDS = (
    "id",
    "retired_in_revision",
    "superseded_by",
    "public_input_count",
    "post_cutover_registry",
    "reinterpretation",
)
REVOCATION_ID_FIELDS = (
    "scheme",
    "construction",
    "depth",
    "accepted_scheme_values",
    "superseded_scheme",
)
EXPECTED_CONSUMER_COMMANDS = (
    "python3 scripts/check-zkm-statement-registry.py",
    "python3 scripts/validate_protocol_family.py validate --repo zkm --root .",
    "python3 scripts/migrate-revocation-v2.py --self-test",
    "bash noir/scripts/check-circuit-goldens.sh",
)
EXPECTED_AUTHORITY_PATHS = {
    "registry_path": "protocol-family/zkm-statement-registry-v1.json",
    "specification_path": "docs/zkm_specification.md",
    "cutover_note_path": "docs/zkm_v1_to_v2_cutover.md",
    "goldens_path": "noir/scripts/goldens/circuits.txt",
    "validator_path": "scripts/check-zkm-statement-registry.py",
}


class Failure(AssertionError):
    """One deterministic registry conformance failure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def normalize(text: str) -> str:
    """Collapse whitespace so line-wrapped prose can be substring-matched."""

    return re.sub(r"\s+", " ", text)


def canonical_json(document: Any) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def project(entry: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: entry.get(field) for field in fields}


def statement_set_id(registry: dict[str, Any]) -> str:
    """Re-derive the security-relevant identity of the statement surface."""

    preimage = {
        "statements": [
            project(entry, STATEMENT_ID_FIELDS) for entry in registry.get("statements", [])
        ],
        "retired_statements": [
            project(entry, RETIRED_ID_FIELDS)
            for entry in registry.get("retired_statements", [])
        ],
        "revocation": project(registry.get("revocation", {}), REVOCATION_ID_FIELDS),
        "toolchain": registry.get("toolchain", {}),
    }
    digest = hashlib.sha256(
        STATEMENT_SET_DOMAIN + canonical_json(preimage).encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def parse_goldens(text: str) -> dict[str, dict[str, Any]]:
    """Parse the blessed structural goldens into package -> values."""

    rows: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("package|"):
            continue
        fields = line.split("|")
        require(len(fields) == 5, f"malformed golden row: {line!r}")
        package, vk_hash, public_inputs, opcodes, bytecode = fields
        require(package not in rows, f"duplicate golden row for {package}")
        rows[package] = {
            "vk_hash": vk_hash,
            "public_input_count": int(public_inputs),
            "acir_opcode_count": int(opcodes),
            "bytecode_sha256": bytecode,
        }
    require(bool(rows), "no golden rows parsed")
    return rows


def mask_noir_comments_and_strings(source: str) -> str:
    """Preserve offsets while removing comments and quoted text from Noir."""

    result = list(source)
    index = 0
    block_depth = 0
    line_comment = False
    in_string = False
    escaped = False
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            else:
                result[index] = " "
        elif block_depth:
            if char == "/" and following == "*":
                result[index] = result[index + 1] = " "
                block_depth += 1
                index += 1
            elif char == "*" and following == "/":
                result[index] = result[index + 1] = " "
                block_depth -= 1
                index += 1
            elif char != "\n":
                result[index] = " "
        elif in_string:
            if char != "\n":
                result[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            result[index] = " "
            in_string = True
        elif char == "/" and following == "/":
            result[index] = result[index + 1] = " "
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            result[index] = result[index + 1] = " "
            block_depth = 1
            index += 1
        index += 1
    require(block_depth == 0 and not in_string, "Noir source has an unterminated comment or string")
    return "".join(result)


def parse_public_inputs(source: str, package: str) -> list[dict[str, str]]:
    """Extract all public `main` ABI slots, including public return values."""

    # Comments are not part of the Noir signature. In particular, a commented
    # `fn main` or `-> pub Field` must not affect the parser's result.
    clean = mask_noir_comments_and_strings(source)
    declarations = list(re.finditer(r"\bfn\s+main\s*\(", clean))
    require(len(declarations) == 1, f"{package}: expected exactly one `fn main(` declaration")
    start = declarations[0].end()
    depth = 1
    end = start
    while end < len(clean) and depth:
        if clean[end] == "(":
            depth += 1
        elif clean[end] == ")":
            depth -= 1
        end += 1
    require(depth == 0, f"{package}: unterminated `fn main(` signature")
    signature = clean[start : end - 1]
    tail = re.match(r"\s*(?:->\s*(?P<returns>[^{}]+?))?\s*\{", clean[end:])
    require(tail is not None, f"{package}: unsupported `fn main` return signature")

    parameters: list[dict[str, str]] = []
    for line in signature.splitlines():
        if re.search(r"\bpub\b", line) is None:
            continue
        match = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*:\s*pub\s+([A-Za-z_]\w*)\s*,?\s*", line)
        require(match is not None, f"{package}: unsupported public `fn main` parameter: {line.strip()!r}")
        parameters.append({"name": match.group(1), "abi_type": match.group(2)})
    require(bool(parameters), f"{package}: no public parameters found in `fn main`")

    returns = tail.group("returns") or ""
    if re.search(r"\bpub\b", returns):
        return_types = re.findall(r"\bpub\s+([A-Za-z_]\w*)\b", returns)
        require(return_types, f"{package}: unsupported public `fn main` return type")
        for index, abi_type in enumerate(return_types):
            parameters.append({"name": f"$return_{index}", "abi_type": abi_type})
    return parameters


def parse_noir_version(text: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\s*(NARGO_VERSION|BB_VERSION)=(\S+)\s*$", line)
        if match is not None:
            pins[match.group(1)] = match.group(2)
    require("NARGO_VERSION" in pins, ".noir-version does not set NARGO_VERSION")
    require("BB_VERSION" in pins, ".noir-version does not set BB_VERSION")
    return pins


def cutover_table(text: str, header: tuple[str, ...]) -> list[tuple[str, ...]]:
    """Read exactly one named Markdown table from the normative cutover note."""

    lines = text.splitlines()
    heading = "| " + " | ".join(header) + " |"
    locations = [
        index
        for index, line in enumerate(lines)
        if line.startswith("|")
        and tuple(cell.strip() for cell in line.strip().strip("|").split("|")) == header
    ]
    require(len(locations) == 1, f"cutover note: expected exactly one {heading!r} table")
    start = locations[0]
    require(
        start + 1 < len(lines)
        and re.fullmatch(r"\|(?:\s*:?-+:?\s*\|){%d}" % len(header), lines[start + 1]),
        f"cutover note: malformed separator under {heading!r}",
    )
    rows: list[tuple[str, ...]] = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        cells = tuple(cell.strip() for cell in line.strip().strip("|").split("|"))
        require(len(cells) == len(header), f"cutover note: malformed row in {heading!r}")
        rows.append(cells)
    require(bool(rows), f"cutover note: empty {heading!r} table")
    return rows


def code_cell(value: str) -> str:
    require(value.startswith("`") and value.endswith("`"), f"expected code cell, got {value!r}")
    return value[1:-1]


def cutover_current_rows(text: str) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for identifier, package, count, vk_hash, moving in cutover_table(
        text,
        ("Statement", "Circuit package", "Public inputs", "Verification-key hash", "Value-moving"),
    ):
        statement_id = code_cell(identifier)
        require(statement_id not in rows, f"cutover note: duplicate statement {statement_id}")
        require(count.isdecimal(), f"cutover note: invalid input count for {statement_id}")
        require(moving in {"**yes**", "no"}, f"cutover note: invalid value-moving cell for {statement_id}")
        rows[statement_id] = {
            "circuit_package": code_cell(package),
            "public_input_count": int(count),
            "vk_hash": code_cell(vk_hash),
            "value_moving": moving == "**yes**",
        }
    return rows


def cutover_lifecycle_rows(text: str) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for identifier, since, predecessor in cutover_table(
        text, ("Statement", "Current since revision", "Supersedes")
    ):
        statement_id = code_cell(identifier)
        require(statement_id not in rows, f"cutover note: duplicate lifecycle {statement_id}")
        require(since.isdecimal(), f"cutover note: invalid current revision for {statement_id}")
        rows[statement_id] = {
            "current_since_revision": int(since),
            "supersedes": None if predecessor == "—" else code_cell(predecessor),
        }
    return rows


def cutover_retired_rows(text: str) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for identifier, retired, successor, count in cutover_table(
        text, ("Retired statement", "Retired in revision", "Superseded by", "Public inputs")
    ):
        statement_id = code_cell(identifier)
        require(statement_id not in rows, f"cutover note: duplicate retired {statement_id}")
        require(retired.isdecimal() and count.isdecimal(), f"cutover note: invalid retired metadata for {statement_id}")
        rows[statement_id] = {
            "retired_in_revision": int(retired),
            "superseded_by": code_cell(successor),
            "public_input_count": int(count),
        }
    return rows


def specification_statement_ids(spec: str) -> set[str]:
    """Take the closed §5 envelope discriminator, not incidental prose IDs."""

    section_start = re.search(r"^## 5\. Authorization Predicate and Proofs\s*$", spec, re.MULTILINE)
    require(section_start is not None, "specification: missing §5 heading")
    section_end = re.search(r"^## 6\. ", spec[section_start.end() :], re.MULTILINE)
    require(section_end is not None, "specification: missing §6 boundary")
    section = normalize(spec[section_start.end() : section_start.end() + section_end.start()])
    require(
        section.count("**Envelope: `zkm:proof:v1`**") == 1,
        "specification: expected one §5 envelope enumeration",
    )
    match = re.search(
        r"`statement` discriminator naming which proof form the envelope carries "
        r"\((?P<identifiers>.*?)\) — the ZKM analogue",
        section,
        flags=re.DOTALL,
    )
    require(match is not None, "specification: malformed §5 statement enumeration")
    enumeration = match.group("identifiers")
    identifiers = re.findall(r"`(zkm:[^`]+)`", enumeration)
    residue = re.sub(r"`zkm:[^`]+`|\s|\|", "", enumeration)
    require(not residue and len(identifiers) == len(set(identifiers)), "specification: invalid §5 statement enumeration")
    return set(identifiers)


def load_sources() -> dict[str, Any]:
    """Load every source of truth the registry's claims are re-derived from."""

    registry_bytes = REGISTRY_PATH.read_bytes()
    manifest = json.loads(MANIFEST_PATH.read_bytes())
    snapshot_lock = json.loads(SNAPSHOT_LOCK_PATH.read_bytes())
    pending_republish, pending_errors = pending_republish_from_lock(
        SNAPSHOT_LOCK_PATH,
        snapshot_lock,
        manifest,
    )
    staged_manifest_assertions = {
        assertion.get("id"): copy.deepcopy(assertion)
        for assertion in manifest.get("projections", {}).get("zkm", {}).get(
            "assertions", []
        )
        if isinstance(assertion, dict)
    }
    packages = sorted(
        path.parent.parent.name for path in REPO_ROOT.glob("noir/*/src/main.nr")
    )
    return {
        "registry_sha256": "sha256:" + hashlib.sha256(registry_bytes).hexdigest(),
        "goldens": GOLDENS_PATH.read_text(encoding="utf-8"),
        "noir_version": NOIR_VERSION_PATH.read_text(encoding="utf-8"),
        "spec": SPEC_PATH.read_text(encoding="utf-8"),
        "cutover": CUTOVER_PATH.read_text(encoding="utf-8"),
        "manifest": manifest,
        "pending_republish": pending_republish,
        "pending_republish_errors": [str(error) for error in pending_errors],
        "staged_manifest_assertions": staged_manifest_assertions,
        "circuits": {
            package: (REPO_ROOT / "noir" / package / "src/main.nr").read_text(
                encoding="utf-8"
            )
            for package in packages
        },
    }


def active_staged_projection(
    sources: dict[str, Any],
    *,
    assertion_id: str,
    path: str,
    pointer: str,
    observed_value: Any,
) -> bool:
    """Return whether the active family marker authorizes one exact value.

    `pending_republish_from_lock` validates the marker's closed shape, expiry,
    staging digest, epoch transition, and assertion identity against the
    family manifest. This final comparison keeps the ZKM-owned checker bound
    to the exact registry field it is about to defer.
    """

    if sources.get("pending_republish_errors"):
        return False
    pending = sources.get("pending_republish")
    if not isinstance(pending, dict) or not pending.get("staging_commit"):
        return False
    current_assertions = [
        assertion
        for assertion in sources["manifest"]
        .get("projections", {})
        .get("zkm", {})
        .get("assertions", [])
        if isinstance(assertion, dict) and assertion.get("id") == assertion_id
    ]
    frozen_assertion = sources.get("staged_manifest_assertions", {}).get(assertion_id)
    if len(current_assertions) != 1 or current_assertions[0] != frozen_assertion:
        return False
    matches = [
        projection
        for projection in pending.get("staged_projections", [])
        if projection.get("repository") == "zkm"
        and projection.get("assertion_id") == assertion_id
        and projection.get("kind") == "json_pointer_equals"
        and projection.get("path") == path
        and projection.get("pointer") == pointer
        and projection.get("observed_value") == observed_value
    ]
    return len(matches) == 1


# --- checks -----------------------------------------------------------------


def check_shape(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    require(registry.get("format") == REGISTRY_FORMAT, "wrong registry format")
    authority = registry.get("authority", {})
    require(authority.get("protocol") == "zkm", "registry is not ZKM-owned")
    require(
        authority.get("repository") == "pyramidal-io/ZKM.dev",
        "registry authority is not the ZKM repository",
    )
    require(
        authority.get("mirrored_from_zka") is False,
        "the registry is ZKM-owned and MUST NOT be declared a canonical-family mirror",
    )
    for key, expected in EXPECTED_AUTHORITY_PATHS.items():
        relative = authority.get(key)
        require(isinstance(relative, str) and relative, f"authority.{key} missing")
        require(relative == expected, f"authority.{key} moved from {expected}")
        require(
            (REPO_ROOT / relative).is_file(), f"authority.{key} does not exist: {relative}"
        )
    require(
        authority["registry_path"] not in CANONICAL_FAMILY_PATHS,
        "the registry MUST NOT be published at a canonical-family snapshot path",
    )
    require(
        REGISTRY_PATH == REPO_ROOT / authority["registry_path"],
        "authority.registry_path does not name this file",
    )
    require(isinstance(registry.get("revision"), int), "revision must be an integer")
    require(
        registry.get("revision_id") == f"zkm:rev:{registry['revision']}",
        "revision_id does not match revision",
    )
    del sources


def check_toolchain(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    pins = parse_noir_version(sources["noir_version"])
    toolchain = registry.get("toolchain", {})
    require(
        toolchain.get("nargo") == pins["NARGO_VERSION"],
        f"registry nargo pin {toolchain.get('nargo')!r} != .noir-version {pins['NARGO_VERSION']!r}",
    )
    require(
        toolchain.get("barretenberg") == pins["BB_VERSION"],
        f"registry bb pin {toolchain.get('barretenberg')!r} != .noir-version {pins['BB_VERSION']!r}",
    )


def check_statement_authority(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    """Bind IDs, packages, flags and lifecycle to the normative documents."""

    statements = registry.get("statements", [])
    current = {entry["id"]: entry for entry in statements}
    cutover = sources["cutover"]
    cutover_current = cutover_current_rows(cutover)
    lifecycle = cutover_lifecycle_rows(cutover)
    retired_note = cutover_retired_rows(cutover)
    retired = {entry["id"]: entry for entry in registry.get("retired_statements", [])}
    normative_ids = specification_statement_ids(sources["spec"])
    require(
        len(current) == len(statements) and set(current) == normative_ids,
        "registry current statement IDs disagree with exact §5 enumeration",
    )
    require(
        set(current) == set(cutover_current) == set(lifecycle),
        "registry current statement IDs disagree with cutover tables",
    )
    require(
        len(retired) == len(registry.get("retired_statements", []))
        and set(retired) == set(retired_note)
        and set(retired) == {"zkm:mandate-only:v1", "zkm:spend-conjoined:v1"},
        "retired statements disagree with normative v1 cutover",
    )
    for identifier, statement in current.items():
        for field, expected in cutover_current[identifier].items():
            require(
                statement.get(field) == expected,
                f"{identifier}: {field} disagrees with normative cutover table",
            )
        for field, expected in lifecycle[identifier].items():
            require(
                statement.get(field) == expected,
                f"{identifier}: {field} disagrees with normative lifecycle table",
            )
        require(
            type(statement.get("value_moving")) is bool
            and statement["value_moving"] is (statement["circuit_package"] == "zkm_spend_conjoined"),
            f"{identifier}: value_moving must be an exact boolean for the spend-conjoined package only",
        )
        since = statement.get("current_since_revision")
        require(
            type(since) is int and 1 <= since <= registry["revision"],
            f"{identifier}: current_since_revision is outside published history",
        )

    for identifier, entry in retired.items():
        for field, expected in retired_note[identifier].items():
            require(
                entry.get(field) == expected,
                f"{identifier}: {field} disagrees with normative retired table",
            )
        retirement = entry.get("retired_in_revision")
        successor = entry.get("superseded_by")
        require(
            type(retirement) is int and 1 <= retirement <= registry["revision"]
            and successor in current
            and current[successor].get("supersedes") == identifier
            and current[successor].get("current_since_revision") == retirement,
            f"{identifier}: successor and retirement revision do not agree",
        )
    for identifier, statement in current.items():
        predecessor = statement.get("supersedes")
        require(
            predecessor is None
            or (predecessor in retired and retired[predecessor].get("superseded_by") == identifier),
            f"{identifier}: supersedes is not reciprocal with a retired statement",
        )


def check_statements_against_goldens(
    registry: dict[str, Any], sources: dict[str, Any]
) -> None:
    goldens = parse_goldens(sources["goldens"])
    statements = registry.get("statements", [])
    require(bool(statements), "registry declares no statements")

    seen_ids: set[str] = set()
    seen_packages: set[str] = set()
    for statement in statements:
        identifier = statement.get("id")
        package = statement.get("circuit_package")
        require(isinstance(identifier, str) and identifier, "statement without an id")
        require(identifier not in seen_ids, f"duplicate statement id {identifier!r}")
        seen_ids.add(identifier)
        require(
            statement.get("status") == "current",
            f"{identifier}: statements[] carries current statements only",
        )
        require(
            isinstance(package, str) and package in goldens,
            f"{identifier}: circuit package {package!r} has no golden row",
        )
        require(package not in seen_packages, f"{package}: mapped by two statements")
        seen_packages.add(package)

        golden = goldens[package]
        for field in ("vk_hash", "acir_opcode_count", "bytecode_sha256", "public_input_count"):
            require(
                statement.get(field) == golden[field],
                f"{identifier}: {field} {statement.get(field)!r} != blessed golden {golden[field]!r}",
            )

    missing = sorted(set(goldens) - seen_packages)
    require(
        not missing,
        f"circuits with blessed goldens but no registry statement: {missing}",
    )


def check_public_input_vectors(
    registry: dict[str, Any], sources: dict[str, Any]
) -> None:
    for statement in registry.get("statements", []):
        identifier = statement.get("id")
        package = statement.get("circuit_package")
        source = sources["circuits"].get(package)
        require(source is not None, f"{identifier}: no circuit source for {package!r}")

        observed = parse_public_inputs(source, str(package))
        declared = statement.get("public_inputs", [])
        require(
            isinstance(declared, list) and len(declared) == len(observed),
            f"{identifier}: declares {len(declared) if isinstance(declared, list) else '?'} "
            f"public inputs, `fn main` declares {len(observed)}",
        )
        require(
            statement.get("public_input_count") == len(observed),
            f"{identifier}: public_input_count != `fn main` public parameter count",
        )
        for index, (entry, actual) in enumerate(zip(declared, observed, strict=True)):
            require(
                entry.get("index") == index,
                f"{identifier}: public input {index} is out of order",
            )
            require(
                entry.get("name") == actual["name"],
                f"{identifier}: public input {index} is {entry.get('name')!r}, "
                f"`fn main` declares {actual['name']!r}",
            )
            require(
                entry.get("abi_type") == actual["abi_type"],
                f"{identifier}: public input {actual['name']!r} is "
                f"{entry.get('abi_type')!r}, `fn main` declares {actual['abi_type']!r}",
            )


def check_retirement(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    spec = normalize(sources["spec"])
    current_ids = {statement["id"] for statement in registry.get("statements", [])}
    retired = registry.get("retired_statements", [])
    require(bool(retired), "registry declares no retired statements")

    for entry in retired:
        identifier = entry.get("id")
        require(isinstance(identifier, str) and identifier, "retired entry without an id")
        require(
            identifier not in current_ids,
            f"{identifier}: retired and current at the same time",
        )
        require(
            entry.get("post_cutover_registry") == "MUST omit",
            f"{identifier}: a retired statement MUST be omitted from a post-cutover registry",
        )
        require(
            entry.get("reinterpretation") == "forbidden",
            f"{identifier}: retired proofs MUST NOT be reinterpreted or upgraded",
        )
        successor = entry.get("superseded_by")
        require(
            successor in current_ids,
            f"{identifier}: superseded_by {successor!r} is not a current statement",
        )
        require(
            f"`{identifier}`" in spec,
            f"{identifier}: retirement is not recorded in the specification",
        )
    require(
        "A post-cutover registry MUST omit them and MUST NOT reinterpret or upgrade their proofs."
        in spec,
        "specification no longer states the post-cutover omission rule",
    )

    for identifier in sorted(current_ids):
        require(
            f"`{identifier}`" in spec,
            f"{identifier}: not enumerated in the specification",
        )


def check_revocation(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    revocation = registry.get("revocation", {})
    require(revocation.get("scheme") == 2, "current revocation scheme MUST be 2")
    require(
        revocation.get("accepted_scheme_values") == [2],
        "scheme 2 is the only acceptable revocation_scheme value",
    )
    require(revocation.get("depth") == 254, "the v2 exclusion tree is depth-254")
    require(
        revocation.get("superseded_scheme") == 1,
        "scheme 2 supersedes the legacy scheme 1 slot",
    )
    for key in ("migration_runbook", "migration_tool"):
        relative = revocation.get(key)
        require(
            isinstance(relative, str) and (REPO_ROOT / relative).is_file(),
            f"revocation.{key} does not exist: {relative!r}",
        )
    require(
        "`revocation_scheme` MUST equal 2 for the depth-254 full-identifier exclusion tree"
        in normalize(sources["spec"]),
        "specification no longer fixes revocation_scheme = 2",
    )
    transition_statements = {
        statement["id"]
        for statement in registry.get("statements", [])
        if any(
            entry.get("name") == "revocation_scheme"
            for entry in statement.get("public_inputs", [])
        )
    }
    require(
        transition_statements == {
            "zkm:mandate-only:v2", "zkm:spend-conjoined:v2", "zkm:revocation-insertion:v1"
        },
        "exactly the two v2 transition statements and insertion companion publish revocation_scheme, "
        f"observed {sorted(transition_statements)}",
    )


def check_statement_set_id(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    observed = statement_set_id(registry)
    require(
        registry.get("statement_set_id") == observed,
        "statement_set_id is stale: the statement surface moved without a new id "
        f"(declared {registry.get('statement_set_id')!r}, derived {observed!r})",
    )
    del sources


def check_revision_history(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    history = registry.get("revision_history", [])
    require(bool(history), "revision_history is empty")

    previous: dict[str, Any] | None = None
    breaking_revisions: list[int] = []
    for entry in history:
        revision = entry.get("revision")
        identity = entry.get("statement_set_id")
        require(isinstance(revision, int), "revision_history entry without a revision")
        require(
            isinstance(identity, str) and identity.startswith("sha256:"),
            f"rev {revision}: revision_history entry without a statement_set_id",
        )
        if previous is None:
            require(
                entry.get("breaking") is True,
                f"rev {revision}: the first recorded revision is breaking by construction",
            )
        else:
            require(
                revision > previous["revision"],
                f"rev {revision}: revision_history must be strictly increasing",
            )
            changed = identity != previous["statement_set_id"]
            require(
                entry.get("breaking") is changed,
                f"rev {revision}: breaking={entry.get('breaking')} contradicts the "
                f"statement_set_id, which {'moved' if changed else 'did not move'}",
            )
        if entry.get("breaking") is True:
            breaking_revisions.append(revision)
        previous = entry

    require(previous is not None, "revision_history is empty")
    require(
        previous["revision"] == registry.get("revision"),
        f"revision {registry.get('revision')} has no revision_history entry",
    )
    require(
        previous["statement_set_id"] == registry.get("statement_set_id"),
        "the current revision_history entry does not carry the current statement_set_id",
    )
    require(
        registry.get("last_breaking_revision") == max(breaking_revisions),
        f"last_breaking_revision {registry.get('last_breaking_revision')!r} != "
        f"{max(breaking_revisions)}, the greatest breaking revision on record",
    )
    del sources


def check_family_pin(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    manifest = sources["manifest"]
    family_pin = registry.get("family_pin", {})
    require(
        not sources.get("pending_republish_errors"),
        "invalid pending_republish marker: "
        + "; ".join(sources.get("pending_republish_errors", [])),
    )
    require(
        manifest.get("epoch") == registry.get("family_epoch"),
        f"family epoch drift: manifest {manifest.get('epoch')!r} != registry "
        f"{registry.get('family_epoch')!r}",
    )

    declared = manifest.get("protocols", {}).get("zkm", {}).get("version")
    require(
        declared == family_pin.get("declared_version"),
        f"manifest pins protocols.zkm = {declared!r}, registry records "
        f"{family_pin.get('declared_version')!r}",
    )
    tuple_versions = {
        combination.get("zkm") for combination in manifest.get("compatibility", [])
    }
    require(
        tuple_versions <= {declared},
        f"compatibility tuples pin ZKM as {sorted(v for v in tuple_versions if v != declared)!r}, "
        f"but protocols.zkm is {declared!r}",
    )

    # The label half of the pin. Epoch 2026-08-15.1 moved protocols.zkm from a
    # bare "0.1.0-draft" — constant since rev 1 — to a revision-labelled
    # "0.1.0-draft (rev 10)". The label discriminates revisions; what it
    # cannot do is move on its own when ZKM ships a breaking one, so that is
    # the invariant enforced here, from ZKM's side, where the revision is
    # known.
    label = family_pin.get("revision_label", {})
    match = re.fullmatch(r"(?P<version>.+?)(?: \(rev (?P<revision>\d+)\))?", str(declared))
    require(match is not None, f"unparseable protocols.zkm version {declared!r}")
    require(
        match.group("version") == registry.get("spec_version"),
        f"manifest pins spec version {match.group('version')!r}, registry publishes "
        f"{registry.get('spec_version')!r}",
    )
    pinned_revision = (
        int(match.group("revision")) if match.group("revision") is not None else None
    )
    require(
        label.get("pinned") is (pinned_revision is not None),
        f"family_pin.revision_label.pinned={label.get('pinned')} contradicts "
        f"protocols.zkm = {declared!r}",
    )
    require(
        label.get("revision") == pinned_revision,
        f"family_pin.revision_label.revision {label.get('revision')!r} != the "
        f"revision the manifest pins ({pinned_revision!r})",
    )

    # Three pin shapes are accepted, each recorded as (name, expected,
    # observed). The file-shaped pins (artifact binding, sha256_equals
    # assertion) compare against the whole-file digest. The field-shaped pin
    # (json_pointer_equals on /statement_set_id) compares against the
    # registry's statement_set_id, whose preimage covers every statement, ABI,
    # VK, revocation and toolchain field but deliberately excludes prose
    # (note/reason/notes) -- so an editorial edit cannot break the family pin,
    # where a whole-file digest would force a new epoch per prose change.
    # A json_pointer_equals on any other pointer is NOT a pin: no other field
    # is compelled to move when the statement surface moves.
    registry_path = registry["authority"]["registry_path"]
    staged_statement_id = active_staged_projection(
        sources,
        assertion_id="zkm-statement-set-id",
        path=registry_path,
        pointer="/statement_set_id",
        observed_value=registry.get("statement_set_id"),
    )
    staged_breaking_revision = active_staged_projection(
        sources,
        assertion_id="zkm-last-breaking-revision",
        path=registry_path,
        pointer="/last_breaking_revision",
        observed_value=registry.get("last_breaking_revision"),
    )
    staged_registry_surface = staged_statement_id and staged_breaking_revision
    pins: list[tuple[str, Any, Any]] = []
    for binding in manifest.get("artifact_bindings", []):
        if binding.get("repository") == "zkm" and binding.get("path") == registry_path:
            pins.append(
                (
                    f"artifact_binding:{binding.get('id')}",
                    binding.get("sha256"),
                    sources["registry_sha256"],
                )
            )
    for assertion in manifest.get("projections", {}).get("zkm", {}).get("assertions", []):
        if assertion.get("path") != registry_path:
            continue
        if assertion.get("kind") == "sha256_equals":
            pins.append(
                (
                    f"assertion:{assertion.get('id')}",
                    assertion.get("expected"),
                    sources["registry_sha256"],
                )
            )
        elif (
            assertion.get("kind") == "json_pointer_equals"
            and assertion.get("pointer") == "/statement_set_id"
        ):
            pins.append(
                (
                    f"assertion:{assertion.get('id')}",
                    assertion.get("expected"),
                    registry.get("statement_set_id"),
                )
            )

    # At least one discriminating pin must exist. Without this the whole check
    # is bypassable by a coordinated edit: drop the revision label from the
    # manifest, record `revision_label.pinned = false` here to match, and the
    # bounds below simply do not apply -- leaving ZKM pinned by a version
    # string constant since rev 1, which is the original defect. Any pin shape
    # satisfies it on its own (file digest and statement_set_id alike move on
    # any statement-surface change, so neither can go stale across a breaking
    # revision unnoticed); a revision label satisfies it subject to the bounds
    # below.
    require(
        pinned_revision is not None or bool(pins),
        "the family manifest discriminates ZKM by neither a revision label nor a "
        f"statement-registry pin: protocols.zkm = {declared!r} is constant across "
        "revisions, so a consumer on this epoch has no way to tell one ZKM statement "
        "surface from another",
    )
    if pinned_revision is not None:
        require(
            pinned_revision <= registry["revision"],
            f"the family pins ZKM rev {pinned_revision}, which this repository has "
            f"not published (current rev {registry['revision']})",
        )
        require(
            pinned_revision >= registry["last_breaking_revision"]
            or staged_registry_surface,
            f"the family pins ZKM rev {pinned_revision}, older than the last breaking "
            f"revision {registry['last_breaking_revision']}: a consumer following the "
            "epoch would combine an incompatible ZKM statement surface without an "
            "active marker staging this exact statement ID and breaking revision",
        )

    digest_pin = family_pin.get("statement_digest", {})
    if not pins:
        require(
            digest_pin.get("pinned") is False,
            "family_pin.statement_digest claims a pin, but the family manifest binds "
            "no digest for the registry -- only the revision label, which is prose "
            "and does not move within a revision",
        )
        require(
            digest_pin.get("pinned_by") is None,
            "family_pin.statement_digest.pinned_by is set while the manifest pins nothing",
        )
        required = digest_pin.get("required_binding", {})
        require(
            required.get("path") == registry_path and required.get("repository") == "zkm",
            "family_pin.statement_digest.required_binding must name this registry for "
            "the ZKA-side adoption",
        )
        return

    require(
        digest_pin.get("pinned") is True,
        "the family manifest pins the registry digest, but "
        "family_pin.statement_digest.pinned is false",
    )
    require(
        digest_pin.get("pinned_by") in {name for name, _, _ in pins},
        f"family_pin.statement_digest.pinned_by {digest_pin.get('pinned_by')!r} is not "
        f"one of the manifest pins {sorted(name for name, _, _ in pins)}",
    )
    for name, expected, observed in pins:
        require(
            expected == observed
            or (name == "assertion:zkm-statement-set-id" and staged_registry_surface),
            f"{name}: pinned value {expected!r} != observed {observed!r}",
        )


def check_cutover_note(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    raw_cutover = sources["cutover"]
    cutover = normalize(raw_cutover)
    prepost_rows = cutover_table(
        raw_cutover,
        ("", "Pre-cutover (rev 9 and earlier)", "Post-cutover (rev 10+)"),
    )
    prepost = {row[0]: row[1:] for row in prepost_rows}
    require(
        len(prepost) == len(prepost_rows),
        "cutover note: duplicate rev 10 comparison row label",
    )
    require(
        set(prepost)
        == {
            "Spend statement", "Mandate-only statement", "Spend public vector",
            "Mandate-only public vector", "Revocation accumulator",
            "`revocation_scheme` wire value", "Verification keys",
        },
        "cutover note: rev 10 comparison rows changed",
    )
    current = {entry["id"]: entry for entry in registry["statements"]}
    retired = {entry["id"]: entry for entry in registry["retired_statements"]}
    for label, old_id, new_id, vector_label in (
        ("Spend statement", "zkm:spend-conjoined:v1", "zkm:spend-conjoined:v2", "Spend public vector"),
        ("Mandate-only statement", "zkm:mandate-only:v1", "zkm:mandate-only:v2", "Mandate-only public vector"),
    ):
        require(
            prepost[label] == (f"`{old_id}`", f"`{new_id}`"),
            f"cutover note: {label} predecessor/successor changed",
        )
        before, after = prepost[vector_label]
        require(
            re.fullmatch(r"(\d+) elements", before) is not None
            and int(before.split()[0]) == retired[old_id]["public_input_count"]
            and re.match(r"\*\*(\d+)\*\* elements", after) is not None
            and int(re.match(r"\*\*(\d+)\*\*", after).group(1)) == current[new_id]["public_input_count"]
            and "`revocation_scheme` added" in after,
            f"cutover note: {vector_label} counts or inserted slot changed",
        )
    require(
        prepost["Revocation accumulator"]
        == ("depth-128 tree over the low half of `root_id`", "**depth-254 full-identifier exclusion tree**")
        and prepost["`revocation_scheme` wire value"]
        == ("absent", "**2**; 0, 1 and 3..255 are invalid")
        and prepost["Verification keys"] == ("rev-9 keys", "**all keys re-blessed**"),
        "cutover note: revocation construction, scheme, or key migration changed",
    )
    spend_vector = re.search(
        r"`zkm:spend-conjoined:v2` — (\d+) elements:\s*```text\s*\((.*?)\)\s*```",
        raw_cutover,
        flags=re.DOTALL,
    )
    mandate_vector = re.search(
        r"`zkm:mandate-only:v2` — (\d+) elements: the first nine of the above "
        r"\(through `settlement_context`\), with no ZKA value leg\.",
        normalize(raw_cutover),
    )
    require(spend_vector is not None and mandate_vector is not None, "cutover note: missing v2 public vector declarations")
    spend_names = [name.strip() for name in spend_vector.group(2).split(",")]
    declared_spend = [entry["name"] for entry in current["zkm:spend-conjoined:v2"]["public_inputs"]]
    declared_mandate = [entry["name"] for entry in current["zkm:mandate-only:v2"]["public_inputs"]]
    require(
        int(spend_vector.group(1)) == len(spend_names) == len(declared_spend)
        and spend_names == declared_spend
        and int(mandate_vector.group(1)) == len(declared_mandate)
        and declared_mandate == spend_names[: len(declared_mandate)],
        "cutover note: v2 public vectors disagree with registry slots",
    )
    require(
        "The two v1 statements are **retired**. They are valid only under pre-cutover v1 keys and roots; a post-cutover registry MUST omit them and MUST NOT reinterpret or upgrade their proofs."
        in cutover,
        "cutover note: v1 retirement prohibition changed",
    )
    post_cutover_section = raw_cutover.split("## 4. What a post-cutover registry MUST contain", 1)
    require(len(post_cutover_section) == 2, "cutover note: missing post-cutover registry rules")
    rules_text = post_cutover_section[1].split("## 5. Migration path", 1)[0]
    rules = {
        int(number): normalize(body)
        for number, body in re.findall(
            r"(?ms)^([1-7])\. (.*?)(?=^[1-7]\. |\Z)", rules_text
        )
    }
    require(set(rules) == set(range(1, 8)), "cutover note: incomplete post-cutover registry rules")
    for number, required in {
        1: ("nine", "exactly one", "verification key"),
        2: ("zkm:spend-conjoined:v1", "zkm:mandate-only:v1", "MUST NOT reinterpret"),
        3: ("zkm:spend-conjoined:v2", "no other key", "MUST NOT reach it"),
        4: ("zkm:revocation-auth:v1", "zkm:revocation-insertion:v1", "zkm:control-attestation:v1", "MUST NOT accept", "atomically"),
        5: ("revocation_scheme = 2", "reject every other scheme"),
        6: ("single", "mandate-nullifier set", "across the cutover"),
        7: ("value-moving entry", "immutable or version-pinned", "statement_set_id"),
    }.items():
        require(
            all(fragment in rules[number] for fragment in required),
            f"cutover note: post-cutover rule {number} lost a normative condition",
        )
    for statement in registry.get("statements", []):
        require(
            f"`{statement['id']}`" in cutover,
            f"{statement['id']}: current statement is missing from the cutover note",
        )
    for entry in registry.get("retired_statements", []):
        require(
            f"`{entry['id']}`" in cutover,
            f"{entry['id']}: retired statement is missing from the cutover note",
        )
    require(
        str(registry.get("family_epoch")) in cutover,
        "the cutover note does not name the family epoch",
    )
    require(
        str(registry.get("statement_set_id")) in cutover,
        "the cutover note does not publish the current statement_set_id",
    )
    require(
        registry.get("consumer_gate", {}).get("commands") == list(EXPECTED_CONSUMER_COMMANDS),
        "consumer_gate.commands differs from the pinned consumer command list",
    )
    consumer_section = raw_cutover.split("## 6. The gate a consumer should execute", 1)
    require(len(consumer_section) == 2, "cutover note: missing consumer gate section")
    bash_block = re.search(r"```bash\n(.*?)\n```", consumer_section[1], flags=re.DOTALL)
    require(bash_block is not None, "cutover note: missing consumer gate command block")
    commands = tuple(
        line for line in bash_block.group(1).splitlines() if line and not line.startswith("#")
    )
    require(commands == EXPECTED_CONSUMER_COMMANDS, "cutover note: consumer command list differs from registry")


CHECKS = (
    check_shape,
    check_toolchain,
    check_statement_authority,
    check_statements_against_goldens,
    check_public_input_vectors,
    check_retirement,
    check_revocation,
    check_statement_set_id,
    check_revision_history,
    check_family_pin,
    check_cutover_note,
)


def run_checks(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    for check in CHECKS:
        check(registry, sources)


# --- self-test --------------------------------------------------------------


def _reseal(registry: dict[str, Any]) -> None:
    """Re-derive every self-consistent field after a mutation.

    This is what a diligent-but-wrong maintainer does: recompute the id,
    record the revision as breaking, move `last_breaking_revision`. A
    resealed mutation defeats the statement_set_id and revision-history
    checks by construction, so it can only be caught by the check that
    re-derives that specific claim from its real source. Every mutation of a
    field inside the statement_set_id preimage is tested in both spellings —
    unsealed and resealed — because a gate that only catches the careless
    spelling is not a gate.
    """

    registry["statement_set_id"] = statement_set_id(registry)
    registry["revision_history"][-1]["statement_set_id"] = registry["statement_set_id"]
    registry["revision_history"][-1]["breaking"] = True
    registry["last_breaking_revision"] = registry["revision_history"][-1]["revision"]


def _drop_revision_label(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    """Revert the manifest to a bare version string, registry kept in agreement."""

    sources["manifest"] = copy.deepcopy(sources["manifest"])
    sources["manifest"]["protocols"]["zkm"]["version"] = registry["spec_version"]
    for combination in sources["manifest"]["compatibility"]:
        combination["zkm"] = registry["spec_version"]
    registry["family_pin"]["declared_version"] = registry["spec_version"]
    registry["family_pin"]["revision_label"]["pinned"] = False
    registry["family_pin"]["revision_label"]["revision"] = None


def _adopt_digest_pin(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    """Add the ZKA-side artifact binding, correctly declared on both sides."""

    sources["manifest"] = copy.deepcopy(sources["manifest"])
    sources["manifest"]["artifact_bindings"].append(
        {
            "id": "zkm-statement-registry-v1",
            "repository": "zkm",
            "path": registry["authority"]["registry_path"],
            "sha256": sources["registry_sha256"],
        }
    )
    registry["family_pin"]["statement_digest"]["pinned"] = True
    registry["family_pin"]["statement_digest"]["pinned_by"] = (
        "artifact_binding:zkm-statement-registry-v1"
    )


def _strip_registry_pins(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    """Remove every manifest pin on the registry path (file- and field-shaped).

    The non-pin `path_exists` assertion is deliberately kept: existence does
    not discriminate one statement surface from another.
    """

    registry_path = registry["authority"]["registry_path"]
    sources["manifest"] = copy.deepcopy(sources["manifest"])
    sources["manifest"]["artifact_bindings"] = [
        binding
        for binding in sources["manifest"]["artifact_bindings"]
        if not (
            binding.get("repository") == "zkm"
            and binding.get("path") == registry_path
        )
    ]
    projection = sources["manifest"]["projections"]["zkm"]
    projection["assertions"] = [
        assertion
        for assertion in projection["assertions"]
        if not (
            assertion.get("path") == registry_path
            and assertion.get("kind") in {"sha256_equals", "json_pointer_equals"}
        )
    ]


def _mutations() -> list[tuple[str, Any]]:
    """Named mutations, each of which MUST make `run_checks` fail.

    Every mutation is a real regression spelled the way it would actually
    arrive: a re-blessed key that nobody recorded, a renamed public input, a
    retired statement quietly kept alive, a revision that claims to be
    non-breaking while its statement surface moved.
    """

    def set_vk(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["statements"][0]["vk_hash"] = "00" * 32

    def stale_after_vk_move(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        # A re-blessed golden with the registry row updated to match, but the
        # statement_set_id (and history) left alone -- the exact rev-10-shaped
        # drift this artifact exists to catch.
        sources["goldens"] = sources["goldens"].replace(
            "zkm_spend_conjoined|02e761b6", "zkm_spend_conjoined|ffffffff"
        )
        for statement in registry["statements"]:
            if statement["circuit_package"] == "zkm_spend_conjoined":
                statement["vk_hash"] = "ffffffff" + statement["vk_hash"][8:]

    def drop_golden_row(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["goldens"] = "\n".join(
            line
            for line in sources["goldens"].splitlines()
            if not line.startswith("zkm_revocation_auth|")
        )

    def rename_public_input(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        for statement in registry["statements"]:
            if statement["id"] == "zkm:mandate-only:v2":
                statement["public_inputs"][6]["name"] = "revocation_epoch"

    def drop_public_input(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        for statement in registry["statements"]:
            if statement["id"] == "zkm:spend-conjoined:v2":
                del statement["public_inputs"][6]
                statement["public_input_count"] = 13

    def reorder_public_inputs(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        for statement in registry["statements"]:
            if statement["id"] == "zkm:spend-conjoined:v2":
                inputs = statement["public_inputs"]
                inputs[6], inputs[7] = inputs[7], inputs[6]

    def circuit_gained_a_public_input(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        sources["circuits"]["zkm_revocation_auth"] = sources["circuits"][
            "zkm_revocation_auth"
        ].replace("    root_id: pub Field,", "    root_id: pub Field,\n    epoch: pub u64,")

    def revive_v1_statement(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        revived = copy.deepcopy(registry["statements"][0])
        revived["id"] = "zkm:spend-conjoined:v1"
        registry["statements"].append(revived)

    def retire_a_current_statement(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        registry["retired_statements"][0]["id"] = "zkm:mandate-only:v2"

    def soften_retirement(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["retired_statements"][0]["post_cutover_registry"] = "SHOULD omit"

    def unknown_statement_id(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        # A statement identifier the specification does not enumerate. Picked
        # on a statement no retired entry points at, so this exercises the
        # spec-enumeration check rather than the supersession check.
        for statement in registry["statements"]:
            if statement["id"] == "zkm:possession:v1":
                statement["id"] = "zkm:possession:v9"

    def legacy_revocation_scheme(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["revocation"]["scheme"] = 1
        registry["revocation"]["accepted_scheme_values"] = [1]

    def widen_accepted_schemes(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["revocation"]["accepted_scheme_values"] = [1, 2]

    def toolchain_drift(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["toolchain"]["barretenberg"] = "5.0.0-nightly.20260601"

    def breaking_flag_lies(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["revision_history"][-1]["breaking"] = False

    def unrecorded_revision(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["revision"] += 1
        registry["revision_id"] = f"zkm:rev:{registry['revision']}"

    def stale_last_breaking(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["last_breaking_revision"] = 9

    def silent_breaking_revision(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        # Append a genuinely new revision whose identity moved, while falsely
        # calling that new revision non-breaking.
        registry["revocation"]["construction"] += ":changed"
        registry["revision"] += 1
        registry["revision_id"] = f"zkm:rev:{registry['revision']}"
        moved_id = statement_set_id(registry)
        registry["statement_set_id"] = moved_id
        registry["revision_history"].append(
            {
                "revision": registry["revision"],
                "published": registry["published"],
                "breaking": False,
                "statement_set_id": moved_id,
                "summary": "changed revocation construction misclassified as non-breaking",
            }
        )

    def swap_ids(registry: dict[str, Any], first: str, second: str) -> None:
        left = next(entry for entry in registry["statements"] if entry["id"] == first)
        right = next(entry for entry in registry["statements"] if entry["id"] == second)
        left["id"], right["id"] = right["id"], left["id"]

    def swap_issuance_revocation(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        swap_ids(registry, "zkm:issuance:v1", "zkm:revocation-auth:v1")

    def swap_mandate_spend(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        swap_ids(registry, "zkm:mandate-only:v2", "zkm:spend-conjoined:v2")

    def swap_possession_control(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        swap_ids(registry, "zkm:possession:v1", "zkm:control-attestation:v1")

    def rename_control(registry: dict[str, Any], replacement: str) -> None:
        entry = next(
            item for item in registry["statements"] if item["id"] == "zkm:control-attestation:v1"
        )
        entry["id"] = replacement

    def flip_value_flag(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        entry = next(
            item for item in registry["statements"] if item["id"] == "zkm:spend-conjoined:v2"
        )
        entry["value_moving"] = False

    def nonboolean_value_flag(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        entry = next(
            item for item in registry["statements"] if item["id"] == "zkm:spend-conjoined:v2"
        )
        entry["value_moving"] = 1

    def current_since_99(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["statements"][2]["current_since_revision"] = 99

    def clear_supersedes(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["statements"][0]["supersedes"] = None

    def drop_retired_spend(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["retired_statements"] = [
            entry for entry in registry["retired_statements"]
            if entry["id"] != "zkm:spend-conjoined:v1"
        ]

    def swap_cutover_vks(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        current = {entry["id"]: entry for entry in registry["statements"]}
        first = current["zkm:revocation-auth:v1"]["vk_hash"]
        second = current["zkm:control-attestation:v1"]["vk_hash"]
        sources["cutover"] = sources["cutover"].replace(first, "_swapped_vk_", 1).replace(
            second, first, 1
        ).replace("_swapped_vk_", second, 1)

    def duplicate_cutover_vector_row(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        legitimate = "| Spend public vector | 13 elements | **14** elements (`revocation_scheme` added) |"
        contradictory = "| Spend public vector | 13 elements | **99** elements (`revocation_scheme` added) |"
        require(legitimate in sources["cutover"], "cutover comparison self-test fixture moved")
        sources["cutover"] = sources["cutover"].replace(
            legitimate, contradictory + "\n" + legitimate, 1
        )

    def empty_consumer_commands(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["consumer_gate"]["commands"] = []

    def redirect_spec_authority(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        registry["authority"]["specification_path"] = "docs/zkm_v1_to_v2_cutover.md"

    def public_root_return(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        source = sources["circuits"]["zkm_control_attestation"]
        marker = ") {\n    assert(lineage_tag != 0"
        final_assertion = (
            '        "prover does not hold the issuance authority for this lineage tag",\n'
            "    );\n}"
        )
        require(
            marker in source and final_assertion in source,
            "control-attestation self-test fixture moved",
        )
        source = source.replace(marker, ") -> pub Field {\n    assert(lineage_tag != 0", 1)
        sources["circuits"]["zkm_control_attestation"] = source.replace(
            final_assertion,
            final_assertion[:-1] + "    root_id\n}",
            1,
        )

    def sealed_toolchain_drift(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        toolchain_drift(registry, sources)
        _reseal(registry)

    def sealed_legacy_revocation_scheme(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        legacy_revocation_scheme(registry, sources)
        _reseal(registry)

    def sealed_soften_retirement(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        soften_retirement(registry, sources)
        _reseal(registry)

    def sealed_vk_move(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        set_vk(registry, sources)
        _reseal(registry)

    def overclaim_family_pin(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        # pinned_by names an artifact binding the manifest does not carry --
        # the pin that actually exists is the field-shaped assertion.
        registry["family_pin"]["statement_digest"]["pinned"] = True
        registry["family_pin"]["statement_digest"]["pinned_by"] = (
            "artifact_binding:zkm-statement-registry-v1"
        )

    def breaking_revision_the_family_has_not_followed(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        # Advance beyond the current revision so this remains a family-pin
        # regression after each cutover, rather than a duplicate history row.
        next_revision = registry["revision"] + 1
        registry["statements"][0]["current_since_revision"] = next_revision
        registry["revision"] = next_revision
        registry["revision_id"] = f"zkm:rev:{next_revision}"
        registry["revision_history"].append(
            {
                "revision": next_revision,
                "published": registry["published"],
                "breaking": True,
                "statement_set_id": statement_set_id(registry),
                "summary": "breaking change the family has not followed",
            }
        )
        registry["statement_set_id"] = registry["revision_history"][-1][
            "statement_set_id"
        ]
        registry["last_breaking_revision"] = next_revision

    def family_pins_an_unpublished_revision(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        next_revision = registry["revision"] + 1
        next_version = f"0.1.0-draft (rev {next_revision})"
        sources["manifest"] = copy.deepcopy(sources["manifest"])
        sources["manifest"]["protocols"]["zkm"]["version"] = next_version
        for combination in sources["manifest"]["compatibility"]:
            combination["zkm"] = next_version
        registry["family_pin"]["declared_version"] = next_version
        registry["family_pin"]["revision_label"]["revision"] = next_revision

    def staging_marker_deactivated(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        del sources["pending_republish"]["staging_commit"]

    def staged_statement_id_removed(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        sources["pending_republish"]["staged_projections"] = [
            projection
            for projection in sources["pending_republish"]["staged_projections"]
            if projection.get("assertion_id") != "zkm-statement-set-id"
        ]

    def staged_breaking_revision_removed(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        sources["pending_republish"]["staged_projections"] = [
            projection
            for projection in sources["pending_republish"]["staged_projections"]
            if projection.get("assertion_id") != "zkm-last-breaking-revision"
        ]

    def family_dropped_label_and_every_pin(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        # The coordinated spelling: the manifest reverts to the bare version
        # string AND drops every pin on the registry path, with the registry
        # updated to agree on both counts, so nothing is inconsistent -- ZKM
        # is simply undiscriminated again. (Dropping the label alone is now
        # an accepted variant: the field pin discriminates on its own.)
        _drop_revision_label(registry, sources)
        _strip_registry_pins(registry, sources)
        registry["family_pin"]["statement_digest"]["pinned"] = False
        registry["family_pin"]["statement_digest"]["pinned_by"] = None

    def statement_surface_moved_under_the_field_pin(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        # The field pin's teeth, isolated: the revision label is gone (so the
        # revision bounds cannot fire), the statement surface moves, and a
        # diligent-but-wrong maintainer reseals everything -- id recomputed,
        # history reclassified, cutover note updated. Only the manifest's
        # /statement_set_id assertion, which ZKA has not re-blessed, can
        # catch it.
        _drop_revision_label(registry, sources)
        old_id = registry["statement_set_id"]
        registry["statements"][0]["current_since_revision"] = 11
        _reseal(registry)
        sources["cutover"] = sources["cutover"].replace(
            old_id, registry["statement_set_id"]
        )

    def field_pin_expects_an_unpublished_id(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        # The same comparison from the other side: ZKA's assertion carries a
        # statement_set_id this registry never published.
        sources["manifest"] = copy.deepcopy(sources["manifest"])
        for assertion in sources["manifest"]["projections"]["zkm"]["assertions"]:
            if assertion.get("id") == "zkm-statement-set-id":
                assertion["expected"] = "sha256:" + "00" * 32

    def compatibility_tuple_disagrees(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        sources["manifest"] = copy.deepcopy(sources["manifest"])
        sources["manifest"]["compatibility"][0]["zkm"] = "0.1.0-draft (rev 9)"

    def adopted_pin_with_wrong_digest(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        sources["manifest"] = copy.deepcopy(sources["manifest"])
        sources["manifest"]["artifact_bindings"].append(
            {
                "id": "zkm-statement-registry-v1",
                "repository": "zkm",
                "path": registry["authority"]["registry_path"],
                "sha256": "sha256:" + "00" * 32,
            }
        )
        registry["family_pin"]["statement_digest"]["pinned"] = True
        registry["family_pin"]["statement_digest"]["pinned_by"] = (
            "artifact_binding:zkm-statement-registry-v1"
        )

    def adopted_pin_undeclared(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        # The manifest pins the registry (the live field pin), but the
        # registry reverts to claiming it is unpinned.
        registry["family_pin"]["statement_digest"]["pinned"] = False
        registry["family_pin"]["statement_digest"]["pinned_by"] = None

    def family_version_moved(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["manifest"] = copy.deepcopy(sources["manifest"])
        sources["manifest"]["protocols"]["zkm"]["version"] = "0.2.0-draft (rev 10)"

    def family_epoch_moved(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["manifest"] = copy.deepcopy(sources["manifest"])
        sources["manifest"]["epoch"] = "zka:protocol-family:2026-09-01.1"

    def cutover_note_omits_statement(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        sources["cutover"] = sources["cutover"].replace("`zkm:spend-conjoined:v1`", "the v1 spend statement")

    def cutover_note_omits_gate(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["cutover"] = sources["cutover"].replace(
            "python3 scripts/migrate-revocation-v2.py --self-test", "(see the runbook)"
        )

    def registry_declared_as_mirror(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        registry["authority"]["mirrored_from_zka"] = True

    def registry_moved_into_mirror(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        registry["authority"]["registry_path"] = "protocol-family/golden-vectors-v1.json"

    mutations = [
        ("unrecorded verification-key move", set_vk),
        ("re-blessed key with a stale statement_set_id", stale_after_vk_move),
        ("golden row deleted for a registered statement", drop_golden_row),
        ("public input renamed in the registry only", rename_public_input),
        ("public input dropped from the registry", drop_public_input),
        ("public inputs reordered", reorder_public_inputs),
        ("circuit gained a public input", circuit_gained_a_public_input),
        ("retired v1 statement revived", revive_v1_statement),
        ("current statement listed as retired", retire_a_current_statement),
        ("post-cutover omission softened to SHOULD", soften_retirement),
        ("statement id absent from the specification", unknown_statement_id),
        ("legacy revocation scheme restored", legacy_revocation_scheme),
        ("both revocation schemes accepted", widen_accepted_schemes),
        ("toolchain pin drifted from .noir-version", toolchain_drift),
        ("toolchain drift, resealed as a new revision", sealed_toolchain_drift),
        ("legacy revocation scheme, resealed", sealed_legacy_revocation_scheme),
        ("retirement softened, resealed", sealed_soften_retirement),
        ("verification-key move, resealed", sealed_vk_move),
        ("breaking revision falsely marked non-breaking", breaking_flag_lies),
        ("revision with no history entry", unrecorded_revision),
        ("last_breaking_revision left stale", stale_last_breaking),
        ("breaking change published as non-breaking", silent_breaking_revision),
        ("family pin claimed but not present", overclaim_family_pin),
        (
            "breaking revision the family epoch has not followed",
            breaking_revision_the_family_has_not_followed,
        ),
        ("family pins an unpublished ZKM revision", family_pins_an_unpublished_revision),
        ("staging marker deactivated", staging_marker_deactivated),
        ("staged statement ID authorization removed", staged_statement_id_removed),
        (
            "staged breaking revision authorization removed",
            staged_breaking_revision_removed,
        ),
        (
            "family dropped the revision label and every registry pin",
            family_dropped_label_and_every_pin,
        ),
        (
            "statement surface moved under the field pin alone",
            statement_surface_moved_under_the_field_pin,
        ),
        (
            "field pin expects an id this registry never published",
            field_pin_expects_an_unpublished_id,
        ),
        ("compatibility tuple disagrees with protocols.zkm", compatibility_tuple_disagrees),
        ("family pin adopted with the wrong digest", adopted_pin_with_wrong_digest),
        ("family pin adopted but registry claims unpinned", adopted_pin_undeclared),
        ("family manifest moved protocols.zkm", family_version_moved),
        ("family epoch moved", family_epoch_moved),
        ("cutover note dropped a statement", cutover_note_omits_statement),
        ("cutover note dropped a consumer-gate command", cutover_note_omits_gate),
        ("registry declared a ZKA mirror", registry_declared_as_mirror),
        ("registry moved onto a mirrored path", registry_moved_into_mirror),
    ]
    source_regressions = [
        ("authority: issuance/revocation id swap", swap_issuance_revocation),
        ("authority: mandate/spend id swap", swap_mandate_spend),
        ("authority: possession/control id swap", swap_possession_control),
        (
            "authority: control renamed to proof",
            lambda registry, sources: rename_control(registry, "zkm:proof:v1"),
        ),
        (
            "authority: control renamed to receipt",
            lambda registry, sources: rename_control(registry, "zkm:receipt:v1"),
        ),
        (
            "authority: control renamed to disclosure",
            lambda registry, sources: rename_control(registry, "zkm:disclosure:v1"),
        ),
        ("authority: value-moving flag flipped", flip_value_flag),
        ("authority: value-moving flag nonboolean", nonboolean_value_flag),
        ("authority: current since revision 99", current_since_99),
        ("authority: supersedes cleared", clear_supersedes),
        ("authority: retired spend removed", drop_retired_spend),
        ("authority: cutover VKs swapped", swap_cutover_vks),
        ("cutover: duplicate contradictory vector row", duplicate_cutover_vector_row),
        ("cutover: consumer commands emptied", empty_consumer_commands),
        ("shape: specification authority redirected", redirect_spec_authority),
        ("abi: control attestation returns public root", public_root_return),
        ("history: moved rev13 called nonbreaking", silent_breaking_revision),
    ]
    for name, mutate in source_regressions:
        for sealed in (False, True):
            def apply_variant(
                registry: dict[str, Any],
                sources: dict[str, Any],
                mutate: Any = mutate,
                sealed: bool = sealed,
                case_name: str = name,
            ) -> None:
                mutate(registry, sources)
                if sealed:
                    _reseal(registry)
                    if case_name.startswith("history:"):
                        registry["revision_history"][-1]["breaking"] = False
                        registry["last_breaking_revision"] = 12

            mutations.append((f"{name} ({'resealed' if sealed else 'unsealed'})", apply_variant))
    return mutations


def _accepted_variants() -> list[tuple[str, Any]]:
    """Named variants that MUST still pass — the rules' other side.

    A check that fails closed on everything is not a check. The discriminating
    -pin requirement in particular is a disjunction (revision label OR digest
    pin), and only a positive case can show it is not an accidental
    hard requirement for one of them.
    """

    def digest_pin_adopted(registry: dict[str, Any], sources: dict[str, Any]) -> None:
        _adopt_digest_pin(registry, sources)

    def digest_pin_instead_of_label(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        _adopt_digest_pin(registry, sources)
        _drop_revision_label(registry, sources)

    def field_pin_instead_of_label(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        # The label is gone and only the live /statement_set_id assertion
        # discriminates ZKM. This is what proves the anti-bypass guard is
        # satisfied by the field pin alone.
        _drop_revision_label(registry, sources)

    def editorial_edit_under_the_field_pin(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        # Anti-churn: an edit confined to prose (note/reason) moves the
        # whole-file digest -- simulated by moving registry_sha256 -- but not
        # the statement_set_id, so the field pin holds where a file-digest
        # pin would have forced a family epoch for an editorial change.
        registry["statements"][0]["note"] = "reworded editorial note"
        registry["retired_statements"][0]["reason"] = "reworded retirement reason"
        registry["family_pin"]["revision_label"]["note"] = "reworded label note"
        registry["family_pin"]["statement_digest"]["reason"] = "reworded pin reason"
        sources["registry_sha256"] = "sha256:" + "ff" * 32

    def nonbreaking_revision_without_surface_move(
        registry: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        registry["revision"] += 1
        registry["revision_id"] = f"zkm:rev:{registry['revision']}"
        registry["revision_history"].append(
            {
                "revision": registry["revision"],
                "published": registry["published"],
                "breaking": False,
                "statement_set_id": registry["statement_set_id"],
                "summary": "editorial-only revision",
            }
        )

    return [
        ("ZKA adopts the digest pin", digest_pin_adopted),
        ("digest pin standing in for the revision label", digest_pin_instead_of_label),
        ("field pin standing in for the revision label", field_pin_instead_of_label),
        ("editorial prose edit under the field pin", editorial_edit_under_the_field_pin),
        ("non-breaking revision with unchanged statement identity", nonbreaking_revision_without_surface_move),
    ]


def self_test(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    """Prove every check has teeth by reintroducing the drift it must catch."""

    run_checks(copy.deepcopy(registry), copy.deepcopy(sources))
    control_source = sources["circuits"]["zkm_control_attestation"]
    with_decoys = (
        '// fn main( -> pub Field\n'
        '/* outer /* nested fn main( -> pub Field */ still comment */\n'
        'fn parser_decoy() { let marker = "fn main( // -> pub Field"; }\n'
        + control_source
    )
    require(
        parse_public_inputs(with_decoys, "zkm_control_attestation")
        == parse_public_inputs(control_source, "zkm_control_attestation"),
        "self-test: Noir comment or string decoy changed the public ABI",
    )
    for name, mutate in _accepted_variants():
        variant_registry = copy.deepcopy(registry)
        variant_sources = copy.deepcopy(sources)
        mutate(variant_registry, variant_sources)
        try:
            run_checks(variant_registry, variant_sources)
        except Failure as failure:
            raise Failure(
                f"self-test: accepted variant rejected -- {name}: {failure}"
            ) from None
    mutations = _mutations()
    if sources.get("pending_republish") is None:
        staging_only = {
            "staging marker deactivated",
            "staged statement ID authorization removed",
            "staged breaking revision authorization removed",
        }
        mutations = [item for item in mutations if item[0] not in staging_only]
    for name, mutate in mutations:
        mutated_registry = copy.deepcopy(registry)
        mutated_sources = copy.deepcopy(sources)
        mutate(mutated_registry, mutated_sources)
        direct_check = {
            "authority": check_statement_authority,
            "cutover": check_cutover_note,
            "abi": check_public_input_vectors,
            "history": check_revision_history,
            "shape": check_shape,
        }.get(name.split(":", 1)[0])
        if direct_check is not None:
            try:
                direct_check(mutated_registry, mutated_sources)
            except Failure:
                pass
            else:
                raise Failure(f"self-test: source-derived check did not catch -- {name}")
        try:
            run_checks(mutated_registry, mutated_sources)
        except Failure:
            continue
        raise Failure(f"self-test: mutation not caught -- {name}")
    print(
        "ZKM statement registry self-test: OK "
        f"({len(mutations)} mutations caught, "
        f"{len(_accepted_variants())} accepted variants still pass)"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="mutate the registry and its sources and require every check to fail closed",
    )
    args = parser.parse_args(argv)

    registry = json.loads(REGISTRY_PATH.read_bytes())
    sources = load_sources()
    try:
        check_encoders(REPO_ROOT, registry)
        if args.self_test:
            self_test(registry, sources)
        else:
            run_checks(registry, sources)
            print(
                "ZKM statement registry: OK "
                f"(rev {registry['revision']}, last breaking rev "
                f"{registry['last_breaking_revision']}, "
                f"{registry['statement_set_id']})"
            )
    except (Failure, ValueError, OSError) as failure:
        print(f"ZKM statement registry FAILED: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
