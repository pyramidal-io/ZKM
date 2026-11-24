#!/usr/bin/env python3
"""Validate the versioned ZKA/AFP/ZKC/ZKM protocol-family interface package."""

from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


FORMAT_ID = "zka:protocol-family:interfaces:v1"
ASSERTION_KINDS = {
    "json_pointer_equals",
    "json_array_equals",
    "text_contains",
    "text_excludes",
    "sha256_equals",
    "path_exists",
}
REPOSITORIES = ("zka", "afp", "zkc", "zkm")
SNAPSHOT_FILES = (
    ("manifest_sha256", "protocol-family/interface-manifest-v1.json"),
    ("schema_sha256", "protocol-family/interface-manifest-v1.schema.json"),
    ("vectors_sha256", "protocol-family/golden-vectors-v1.json"),
    ("validator_sha256", "scripts/validate_protocol_family.py"),
)
SNAPSHOT_LOCK_KEYS = {
    "format",
    "epoch",
    "canonical_repository",
    "canonical_commit",
    *(digest for digest, _ in SNAPSHOT_FILES),
}
PENDING_REPUBLISH_KEYS = {
    "target_epoch",
    "predecessor_epoch",
    "predecessor_commit",
}
STAGED_REPUBLISH_INTENT_KEYS = PENDING_REPUBLISH_KEYS | {
    "expires_at",
    "staging_sha256",
    "staged_projections",
}
STAGED_PENDING_REPUBLISH_KEYS = STAGED_REPUBLISH_INTENT_KEYS | {"staging_commit"}
STAGEABLE_ASSERTION_KINDS = {
    "json_pointer_equals",
    "json_array_equals",
    "text_contains",
    "sha256_equals",
}
STAGED_PROJECTION_KEYS = {
    "repository",
    "assertion_id",
    "kind",
    "path",
    "observed_value",
}
JSON_STAGED_PROJECTION_KEYS = STAGED_PROJECTION_KEYS | {"pointer"}
COMPATIBILITY_FIELDS = (
    "zka",
    "zkc",
    "afp",
    "kdc",
    "zkm",
    "bundle",
    "proof",
    "profile",
    "presentation_context_mode",
    "binding_circuit",
    "transaction",
)
PRESENTATION_CONTEXT_MODE = "afp:zkc-presentation-context:v2"
AFP_SESSION_CONTEXT = re.compile(r"^X_[0-9a-f]{64}$")
CANONICAL_FIELD = re.compile(r"^0x[0-9a-f]{64}$")
SHA256_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
BN254_SCALAR_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
AFP_TRUST_FLOWS = frozenset(
    {
        "afp:trust-flow:telemetry",
        "afp:trust-flow:bilateral",
        "afp:trust-flow:introduction",
        "afp:trust-flow:open-federation",
    }
)
TELEMETRY_PRESENTATION_PREDICATES = frozenset(
    {"afp.telemetry.instance_attestation.v2"}
)
PRESENTATION_PREDICATE_ID = re.compile(
    r"^(?:zkc:proof:[a-z0-9._-]+:v[0-9]+|"
    r"afp\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\.v[1-9][0-9]*)$"
)
PREDICATE_VERSION_TOKEN = re.compile(r"[.:]v(?P<version>[0-9]+)$")
WHOLE_SECOND_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
PROTOCOL_FAMILY_EPOCH = re.compile(
    r"^zka:protocol-family:[0-9]{4}-[0-9]{2}-[0-9]{2}\.[1-9][0-9]*$"
)
INSTANCE_ATTESTATION_PREDICATE_V2 = "afp.telemetry.instance_attestation.v2"
INSTANCE_ATTESTATION_ROOT_CLASSES = frozenset(
    {"root:build-provenance", "root:tee-attestation", "root:publisher-manifest"}
)
PREDICATE_RECORD_MEMBERS = frozenset(
    {
        "predicate_id",
        "predicate_version",
        "root_class",
        "root_authority_identifier",
        "attestation_window",
        "subject_aid",
    }
)
ATTESTATION_WINDOW_MEMBERS = frozenset({"starts_at", "ends_at"})
REQUIRED_PREDICATE_POLICY_MEMBERS = frozenset(
    {
        "accepted_predicate_ids",
        "required_predicate_ids",
        "accepted_instance_attestation_roots",
    }
)
ATTESTATION_ROOT_MEMBERS = frozenset(
    {"root_class", "root_authority_identifier"}
)
GOLDEN_ZKC_BUILTIN_PROFILE_COMPATIBILITY = {
    # This is deliberately limited to the reference identifiers used by this
    # vector package. It is not a global ZKC predicate catalog: syntactically
    # valid external proof types remain verifier-policy inputs under ZKC's
    # predicate-pluralism safeguard.
    "zkc:proof:kyc:v1": frozenset({"zkc:presentation:linkable:v1"}),
    "zkc:proof:kyc:v2": frozenset(
        {"zkc:presentation:anonymous:v1", "zkc:presentation:scoped:v1"}
    ),
    "zkc:proof:jurisdiction:v2": frozenset(
        {"zkc:presentation:anonymous:v1", "zkc:presentation:scoped:v1"}
    ),
    "zkc:proof:selective_disclosure:v1": frozenset(
        {"zkc:presentation:anonymous:v1", "zkc:presentation:scoped:v1"}
    ),
}
TOP_LEVEL_FIELDS = {
    "format",
    "epoch",
    "authority",
    "protocols",
    "toolchains",
    "interfaces",
    "domains",
    "invariants",
    "compatibility",
    "artifact_bindings",
    "projections",
    "vector_file",
}


class ProtocolFamilyError(Exception):
    """One deterministic protocol-family conformance error."""

    def __init__(self, code: str, location: str, message: str) -> None:
        self.code = code
        self.location = location
        self.message = message
        super().__init__(f"{code} {location}: {message}")


def _error_key(error: ProtocolFamilyError) -> tuple[str, str, str]:
    return (error.location, error.code, error.message)


def _is_full_commit(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def load_json(path: Path) -> Any:
    """Load a UTF-8 JSON document and normalize input failures."""

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolFamilyError("UNREADABLE_INPUT", str(path), str(exc)) from exc


def resolve_repo_path(root: Path, relative: str) -> Path:
    """Resolve a repository-relative path without permitting root escape."""

    candidate = Path(relative)
    if candidate.is_absolute():
        raise ProtocolFamilyError("PATH_ESCAPE", relative, "absolute paths are forbidden")
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ProtocolFamilyError(
            "PATH_ESCAPE", relative, "path escapes the repository root"
        ) from exc
    return resolved


def validate_manifest_structure(manifest: dict[str, Any]) -> list[ProtocolFamilyError]:
    """Validate fail-closed structural properties needed before projection."""

    errors: list[ProtocolFamilyError] = []
    for field in sorted(set(manifest) - TOP_LEVEL_FIELDS):
        errors.append(
            ProtocolFamilyError(
                "UNKNOWN_PROPERTY", f"/{field}", "top-level property is not allowed"
            )
        )
    for field in sorted(TOP_LEVEL_FIELDS - set(manifest)):
        errors.append(
            ProtocolFamilyError("MISSING_PROPERTY", f"/{field}", "required property")
        )
    if manifest.get("format") != FORMAT_ID:
        errors.append(
            ProtocolFamilyError(
                "UNKNOWN_FORMAT",
                "/format",
                f"expected {FORMAT_ID!r}, observed {manifest.get('format')!r}",
            )
        )

    seen: dict[str, str] = {}
    projections = manifest.get("projections", {})
    if not isinstance(projections, dict):
        projections = {}
        errors.append(
            ProtocolFamilyError("INVALID_TYPE", "/projections", "expected object")
        )

    for repository in REPOSITORIES:
        projection = projections.get(repository, {})
        assertions = projection.get("assertions", []) if isinstance(projection, dict) else []
        if not isinstance(assertions, list):
            errors.append(
                ProtocolFamilyError(
                    "INVALID_TYPE",
                    f"/projections/{repository}/assertions",
                    "expected array",
                )
            )
            continue
        for index, assertion in enumerate(assertions):
            location = f"/projections/{repository}/assertions/{index}"
            if not isinstance(assertion, dict):
                errors.append(ProtocolFamilyError("INVALID_TYPE", location, "expected object"))
                continue
            assertion_id = assertion.get("id")
            if not isinstance(assertion_id, str) or not assertion_id:
                errors.append(
                    ProtocolFamilyError("INVALID_ASSERTION_ID", f"{location}/id", "expected non-empty string")
                )
            elif assertion_id in seen:
                errors.append(
                    ProtocolFamilyError(
                        "DUPLICATE_ASSERTION",
                        f"{location}/id",
                        f"{assertion_id!r} already declared at {seen[assertion_id]}",
                    )
                )
            else:
                seen[assertion_id] = f"{location}/id"

            kind = assertion.get("kind")
            if kind not in ASSERTION_KINDS:
                errors.append(
                    ProtocolFamilyError(
                        "UNKNOWN_ASSERTION_KIND",
                        f"{location}/kind",
                        f"unsupported assertion kind {kind!r}",
                    )
                )

    combinations = manifest.get("compatibility", [])
    compatibility_seen: dict[tuple[Any, ...], str] = {}
    if isinstance(combinations, list):
        for index, combination in enumerate(combinations):
            if not isinstance(combination, dict):
                errors.append(
                    ProtocolFamilyError(
                        "INVALID_TYPE", f"/compatibility/{index}", "expected object"
                    )
                )
                continue
            signature = tuple(combination.get(field) for field in COMPATIBILITY_FIELDS)
            if signature in compatibility_seen:
                errors.append(
                    ProtocolFamilyError(
                        "DUPLICATE_COMPATIBILITY",
                        f"/compatibility/{index}",
                        f"duplicates {compatibility_seen[signature]}",
                    )
                )
            else:
                compatibility_seen[signature] = f"/compatibility/{index}"

    return sorted(errors, key=_error_key)


def match_compatibility(manifest: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """Return the single compatibility tuple matching a vector case."""

    combinations = manifest.get("compatibility", [])
    if not isinstance(combinations, list):
        raise ProtocolFamilyError(
            "INVALID_TYPE", "/compatibility", "expected array"
        )
    matches = [
        combination
        for combination in combinations
        if isinstance(combination, dict)
        and all(combination.get(field) == case.get(field) for field in COMPATIBILITY_FIELDS)
    ]
    if not matches:
        raise ProtocolFamilyError(
            "NO_COMPATIBILITY_MATCH",
            "/compatibility",
            "case matches no supported compatibility tuple",
        )
    if len(matches) != 1:
        identifiers = sorted(str(match.get("id")) for match in matches)
        raise ProtocolFamilyError(
            "AMBIGUOUS_COMPATIBILITY_MATCH",
            "/compatibility",
            f"case matches multiple tuples: {identifiers}",
        )
    return matches[0]


def _presentation_context_digest(derivation: Any) -> str | None:
    """Return the strict SHA-256/JCS reduced BN254 presentation context."""

    if not isinstance(derivation, dict) or set(derivation) != {
        "algorithm", "canonicalization", "trust_flow", "preimage", "sha256_digest", "field_context"
    }:
        return None
    if (
        derivation.get("algorithm") != "sha-256-mod-bn254-fr"
        or derivation.get("canonicalization") != "rfc8785-jcs"
        or derivation.get("trust_flow") not in AFP_TRUST_FLOWS
        or not isinstance(derivation.get("sha256_digest"), str)
        or not isinstance(derivation.get("field_context"), str)
    ):
        return None
    preimage = derivation.get("preimage")
    if not isinstance(preimage, dict) or set(preimage) != {
        "kind", "purpose", "credential_subject_aid", "session_context",
        "apr_verifier_aid", "presentation_profile", "scope_policy",
    }:
        return None
    if (
        preimage.get("kind") != PRESENTATION_CONTEXT_MODE
        or preimage.get("purpose") != derivation.get("trust_flow")
        or any(not isinstance(preimage.get(field), str) or not preimage[field] for field in (
            "purpose", "credential_subject_aid", "session_context", "apr_verifier_aid",
            "presentation_profile",
        ))
    ):
        return None
    profile = preimage["presentation_profile"]
    scope_policy = preimage.get("scope_policy")
    if (
        (profile == "zkc:presentation:scoped:v1" and (
            not isinstance(scope_policy, str)
            or not scope_policy.startswith("protocol:afp:")
            or not scope_policy[len("protocol:afp:"):]
        ))
        or (profile in {"zkc:presentation:anonymous:v1", "zkc:presentation:linkable:v1"} and scope_policy is not None)
        or profile not in {
            "zkc:presentation:anonymous:v1", "zkc:presentation:linkable:v1", "zkc:presentation:scoped:v1"
        }
    ):
        return None
    canonical = json.dumps(
        preimage, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    raw = "0x" + digest.hex()
    reduced = int.from_bytes(digest, "big") % BN254_SCALAR_MODULUS
    field_context = "0x" + format(reduced, "064x")
    if (
        reduced == 0
        or derivation["sha256_digest"] != raw
        or derivation["field_context"] != field_context
    ):
        return None
    return field_context


def _afp_session_context_field(session_context: str) -> str | None:
    """Project one exact AFP ``X_`` session digest into canonical BN254 Fr."""

    if AFP_SESSION_CONTEXT.fullmatch(session_context) is None:
        return None
    reduced = int(session_context[2:], 16) % BN254_SCALAR_MODULUS
    if reduced == 0:
        return None
    return "0x" + format(reduced, "064x")


def _is_nonzero_canonical_bn254_field(value: object) -> bool:
    """Return whether ``value`` is an exact nonzero canonical BN254 scalar."""

    return (
        isinstance(value, str)
        and CANONICAL_FIELD.fullmatch(value) is not None
        and 0 < int(value[2:], 16) < BN254_SCALAR_MODULUS
    )


def _is_whole_second_utc(value: object) -> bool:
    """Return whether ``value`` is a real canonical whole-second UTC instant."""

    if not isinstance(value, str) or WHOLE_SECOND_UTC.fullmatch(value) is None:
        return False
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _predicate_record_failure(record: object) -> str | None:
    """Validate the exact language-neutral serialization of AFP ProvenPredicate."""

    if not isinstance(record, dict) or set(record) != PREDICATE_RECORD_MEMBERS:
        return "VERIFIED_PREDICATE_RECORD_INVALID"
    predicate_id = record.get("predicate_id")
    predicate_version = record.get("predicate_version")
    if (
        not isinstance(predicate_id, str)
        or not predicate_id
        or PRESENTATION_PREDICATE_ID.fullmatch(predicate_id) is None
        or not isinstance(predicate_version, str)
        or not predicate_version
    ):
        return "VERIFIED_PREDICATE_RECORD_INVALID"
    version_match = PREDICATE_VERSION_TOKEN.search(predicate_id)
    if version_match is None or version_match.group("version") != predicate_version:
        return "VERIFIED_PREDICATE_RECORD_INVALID"

    root_class = record.get("root_class")
    root_authority = record.get("root_authority_identifier")
    window = record.get("attestation_window")
    subject_aid = record.get("subject_aid")
    is_instance_attestation = predicate_id == INSTANCE_ATTESTATION_PREDICATE_V2

    if is_instance_attestation:
        if (
            not isinstance(root_class, str)
            or root_class not in INSTANCE_ATTESTATION_ROOT_CLASSES
        ):
            return "INSTANCE_ATTESTATION_ROOT_CLASS_UNSUPPORTED"
        if not isinstance(root_authority, str) or not root_authority:
            return "INSTANCE_ATTESTATION_ROOT_UNACCEPTED"
        if (
            not isinstance(window, dict)
            or set(window) != ATTESTATION_WINDOW_MEMBERS
            or not _is_whole_second_utc(window.get("starts_at"))
            or not _is_whole_second_utc(window.get("ends_at"))
            or window["starts_at"] >= window["ends_at"]
        ):
            return "INSTANCE_ATTESTATION_WINDOW_INVALID"
        if not isinstance(subject_aid, str) or not subject_aid:
            return "INSTANCE_ATTESTATION_SUBJECT_INVALID"
        return None

    # AFP freezes v1 and every non-v2 predicate against reinterpretation as a
    # generic root-bearing attestation. Window/subject remain available to
    # other versioned predicates and are therefore shape-checked, not forbidden.
    if root_class is not None or root_authority is not None:
        return "VERIFIED_PREDICATE_RECORD_INVALID"
    if window is not None and (
        not isinstance(window, dict)
        or set(window) != ATTESTATION_WINDOW_MEMBERS
        or not _is_whole_second_utc(window.get("starts_at"))
        or not _is_whole_second_utc(window.get("ends_at"))
        or window["starts_at"] >= window["ends_at"]
    ):
        return "VERIFIED_PREDICATE_RECORD_INVALID"
    if subject_aid is not None and (
        not isinstance(subject_aid, str) or not subject_aid
    ):
        return "VERIFIED_PREDICATE_RECORD_INVALID"
    return None


def _required_predicate_policy(
    value: object,
) -> tuple[frozenset[str], frozenset[str], frozenset[tuple[str, str]]] | None:
    """Parse the vector-only caller policy comparand used by the AFP seam."""

    if not isinstance(value, dict) or set(value) != REQUIRED_PREDICATE_POLICY_MEMBERS:
        return None
    accepted = value.get("accepted_predicate_ids")
    required = value.get("required_predicate_ids")
    roots = value.get("accepted_instance_attestation_roots")
    if (
        not isinstance(accepted, list)
        or not accepted
        or not isinstance(required, list)
        or not isinstance(roots, list)
        or any(
            not isinstance(predicate_id, str)
            or PRESENTATION_PREDICATE_ID.fullmatch(predicate_id) is None
            for predicate_id in accepted + required
        )
        or len(set(accepted)) != len(accepted)
        or len(set(required)) != len(required)
        or accepted != sorted(accepted)
        or required != sorted(required)
    ):
        return None

    root_pairs: list[tuple[str, str]] = []
    for root in roots:
        if (
            not isinstance(root, dict)
            or set(root) != ATTESTATION_ROOT_MEMBERS
            or not isinstance(root.get("root_class"), str)
            or root["root_class"] not in INSTANCE_ATTESTATION_ROOT_CLASSES
            or not isinstance(root.get("root_authority_identifier"), str)
            or not root["root_authority_identifier"]
        ):
            return None
        root_pairs.append((root["root_class"], root["root_authority_identifier"]))
    if len(set(root_pairs)) != len(root_pairs) or root_pairs != sorted(root_pairs):
        return None

    accepted_set = frozenset(accepted)
    required_set = frozenset(required)
    root_set = frozenset(root_pairs)
    if not required_set.issubset(accepted_set):
        return None
    accepts_instance_attestation = INSTANCE_ATTESTATION_PREDICATE_V2 in accepted_set
    if accepts_instance_attestation != bool(root_set):
        return None
    return accepted_set, required_set, root_set


def evaluate_vector_case(manifest: dict[str, Any], case: dict[str, Any]) -> str | None:
    """Evaluate one serialized cross-protocol case and return its stable failure code."""

    compatibility = case.get("compatibility", {})
    if not isinstance(compatibility, dict):
        return "INVALID_VECTOR_CASE"
    proof = compatibility.get("proof")
    profile = compatibility.get("profile")
    if proof == "zkc:proof:v1" and profile != "zkc:presentation:linkable:v1":
        return "PROFILE_MISMATCH"
    if proof == "zkc:proof:v2" and profile not in {
        "zkc:presentation:anonymous:v1",
        "zkc:presentation:scoped:v1",
    }:
        return "PROFILE_MISMATCH"

    effective_manifest = manifest
    mutation = case.get("manifest_mutation")
    if isinstance(mutation, dict) and "duplicate_combination_id" in mutation:
        effective_manifest = copy.deepcopy(manifest)
        source_id = mutation["duplicate_combination_id"]
        source = next(
            (
                combination
                for combination in effective_manifest.get("compatibility", [])
                if combination.get("id") == source_id
            ),
            None,
        )
        if source is None:
            return "INVALID_VECTOR_CASE"
        effective_manifest["compatibility"].append(
            {**source, "id": f"{source_id}-duplicate"}
        )
    try:
        match_compatibility(effective_manifest, compatibility)
    except ProtocolFamilyError as error:
        return error.code

    afp = case.get("afp", {})
    zka = case.get("zka", {})
    zkc = case.get("zkc", {})
    if not all(isinstance(value, dict) for value in (afp, zka, zkc)):
        return "INVALID_VECTOR_CASE"
    if compatibility.get("presentation_context_mode") != PRESENTATION_CONTEXT_MODE:
        return "PRESENTATION_CONTEXT_MODE_MISMATCH"

    session_context = afp.get("session_context")
    session_context_field = afp.get("session_context_field")
    presentation_context = afp.get("presentation_proof_context")
    if (
        afp.get("presentation_context_mode") != PRESENTATION_CONTEXT_MODE
        or not isinstance(presentation_context, str)
        or not isinstance(zka.get("bundle_context"), str)
        or not isinstance(zkc.get("proof_context"), str)
    ):
        return "INVALID_VECTOR_CONTEXT"
    if not _is_nonzero_canonical_bn254_field(
        presentation_context
    ) or not _is_nonzero_canonical_bn254_field(zkc.get("proof_context")):
        return "INVALID_VECTOR_CONTEXT"
    if not isinstance(session_context, str) or AFP_SESSION_CONTEXT.fullmatch(session_context) is None:
        return "INVALID_SESSION_CONTEXT"
    reduced_session_context = int(session_context[2:], 16) % BN254_SCALAR_MODULUS
    if reduced_session_context == 0:
        return "ZERO_SESSION_CONTEXT_PROJECTION"
    expected_session_context_field = _afp_session_context_field(session_context)
    assert expected_session_context_field is not None
    if session_context_field != expected_session_context_field:
        return "SESSION_CONTEXT_PROJECTION_MISMATCH"
    if zka.get("bundle_context") != expected_session_context_field:
        return "SESSION_CONTEXT_MISMATCH"
    transaction_present = zka.get("transaction_present") is True
    if transaction_present:
        if zka.get("transaction_context") != expected_session_context_field:
            return "SESSION_CONTEXT_MISMATCH"
    elif "transaction_context" in zka:
        return "INVALID_VECTOR_CONTEXT"
    if zka.get("coord_proof_present") is True:
        if zka.get("coord_context") != expected_session_context_field:
            return "SESSION_CONTEXT_MISMATCH"
    elif "coord_context" in zka:
        return "INVALID_VECTOR_CONTEXT"
    for participant, context in ((afp, presentation_context), (zkc, zkc.get("proof_context"))):
        if "presentation_context_derivation" not in participant:
            continue
        digest = _presentation_context_digest(participant["presentation_context_derivation"])
        if digest is None or digest != context:
            return "PRESENTATION_CONTEXT_DERIVATION_MISMATCH"
        preimage = participant["presentation_context_derivation"]["preimage"]
        if preimage["session_context"] != session_context or preimage["presentation_profile"] != profile:
            return "PRESENTATION_CONTEXT_DERIVATION_MISMATCH"
    if zkc.get("proof_context") != presentation_context:
        return "PRESENTATION_CONTEXT_MISMATCH"
    if "presentation_context_derivation" in afp:
        result = afp.get("presentation_result")
        zkc_derivation = zkc.get("presentation_context_derivation")
        assurance = afp.get("presentation_subject_assurance")
        if not isinstance(result, dict) or set(result) != {
            "proof_context", "credential_subject_aid", "proven_predicates"
        } or not isinstance(assurance, dict) or set(assurance) != {"basis"} or not isinstance(zkc_derivation, dict):
            return "VERIFIED_SUBJECT_REQUIRED"
        if (
            result.get("proof_context") != presentation_context
            or not isinstance(result.get("credential_subject_aid"), str)
            or not result["credential_subject_aid"]
            or assurance.get("basis") not in {
                "issuer-authenticated-aid-claim", "verified-companion-subject-binding-proof"
            }
        ):
            return "VERIFIED_SUBJECT_REQUIRED"
        predicates = result.get("proven_predicates")
        if not isinstance(predicates, list) or not predicates:
            return "VERIFIED_PREDICATE_REQUIRED"
        for predicate in predicates:
            if failure := _predicate_record_failure(predicate):
                return failure
        predicate_ids = [predicate["predicate_id"] for predicate in predicates]
        if len(set(predicate_ids)) != len(predicate_ids):
            return "VERIFIED_PREDICATE_RECORD_INVALID"

        policy = _required_predicate_policy(afp.get("required_predicate_policy"))
        if policy is None:
            return "VERIFIED_PREDICATE_POLICY_INVALID"
        accepted_predicates, required_predicates, accepted_roots = policy
        if any(
            profile not in allowed_profiles
            for predicate in predicate_ids
            if (
                allowed_profiles := GOLDEN_ZKC_BUILTIN_PROFILE_COMPATIBILITY.get(
                    predicate
                )
            )
            is not None
        ):
            return "VERIFIED_PREDICATE_PROFILE_MISMATCH"
        if (
            afp["presentation_context_derivation"]["trust_flow"] == "afp:trust-flow:telemetry"
            and not all(predicate in TELEMETRY_PRESENTATION_PREDICATES for predicate in predicate_ids)
        ):
            return "VERIFIED_PREDICATE_POLICY_MISMATCH"
        proven_predicates = frozenset(predicate_ids)
        if (
            not proven_predicates.issubset(accepted_predicates)
            or not required_predicates.issubset(proven_predicates)
        ):
            return "VERIFIED_PREDICATE_POLICY_MISMATCH"
        for predicate in predicates:
            if predicate["predicate_id"] != INSTANCE_ATTESTATION_PREDICATE_V2:
                continue
            root_pair = (
                predicate["root_class"],
                predicate["root_authority_identifier"],
            )
            if root_pair not in accepted_roots:
                return "INSTANCE_ATTESTATION_ROOT_UNACCEPTED"
        afp_subject = afp["presentation_context_derivation"]["preimage"]["credential_subject_aid"]
        zkc_subject = zkc_derivation.get("preimage", {}).get("credential_subject_aid")
        if (
            result["credential_subject_aid"] != afp_subject
            or result["credential_subject_aid"] != zkc_subject
            or
            "note_subject" in zka
            and zka.get("note_subject") != result["credential_subject_aid"]
        ):
            return "VERIFIED_SUBJECT_MISMATCH"
    if profile == "zkc:presentation:scoped:v1" and (
        "scope_id" in afp and afp.get("scope_id") != zkc.get("scope_id")
    ):
        return "SCOPE_MISMATCH"
    if (
        "note_subject" in zka
        and "credential_subject" in zkc
        and zka.get("note_subject") != zkc.get("credential_subject")
    ):
        return "SUBJECT_MISMATCH"
    if zka.get("binding_circuit") != compatibility.get("binding_circuit"):
        return "BINDING_CIRCUIT_MISMATCH"
    if compatibility.get("transaction") == "required" and not transaction_present:
        return "TRANSACTION_REQUIRED"
    if compatibility.get("transaction") == "forbidden" and transaction_present:
        return "TRANSACTION_FORBIDDEN"
    if not transaction_present and zka.get("coord_proof_present") is not True:
        return "EMPTY_BUNDLE"
    if profile == "zkc:presentation:anonymous:v1" and (
        zkc.get("presentation_pseudonym") != "0x00" or zkc.get("scope_id") != "0x00"
    ):
        return "ANONYMOUS_SENTINEL_MISMATCH"
    if profile == "zkc:presentation:scoped:v1" and (
        zkc.get("presentation_pseudonym") in {None, "0x00"}
        or zkc.get("scope_id") in {None, "0x00"}
    ):
        return "SCOPED_HANDLE_MISSING"
    # Every otherwise-accepted AFP v2 vector must carry the complete
    # presentation contract.  Keep this gate after the specific rejection
    # checks above so legacy negative vectors retain their declared failure
    # codes, while a stripped accepted vector cannot silently pass.
    if (
        "presentation_context_derivation" not in afp
        or "presentation_context_derivation" not in zkc
        or "presentation_result" not in afp
        or "required_predicate_policy" not in afp
        or "presentation_subject_assurance" not in afp
    ):
        return "PRESENTATION_CONTEXT_DERIVATION_MISMATCH"
    return None


def _json_pointer(document: Any, pointer: str, location: str) -> Any:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ProtocolFamilyError(
            "INVALID_JSON_POINTER", location, f"pointer must start with '/': {pointer!r}"
        )
    current = document
    for encoded in pointer[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        try:
            if isinstance(current, list):
                current = current[int(token)]
            elif isinstance(current, dict):
                current = current[token]
            else:
                raise KeyError(token)
        except (KeyError, IndexError, ValueError) as exc:
            raise ProtocolFamilyError(
                "JSON_POINTER_MISSING", location, f"missing pointer segment {token!r}"
            ) from exc
    return current


def _matches_json_type(value: Any, expected: str) -> bool:
    types = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    predicate = types.get(expected)
    return predicate(value) if predicate is not None else False


def validate_json_schema(
    document: Any,
    schema: dict[str, Any],
    *,
    root_schema: dict[str, Any] | None = None,
    location: str = "",
) -> list[ProtocolFamilyError]:
    """Evaluate the strict JSON Schema subset used by the family manifest."""

    root_schema = schema if root_schema is None else root_schema
    if "$ref" in schema:
        reference = schema["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/"):
            return [ProtocolFamilyError("SCHEMA_INVALID_REF", location or "/", str(reference))]
        try:
            resolved = _json_pointer(root_schema, reference[1:], "schema")
        except ProtocolFamilyError as error:
            return [error]
        if not isinstance(resolved, dict):
            return [ProtocolFamilyError("SCHEMA_INVALID_REF", location or "/", reference)]
        return validate_json_schema(
            document, resolved, root_schema=root_schema, location=location
        )

    errors: list[ProtocolFamilyError] = []
    shown_location = location or "/"
    expected_type = schema.get("type")
    if expected_type is not None:
        expected_types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(
            isinstance(item, str) and _matches_json_type(document, item)
            for item in expected_types
        ):
            return [
                ProtocolFamilyError(
                    "SCHEMA_TYPE_MISMATCH",
                    shown_location,
                    f"expected {expected_type!r}, observed {type(document).__name__}",
                )
            ]
    if "const" in schema and document != schema["const"]:
        errors.append(
            ProtocolFamilyError(
                "SCHEMA_CONST_MISMATCH",
                shown_location,
                f"expected {schema['const']!r}, observed {document!r}",
            )
        )
    if "enum" in schema and document not in schema["enum"]:
        errors.append(
            ProtocolFamilyError(
                "SCHEMA_ENUM_MISMATCH",
                shown_location,
                f"expected one of {schema['enum']!r}, observed {document!r}",
            )
        )
    if isinstance(document, str):
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, document) is None:
            errors.append(
                ProtocolFamilyError(
                    "SCHEMA_PATTERN_MISMATCH", shown_location, f"does not match {pattern!r}"
                )
            )
        if schema.get("format") == "date":
            try:
                datetime.date.fromisoformat(document)
            except ValueError:
                errors.append(
                    ProtocolFamilyError(
                        "SCHEMA_FORMAT_MISMATCH", shown_location, "expected ISO 8601 date"
                    )
                )
    if isinstance(document, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for key in required:
            if key not in document:
                errors.append(
                    ProtocolFamilyError(
                        "SCHEMA_MISSING_PROPERTY",
                        f"{location}/{key}",
                        "required property",
                    )
                )
        if schema.get("additionalProperties") is False:
            for key in set(document) - set(properties):
                errors.append(
                    ProtocolFamilyError(
                        "SCHEMA_UNKNOWN_PROPERTY",
                        f"{location}/{key}",
                        "property is not allowed",
                    )
                )
        for key, value in document.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                errors.extend(
                    validate_json_schema(
                        value,
                        child_schema,
                        root_schema=root_schema,
                        location=f"{location}/{key}",
                    )
                )
    if isinstance(document, list):
        minimum = schema.get("minItems")
        if isinstance(minimum, int) and len(document) < minimum:
            errors.append(
                ProtocolFamilyError(
                    "SCHEMA_MIN_ITEMS", shown_location, f"expected at least {minimum} items"
                )
            )
        if schema.get("uniqueItems") is True:
            serialized = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in document]
            if len(serialized) != len(set(serialized)):
                errors.append(
                    ProtocolFamilyError(
                        "SCHEMA_DUPLICATE_ITEM", shown_location, "array items must be unique"
                    )
                )
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, value in enumerate(document):
                errors.extend(
                    validate_json_schema(
                        value,
                        item_schema,
                        root_schema=root_schema,
                        location=f"{location}/{index}",
                    )
                )
    return sorted(errors, key=_error_key)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ProtocolFamilyError("UNREADABLE_INPUT", str(path), str(exc)) from exc
    return "sha256:" + digest.hexdigest()


def evaluate_assertion(
    root: Path, assertion: dict[str, Any]
) -> list[ProtocolFamilyError]:
    """Evaluate one declarative repository projection assertion."""

    assertion_id = str(assertion.get("id", "<missing>"))
    kind = assertion.get("kind")
    location = f"assertion:{assertion_id}"
    if kind not in ASSERTION_KINDS:
        return [
            ProtocolFamilyError(
                "UNKNOWN_ASSERTION_KIND", location, f"unsupported assertion kind {kind!r}"
            )
        ]
    try:
        path = resolve_repo_path(root, str(assertion.get("path", "")))
    except ProtocolFamilyError as error:
        return [error]

    if kind == "path_exists":
        return [] if path.exists() else [
            ProtocolFamilyError("PATH_MISSING", location, str(path))
        ]
    if not path.is_file():
        return [ProtocolFamilyError("PATH_MISSING", location, str(path))]

    expected = assertion.get("expected")
    try:
        if kind in {"json_pointer_equals", "json_array_equals"}:
            observed = _json_pointer(
                load_json(path), str(assertion.get("pointer", "")), location
            )
            if kind == "json_array_equals" and (
                not isinstance(expected, list) or not isinstance(observed, list)
            ):
                return [
                    ProtocolFamilyError(
                        "INVALID_TYPE", location, "ordered-array assertion requires arrays"
                    )
                ]
            if observed != expected:
                code = "ARRAY_MISMATCH" if kind == "json_array_equals" else "JSON_MISMATCH"
                return [
                    ProtocolFamilyError(
                        code, location, f"expected {expected!r}, observed {observed!r}"
                    )
                ]
            return []

        if kind in {"text_contains", "text_excludes"}:
            observed_text = path.read_text(encoding="utf-8")
            needle = str(expected)
            present = needle in observed_text
            if kind == "text_contains" and not present:
                return [
                    ProtocolFamilyError("TEXT_MISSING", location, f"required {needle!r}")
                ]
            if kind == "text_excludes" and present:
                return [
                    ProtocolFamilyError("FORBIDDEN_TEXT", location, f"found {needle!r}")
                ]
            return []

        observed_digest = _sha256(path)
        if observed_digest != expected:
            return [
                ProtocolFamilyError(
                    "SHA256_MISMATCH",
                    location,
                    f"expected {expected!r}, observed {observed_digest!r}",
                )
            ]
        return []
    except (OSError, UnicodeError) as exc:
        return [ProtocolFamilyError("UNREADABLE_INPUT", location, str(exc))]
    except ProtocolFamilyError as error:
        return [error]


def validate_projection(
    root: Path,
    manifest: dict[str, Any],
    repository: str,
    *,
    pending_republish: dict[str, Any] | None = None,
) -> list[ProtocolFamilyError]:
    """Evaluate a projection, including only exact component-staging replacements."""

    projections = manifest.get("projections")
    if not isinstance(projections, dict):
        return [ProtocolFamilyError("INVALID_TYPE", "/projections", "expected object")]
    projection = projections.get(repository)
    if not isinstance(projection, dict):
        return [
            ProtocolFamilyError(
                "PROJECTION_MISSING", f"/projections/{repository}", "expected object"
            )
        ]
    staged_by_assertion: dict[str, dict[str, Any]] = {}
    if (
        pending_republish is not None
        and _pending_republish_phase(pending_republish, manifest) == "component_staging"
    ):
        staged_by_assertion = {
            str(entry.get("assertion_id")): entry
            for entry in pending_republish.get("staged_projections", [])
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("assertion_id"), str)
                and entry.get("repository") == repository
            )
        }
    errors: list[ProtocolFamilyError] = []
    for assertion in projection.get("assertions", []):
        if isinstance(assertion, dict):
            assertion_errors = evaluate_assertion(root, assertion)
            if not assertion_errors:
                continue
            staged = staged_by_assertion.get(str(assertion.get("id", "")))
            if staged is None:
                errors.extend(assertion_errors)
                continue
            replacement = dict(assertion)
            replacement["expected"] = staged["observed_value"]
            staged_errors = evaluate_assertion(root, replacement)
            if staged_errors:
                errors.extend(assertion_errors)
                errors.append(
                    ProtocolFamilyError(
                        "STAGED_PROJECTION_VALUE_MISMATCH",
                        f"assertion:{assertion.get('id', '<missing>')}",
                        f"component matches neither the frozen value nor staged value {staged['observed_value']!r}",
                    )
                )
    return sorted(errors, key=_error_key)


def validate_vectors(
    vectors: dict[str, Any], manifest: dict[str, Any]
) -> list[ProtocolFamilyError]:
    """Validate vector identity, epoch, case IDs, and declared consumption."""

    errors: list[ProtocolFamilyError] = []
    if vectors.get("format") != "zka:protocol-family:vectors:v1":
        errors.append(
            ProtocolFamilyError(
                "UNKNOWN_VECTOR_FORMAT", "/format", f"observed {vectors.get('format')!r}"
            )
        )
    if vectors.get("epoch") != manifest.get("epoch"):
        errors.append(
            ProtocolFamilyError(
                "VECTOR_EPOCH_MISMATCH",
                "/epoch",
                f"expected {manifest.get('epoch')!r}, observed {vectors.get('epoch')!r}",
            )
        )
    cases = vectors.get("cases", [])
    if not isinstance(cases, list):
        return errors + [ProtocolFamilyError("INVALID_TYPE", "/cases", "expected array")]
    seen: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(
                ProtocolFamilyError("INVALID_TYPE", f"/cases/{index}", "expected object")
            )
            continue
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            errors.append(
                ProtocolFamilyError(
                    "INVALID_VECTOR_CASE", f"/cases/{index}/case_id", "expected non-empty string"
                )
            )
        elif case_id in seen:
            errors.append(
                ProtocolFamilyError(
                    "DUPLICATE_VECTOR_CASE", f"/cases/{index}/case_id", case_id
                )
            )
        else:
            seen.add(case_id)
        observed = evaluate_vector_case(manifest, case)
        expected = case.get("expected")
        expected_code = None if expected == "accept" else case.get("failure_code")
        if expected not in {"accept", "reject"}:
            errors.append(
                ProtocolFamilyError(
                    "INVALID_VECTOR_EXPECTATION",
                    f"/cases/{index}/expected",
                    f"observed {expected!r}",
                )
            )
        elif observed != expected_code:
            errors.append(
                ProtocolFamilyError(
                    "VECTOR_OUTCOME_MISMATCH",
                    f"/cases/{index}",
                    f"expected {expected_code!r}, observed {observed!r}",
                )
            )
    projections = manifest.get("projections")
    if not isinstance(projections, dict):
        errors.append(ProtocolFamilyError("INVALID_TYPE", "/projections", "expected object"))
        return sorted(errors, key=_error_key)
    for repository in REPOSITORIES:
        projection = projections.get(repository, {})
        consumed = projection.get("vector_cases", []) if isinstance(projection, dict) else []
        if set(consumed) != seen:
            errors.append(
                ProtocolFamilyError(
                    "VECTOR_CONSUMPTION_MISMATCH",
                    f"/projections/{repository}/vector_cases",
                    f"expected {sorted(seen)!r}, observed {sorted(set(consumed))!r}",
                )
            )
    return sorted(errors, key=_error_key)


def validate_matrix(path: Path, manifest: dict[str, Any]) -> list[ProtocolFamilyError]:
    """Compare the Markdown compatibility table with manifest tuples."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return [ProtocolFamilyError("UNREADABLE_INPUT", str(path), str(exc))]
    rows: list[tuple[str, ...]] = []
    for line in lines:
        if not line.startswith("|") or line.startswith("|---") or "Combination ID" in line:
            continue
        cells = tuple(cell.strip() for cell in line.strip("|").split("|"))
        if len(cells) == 13:
            rows.append(cells)
    expected = []
    for combination in manifest.get("compatibility", []):
        expected.append(
            (
                str(combination.get("id")),
                str(combination.get("zka")),
                str(combination.get("zkc")),
                str(combination.get("afp")),
                str(combination.get("kdc")),
                str(combination.get("zkm")),
                str(combination.get("bundle")),
                str(combination.get("proof")),
                str(combination.get("profile")),
                "—" if combination.get("binding_circuit") is None else str(combination.get("binding_circuit")),
                str(combination.get("transaction")),
                str(combination.get("presentation_context_mode")),
                str(combination.get("state")),
            )
        )
    if rows != expected:
        return [
            ProtocolFamilyError(
                "MATRIX_MISMATCH", str(path), f"expected {expected!r}, observed {rows!r}"
            )
        ]
    return []


def validate_artifact_bindings(
    root: Path, manifest: dict[str, Any], repository: str
) -> list[ProtocolFamilyError]:
    """Validate immutable artifacts owned by the selected repository."""

    errors: list[ProtocolFamilyError] = []
    for index, binding in enumerate(manifest.get("artifact_bindings", [])):
        if not isinstance(binding, dict) or binding.get("repository") != repository:
            continue
        location = f"/artifact_bindings/{index}"
        try:
            path = resolve_repo_path(root, str(binding.get("path", "")))
            observed = _sha256(path)
        except ProtocolFamilyError as error:
            errors.append(error)
            continue
        if observed != binding.get("sha256"):
            errors.append(
                ProtocolFamilyError(
                    "SHA256_MISMATCH",
                    location,
                    f"expected {binding.get('sha256')!r}, observed {observed!r}",
                )
            )
    return sorted(errors, key=_error_key)


def _pending_republish_phase(
    pending: dict[str, Any], manifest: dict[str, Any]
) -> str:
    """Return the state selected by a structurally valid pending marker."""

    if "staged_projections" not in pending:
        return "canonical_republish"
    if "staging_commit" not in pending:
        return "staging_intent"
    if manifest.get("epoch") == pending.get("predecessor_epoch"):
        return "component_staging"
    if manifest.get("epoch") == pending.get("target_epoch"):
        return "epoch_finalization"
    return "invalid"


def _manifest_assertion(
    manifest: dict[str, Any], repository: str, assertion_id: str
) -> dict[str, Any] | None:
    projections = manifest.get("projections")
    projection = projections.get(repository) if isinstance(projections, dict) else None
    assertions = projection.get("assertions") if isinstance(projection, dict) else None
    if not isinstance(assertions, list):
        return None
    matches = [
        assertion
        for assertion in assertions
        if isinstance(assertion, dict) and assertion.get("id") == assertion_id
    ]
    return matches[0] if len(matches) == 1 else None


def _parse_whole_second_utc(value: object) -> datetime.datetime | None:
    if not isinstance(value, str) or WHOLE_SECOND_UTC.fullmatch(value) is None:
        return None
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
    except ValueError:
        return None


def _protocol_family_epoch_key(value: str) -> tuple[datetime.date, int] | None:
    if PROTOCOL_FAMILY_EPOCH.fullmatch(value) is None:
        return None
    date_text, sequence_text = value.rsplit(":", 1)[1].rsplit(".", 1)
    try:
        return datetime.date.fromisoformat(date_text), int(sequence_text)
    except ValueError:
        return None


def _staging_sha256(pending: dict[str, Any]) -> str:
    preimage = {
        key: pending.get(key)
        for key in (
            "target_epoch",
            "predecessor_epoch",
            "predecessor_commit",
            "expires_at",
            "staged_projections",
        )
    }
    encoded = json.dumps(
        preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(
        b"zka:protocol-family:component-staging:v1\x00" + encoded
    ).hexdigest()


def _validate_staged_projections(
    root: Path,
    lock_path: Path,
    pending: dict[str, Any],
    manifest: dict[str, Any],
    *,
    as_of: datetime.datetime | None = None,
) -> list[ProtocolFamilyError]:
    """Validate exact, bounded replacements for component-owned projections."""

    errors: list[ProtocolFamilyError] = []
    validation_time: datetime.datetime | None
    if as_of is None:
        validation_time = datetime.datetime.now(datetime.timezone.utc)
    elif as_of.tzinfo is None or as_of.utcoffset() is None:
        validation_time = None
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_INVALID",
                "validation_time",
                "as_of must be timezone-aware",
            )
        )
    else:
        validation_time = as_of.astimezone(datetime.timezone.utc)
    staging_sha256 = pending.get("staging_sha256")
    derived_staging_sha256 = _staging_sha256(pending)
    if (
        not isinstance(staging_sha256, str)
        or SHA256_ID.fullmatch(staging_sha256) is None
        or staging_sha256 != derived_staging_sha256
    ):
        errors.append(
            ProtocolFamilyError(
                "STAGING_DIGEST_MISMATCH",
                f"{lock_path}:pending_republish:staging_sha256",
                f"expected {derived_staging_sha256!r}, observed {staging_sha256!r}",
            )
        )
    expires_at = _parse_whole_second_utc(pending.get("expires_at"))
    if expires_at is None:
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_INVALID",
                f"{lock_path}:pending_republish:expires_at",
                "expected a real whole-second UTC timestamp",
            )
        )
    elif validation_time is not None and expires_at <= validation_time:
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_EXPIRED",
                f"{lock_path}:pending_republish:expires_at",
                f"staging expired at {pending.get('expires_at')}",
            )
        )

    staged = pending.get("staged_projections")
    if not isinstance(staged, list) or not staged:
        return errors + [
            ProtocolFamilyError(
                "PENDING_REPUBLISH_INVALID",
                f"{lock_path}:pending_republish:staged_projections",
                "expected a non-empty array",
            )
        ]

    phase = _pending_republish_phase(pending, manifest)
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(staged):
        location = f"{lock_path}:pending_republish:staged_projections:{index}"
        if not isinstance(entry, dict):
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID", location, "expected object"
                )
            )
            continue
        kind = entry.get("kind")
        expected_keys = (
            JSON_STAGED_PROJECTION_KEYS
            if kind in {"json_pointer_equals", "json_array_equals"}
            else STAGED_PROJECTION_KEYS
        )
        if set(entry) != expected_keys:
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    location,
                    f"expected keys {sorted(expected_keys)!r}, observed {sorted(entry)!r}",
                )
            )
            continue
        repository = entry.get("repository")
        assertion_id = entry.get("assertion_id")
        path = entry.get("path")
        if repository not in REPOSITORIES:
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:repository",
                    f"expected one of {REPOSITORIES!r}, observed {repository!r}",
                )
            )
            continue
        if not isinstance(assertion_id, str) or not assertion_id:
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:assertion_id",
                    "expected non-empty string",
                )
            )
            continue
        identity = (repository, assertion_id)
        if identity in seen:
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_DUPLICATE",
                    location,
                    f"duplicate staged projection {identity!r}",
                )
            )
            continue
        seen.add(identity)
        if kind not in STAGEABLE_ASSERTION_KINDS:
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:kind",
                    f"assertion kind {kind!r} cannot be staged",
                )
            )
            continue
        if not isinstance(path, str) or not path:
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:path",
                    "expected non-empty repository-relative path",
                )
            )
            continue
        try:
            resolve_repo_path(root, path)
        except ProtocolFamilyError:
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:path",
                    "path must remain inside the selected repository",
                )
            )
            continue

        assertion = _manifest_assertion(manifest, repository, assertion_id)
        if assertion is None:
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:assertion_id",
                    "must identify exactly one assertion in the selected repository",
                )
            )
            continue
        for field in ("kind", "path"):
            if entry.get(field) != assertion.get(field):
                errors.append(
                    ProtocolFamilyError(
                        "STAGED_PROJECTION_MISMATCH",
                        f"{location}:{field}",
                        f"expected manifest value {assertion.get(field)!r}, observed {entry.get(field)!r}",
                    )
                )
        if kind in {"json_pointer_equals", "json_array_equals"} and entry.get(
            "pointer"
        ) != assertion.get("pointer"):
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_MISMATCH",
                    f"{location}:pointer",
                    f"expected manifest pointer {assertion.get('pointer')!r}, observed {entry.get('pointer')!r}",
                )
            )
        observed_value = entry.get("observed_value")
        frozen_value = assertion.get("expected")
        if kind in {"text_contains", "sha256_equals"} and (
            not isinstance(observed_value, str) or not observed_value
        ):
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:observed_value",
                    "expected non-empty string for this assertion kind",
                )
            )
        if kind == "json_array_equals" and not isinstance(observed_value, list):
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:observed_value",
                    "expected array for json_array_equals",
                )
            )
        if kind == "json_pointer_equals" and type(observed_value) is not type(
            frozen_value
        ):
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:observed_value",
                    f"expected the frozen value's {type(frozen_value).__name__} type",
                )
            )
        if (
            kind == "sha256_equals"
            or (
                isinstance(frozen_value, str)
                and SHA256_ID.fullmatch(frozen_value) is not None
            )
        ) and (
            not isinstance(observed_value, str)
            or SHA256_ID.fullmatch(observed_value) is None
        ):
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:observed_value",
                    "expected a sha256: identifier with 64 lowercase hexadecimal digits",
                )
            )
        if observed_value == frozen_value and phase == "component_staging":
            errors.append(
                ProtocolFamilyError(
                    "STAGED_PROJECTION_INVALID",
                    f"{location}:observed_value",
                    "staged value must differ from the frozen manifest value",
                )
            )
        if observed_value != frozen_value and phase == "epoch_finalization":
            errors.append(
                ProtocolFamilyError(
                    "PENDING_FINALIZATION_MISMATCH",
                    f"{location}:observed_value",
                    f"final manifest has not consumed staged value {observed_value!r}",
                )
            )
    return sorted(errors, key=_error_key)


def pending_republish_from_lock(
    lock_path: Path,
    lock: dict[str, Any],
    manifest: dict[str, Any],
    *,
    root: Path | None = None,
    as_of: datetime.datetime | None = None,
) -> tuple[dict[str, Any] | None, list[ProtocolFamilyError]]:
    """Validate and return the narrow, temporary republish state machine."""

    pending = lock.get("pending_republish")
    if pending is None:
        return None, []
    if not isinstance(pending, dict) or frozenset(pending) not in {
        frozenset(PENDING_REPUBLISH_KEYS),
        frozenset(STAGED_REPUBLISH_INTENT_KEYS),
        frozenset(STAGED_PENDING_REPUBLISH_KEYS),
    }:
        return None, [
            ProtocolFamilyError(
                "PENDING_REPUBLISH_INVALID",
                f"{lock_path}:pending_republish",
                "expected the exact canonical-republish, inert staging-intent, or active staging shape",
            )
        ]
    if not all(
        isinstance(pending.get(key), str) and pending.get(key)
        for key in PENDING_REPUBLISH_KEYS
    ):
        return None, [
            ProtocolFamilyError(
                "PENDING_REPUBLISH_INVALID",
                f"{lock_path}:pending_republish",
                "target_epoch, predecessor_epoch, and predecessor_commit must be non-empty strings",
            )
        ]
    typed_pending = dict(pending)
    errors: list[ProtocolFamilyError] = []
    target_epoch = typed_pending["target_epoch"]
    predecessor_epoch = typed_pending["predecessor_epoch"]
    manifest_epoch = manifest.get("epoch")
    lock_epoch = lock.get("epoch")
    target_key = _protocol_family_epoch_key(target_epoch)
    predecessor_key = _protocol_family_epoch_key(predecessor_epoch)
    if target_key is None:
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_INVALID",
                f"{lock_path}:pending_republish:target_epoch",
                "expected a versioned protocol-family epoch",
            )
        )
    if predecessor_key is None:
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_INVALID",
                f"{lock_path}:pending_republish:predecessor_epoch",
                "expected a versioned protocol-family epoch",
            )
        )
    if predecessor_epoch == target_epoch:
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_MISMATCH",
                f"{lock_path}:pending_republish:predecessor_epoch",
                "predecessor_epoch must differ from target_epoch",
            )
        )
    elif (
        target_key is not None
        and predecessor_key is not None
        and target_key <= predecessor_key
    ):
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_MISMATCH",
                f"{lock_path}:pending_republish:target_epoch",
                "target_epoch must be later than predecessor_epoch",
            )
        )

    phase = _pending_republish_phase(typed_pending, manifest)
    expected_epoch = target_epoch
    if phase in {"staging_intent", "component_staging"}:
        expected_epoch = predecessor_epoch
    elif phase == "invalid":
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_MISMATCH",
                f"{lock_path}:pending_republish",
                f"manifest epoch {manifest_epoch!r} is neither predecessor {predecessor_epoch!r} nor target {target_epoch!r}",
            )
        )
    if manifest_epoch != expected_epoch:
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_MISMATCH",
                f"{lock_path}:pending_republish:target_epoch",
                f"expected manifest epoch {expected_epoch!r}, observed {manifest_epoch!r}",
            )
        )
    if lock_epoch != expected_epoch:
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_MISMATCH",
                f"{lock_path}:pending_republish:target_epoch",
                f"expected lock epoch {expected_epoch!r}, observed {lock_epoch!r}",
            )
        )
    if typed_pending["predecessor_commit"] != lock.get("canonical_commit"):
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_MISMATCH",
                f"{lock_path}:pending_republish:predecessor_commit",
                "predecessor_commit must equal canonical_commit",
            )
        )
    if not _is_full_commit(typed_pending["predecessor_commit"]):
        errors.append(
            ProtocolFamilyError(
                "PENDING_REPUBLISH_INVALID",
                f"{lock_path}:pending_republish:predecessor_commit",
                "expected a 40-character lowercase hexadecimal commit",
            )
        )
    staging_commit = typed_pending.get("staging_commit")
    if staging_commit is not None:
        if not _is_full_commit(staging_commit):
            errors.append(
                ProtocolFamilyError(
                    "PENDING_REPUBLISH_INVALID",
                    f"{lock_path}:pending_republish:staging_commit",
                    "expected a 40-character lowercase hexadecimal commit",
                )
            )
        elif staging_commit == typed_pending["predecessor_commit"]:
            errors.append(
                ProtocolFamilyError(
                    "PENDING_REPUBLISH_MISMATCH",
                    f"{lock_path}:pending_republish:staging_commit",
                    "staging_commit must follow predecessor_commit",
                )
            )
    if "staged_projections" in typed_pending:
        errors.extend(
            _validate_staged_projections(
                root if root is not None else lock_path.parent.parent,
                lock_path,
                typed_pending,
                manifest,
                as_of=as_of,
            )
        )
    return typed_pending, sorted(errors, key=_error_key)


def validate_pending_republish_predecessor(
    root: Path, lock_path: Path, pending: dict[str, Any]
) -> list[ProtocolFamilyError]:
    """Require the predecessor to be ancestral, readable, and at its stated epoch."""

    commit = pending["predecessor_commit"]
    relative = "protocol-family/interface-manifest-v1.json"
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        return [
            ProtocolFamilyError(
                "UNREADABLE_PENDING_PREDECESSOR",
                f"{lock_path}:pending_republish:predecessor_commit",
                str(exc),
            )
        ]
    ancestor = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", commit, head],
        check=False,
        capture_output=True,
    )
    if ancestor.returncode == 1:
        return [
            ProtocolFamilyError(
                "PENDING_PREDECESSOR_ANCESTRY_MISMATCH",
                f"{lock_path}:pending_republish:predecessor_commit",
                f"{commit} is not an ancestor of canonical revision {head}",
            )
        ]
    if ancestor.returncode != 0:
        detail = ancestor.stderr.decode(errors="replace").strip()
        return [
            ProtocolFamilyError(
                "UNREADABLE_PENDING_PREDECESSOR",
                f"{lock_path}:pending_republish:predecessor_commit",
                detail or f"git merge-base exited {ancestor.returncode}",
            )
        ]
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{relative}"],
            check=True,
            capture_output=True,
        )
        predecessor_manifest = json.loads(result.stdout)
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        return [
            ProtocolFamilyError(
                "UNREADABLE_PENDING_PREDECESSOR",
                f"{lock_path}:pending_republish:predecessor_commit",
                str(exc),
            )
        ]
    if not isinstance(predecessor_manifest, dict) or predecessor_manifest.get("epoch") != pending[
        "predecessor_epoch"
    ]:
        return [
            ProtocolFamilyError(
                "PENDING_REPUBLISH_MISMATCH",
                f"{lock_path}:pending_republish:predecessor_epoch",
                "named predecessor does not declare predecessor_epoch",
            )
        ]
    authority = predecessor_manifest.get("authority")
    if not isinstance(authority, dict) or authority.get("repository") != (
        "pyramidal-io/ZKA.dev"
    ):
        return [
            ProtocolFamilyError(
                "PENDING_REPUBLISH_MISMATCH",
                f"{lock_path}:pending_republish:predecessor_commit",
                "named predecessor is not a canonical ZKA manifest",
            )
        ]
    return []


def validate_pending_republish_staging_commit(
    root: Path,
    lock_path: Path,
    pending: dict[str, Any],
    *,
    as_of: datetime.datetime | None = None,
) -> list[ProtocolFamilyError]:
    """Require an active/final stage to name its exact inert intent commit."""

    staging_commit = pending.get("staging_commit")
    if staging_commit is None:
        return []
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        lock_result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "show",
                f"{staging_commit}:protocol-family/snapshot-lock.json",
            ],
            check=True,
            capture_output=True,
        )
        manifest_result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "show",
                f"{staging_commit}:protocol-family/interface-manifest-v1.json",
            ],
            check=True,
            capture_output=True,
        )
        intent_lock = json.loads(lock_result.stdout)
        intent_manifest = json.loads(manifest_result.stdout)
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        return [
            ProtocolFamilyError(
                "UNREADABLE_STAGING_COMMIT",
                f"{lock_path}:pending_republish:staging_commit",
                str(exc),
            )
        ]
    for ancestor, descendant, label in (
        (staging_commit, head, "current revision"),
        (pending["predecessor_commit"], staging_commit, "staging commit"),
    ):
        result = subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", ancestor, descendant],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()
            return [
                ProtocolFamilyError(
                    "STAGING_COMMIT_ANCESTRY_MISMATCH",
                    f"{lock_path}:pending_republish:staging_commit",
                    detail or f"{ancestor} is not an ancestor of {label} {descendant}",
                )
            ]
    if not isinstance(intent_lock, dict) or not isinstance(intent_manifest, dict):
        return [
            ProtocolFamilyError(
                "STAGING_COMMIT_MISMATCH",
                f"{lock_path}:pending_republish:staging_commit",
                "staging commit must contain object-shaped lock and manifest documents",
            )
        ]
    intent_pending, intent_errors = pending_republish_from_lock(
        lock_path, intent_lock, intent_manifest, root=root, as_of=as_of
    )
    if (
        intent_pending is None
        or intent_errors
        or _pending_republish_phase(intent_pending, intent_manifest) != "staging_intent"
    ):
        detail = "; ".join(str(error) for error in intent_errors)
        return [
            ProtocolFamilyError(
                "STAGING_COMMIT_MISMATCH",
                f"{lock_path}:pending_republish:staging_commit",
                detail or "named commit does not contain a valid inert staging intent",
            )
        ]
    for key in (
        "target_epoch",
        "predecessor_epoch",
        "predecessor_commit",
        "expires_at",
        "staging_sha256",
        "staged_projections",
    ):
        if pending.get(key) != intent_pending.get(key):
            return [
                ProtocolFamilyError(
                    "STAGING_COMMIT_MISMATCH",
                    f"{lock_path}:pending_republish:{key}",
                    "active/final staging must preserve the exact published intent",
                )
            ]
    return []


def validate_fixture_bindings(
    root: Path, vectors: dict[str, Any], repository: str
) -> list[ProtocolFamilyError]:
    """Validate vector references to repository-owned cryptographic fixtures."""

    errors: list[ProtocolFamilyError] = []
    for case_index, case in enumerate(vectors.get("cases", [])):
        if not isinstance(case, dict):
            continue
        for binding_index, binding in enumerate(case.get("fixture_bindings", [])):
            if not isinstance(binding, dict) or binding.get("repository") != repository:
                continue
            location = f"/cases/{case_index}/fixture_bindings/{binding_index}"
            try:
                path = resolve_repo_path(root, str(binding.get("path", "")))
                observed = _sha256(path)
            except ProtocolFamilyError as error:
                errors.append(error)
                continue
            if observed != binding.get("sha256"):
                errors.append(
                    ProtocolFamilyError(
                        "SHA256_MISMATCH",
                        location,
                        f"expected {binding.get('sha256')!r}, observed {observed!r}",
                    )
                )
    return sorted(errors, key=_error_key)


def validate_snapshot_lock(
    root: Path,
    manifest: dict[str, Any],
    *,
    canonical_commit: str | None = None,
    resolve_pending_predecessor: bool = False,
    as_of: datetime.datetime | None = None,
) -> list[ProtocolFamilyError]:
    """Validate a consumer's local snapshot lock and optional canonical commit."""

    lock_path = root / "protocol-family" / "snapshot-lock.json"
    try:
        lock = load_json(lock_path)
    except ProtocolFamilyError as error:
        return [error]
    if not isinstance(lock, dict):
        return [ProtocolFamilyError("INVALID_TYPE", str(lock_path), "expected object")]
    errors: list[ProtocolFamilyError] = []
    expected_keys = SNAPSHOT_LOCK_KEYS | ({"pending_republish"} if "pending_republish" in lock else set())
    if set(lock) != expected_keys:
        errors.append(
            ProtocolFamilyError(
                "SNAPSHOT_LOCK_INVALID",
                str(lock_path),
                f"expected keys {sorted(expected_keys)!r}, observed {sorted(lock)!r}",
            )
        )
    expected_scalars = {
        "format": "zka:protocol-family:snapshot-lock:v1",
        "epoch": manifest.get("epoch"),
        "canonical_repository": "pyramidal-io/ZKA.dev",
    }
    if canonical_commit is not None:
        expected_scalars["canonical_commit"] = canonical_commit
    for key, expected in expected_scalars.items():
        if lock.get(key) != expected:
            errors.append(
                ProtocolFamilyError(
                    "SNAPSHOT_LOCK_MISMATCH",
                    f"{lock_path}:{key}",
                    f"expected {expected!r}, observed {lock.get(key)!r}",
                )
            )
    commit = lock.get("canonical_commit")
    if not _is_full_commit(commit):
        errors.append(
            ProtocolFamilyError(
                "SNAPSHOT_LOCK_MISMATCH",
                f"{lock_path}:canonical_commit",
                "expected a 40-character lowercase hexadecimal commit",
            )
        )
    for digest_key, relative in SNAPSHOT_FILES:
        try:
            observed = _sha256(resolve_repo_path(root, relative))
        except ProtocolFamilyError as error:
            errors.append(error)
            continue
        if lock.get(digest_key) != observed:
            errors.append(
                ProtocolFamilyError(
                    "SNAPSHOT_LOCK_MISMATCH",
                    f"{lock_path}:{digest_key}",
                    f"expected {observed!r}, observed {lock.get(digest_key)!r}",
                )
            )
    pending, pending_errors = pending_republish_from_lock(
        lock_path, lock, manifest, root=root, as_of=as_of
    )
    errors.extend(pending_errors)
    if pending is not None and not pending_errors and resolve_pending_predecessor:
        errors.extend(validate_pending_republish_predecessor(root, lock_path, pending))
        if _pending_republish_phase(pending, manifest) in {
            "component_staging",
            "epoch_finalization",
        }:
            errors.extend(
                validate_pending_republish_staging_commit(
                    root, lock_path, pending, as_of=as_of
                )
            )
    return sorted(errors, key=_error_key)


def validate_repository(
    root: Path,
    repository: str,
    *,
    as_of: datetime.datetime | None = None,
) -> list[ProtocolFamilyError]:
    """Validate package structure, vectors, matrix, and one repository projection."""

    manifest_path = root / "protocol-family" / "interface-manifest-v1.json"
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        return [ProtocolFamilyError("INVALID_TYPE", str(manifest_path), "expected object")]
    schema_path = root / "protocol-family" / "interface-manifest-v1.schema.json"
    schema = load_json(schema_path)
    if not isinstance(schema, dict):
        return [ProtocolFamilyError("INVALID_TYPE", str(schema_path), "expected object")]
    errors = validate_json_schema(manifest, schema)
    errors.extend(validate_manifest_structure(manifest))
    pending_republish: dict[str, Any] | None = None
    lock_path = root / "protocol-family" / "snapshot-lock.json"
    try:
        lock = load_json(lock_path)
    except ProtocolFamilyError:
        lock = None
    if isinstance(lock, dict):
        candidate, pending_errors = pending_republish_from_lock(
            lock_path, lock, manifest, root=root, as_of=as_of
        )
        if candidate is not None and not pending_errors:
            pending_republish = candidate
    errors.extend(
        validate_projection(
            root,
            manifest,
            repository,
            pending_republish=pending_republish,
        )
    )
    errors.extend(validate_artifact_bindings(root, manifest, repository))

    vector_path = resolve_repo_path(root, str(manifest.get("vector_file", "")))
    vectors = load_json(vector_path)
    if isinstance(vectors, dict):
        errors.extend(validate_vectors(vectors, manifest))
        errors.extend(validate_fixture_bindings(root, vectors, repository))
    else:
        errors.append(ProtocolFamilyError("INVALID_TYPE", str(vector_path), "expected object"))

    if repository == "zka":
        errors.extend(
            validate_matrix(root / "protocol-family" / "compatibility-matrix.md", manifest)
        )
        errors.extend(
            validate_snapshot_lock(
                root,
                manifest,
                resolve_pending_predecessor=True,
                as_of=as_of,
            )
        )
    else:
        errors.extend(validate_snapshot_lock(root, manifest, as_of=as_of))
    return sorted(errors, key=_error_key)


def audit_roots(
    zka_root: Path,
    afp_root: Path,
    zkc_root: Path,
    zkm_root: Path,
    *,
    canonical_commit: str,
    as_of: datetime.datetime | None = None,
) -> list[ProtocolFamilyError]:
    """Audit four explicit repository roots for byte and lock identity."""

    roots = {
        "zka": zka_root,
        "afp": afp_root,
        "zkc": zkc_root,
        "zkm": zkm_root,
    }
    errors: list[ProtocolFamilyError] = []
    for repository, root in roots.items():
        errors.extend(validate_repository(root, repository, as_of=as_of))
    for _, relative in SNAPSHOT_FILES:
        canonical_path = resolve_repo_path(zka_root, relative)
        try:
            canonical_bytes = canonical_path.read_bytes()
        except OSError as exc:
            errors.append(ProtocolFamilyError("UNREADABLE_INPUT", str(canonical_path), str(exc)))
            continue
        for repository in ("afp", "zkc", "zkm"):
            consumer_path = resolve_repo_path(roots[repository], relative)
            try:
                consumer_bytes = consumer_path.read_bytes()
            except OSError as exc:
                errors.append(ProtocolFamilyError("UNREADABLE_INPUT", str(consumer_path), str(exc)))
                continue
            if consumer_bytes != canonical_bytes:
                errors.append(
                    ProtocolFamilyError(
                        "SNAPSHOT_BYTE_MISMATCH",
                        f"{repository}:{relative}",
                        "consumer bytes differ from canonical ZKA bytes",
                    )
                )
    manifest = load_json(zka_root / "protocol-family" / "interface-manifest-v1.json")
    if isinstance(manifest, dict):
        for root in roots.values():
            errors.extend(
                validate_snapshot_lock(
                    root,
                    manifest,
                    canonical_commit=canonical_commit,
                    as_of=as_of,
                )
            )
        canonical_lock_path = zka_root / "protocol-family" / "snapshot-lock.json"
        try:
            canonical_lock = load_json(canonical_lock_path)
        except ProtocolFamilyError as error:
            errors.append(error)
        else:
            if isinstance(canonical_lock, dict):
                pending, pending_errors = pending_republish_from_lock(
                    canonical_lock_path,
                    canonical_lock,
                    manifest,
                    root=zka_root,
                    as_of=as_of,
                )
                if pending is not None and not pending_errors:
                    phase = _pending_republish_phase(pending, manifest)
                    if phase == "staging_intent":
                        code = "PENDING_STAGING_ACTIVATION"
                        message = (
                            "staging intent must be activated from its observed commit "
                            "before any component exception is available"
                        )
                    elif phase == "component_staging":
                        code = "PENDING_COMPONENT_PROJECTIONS"
                        message = (
                            "component projections are staged for a future epoch; "
                            "the family remains frozen"
                        )
                    else:
                        code = "PENDING_CANONICAL_REPUBLISH"
                        message = (
                            "canonical snapshot lock must be republished from the "
                            "observed merge commit"
                        )
                    errors.append(
                        ProtocolFamilyError(
                            code,
                            f"{canonical_lock_path}:pending_republish",
                            message,
                        )
                    )
                elif "pending_republish" not in canonical_lock:
                    errors.extend(validate_canonical_commit_snapshot(zka_root, canonical_commit))
    canonical_lock_path = zka_root / "protocol-family" / "snapshot-lock.json"
    try:
        canonical_lock_bytes = canonical_lock_path.read_bytes()
    except OSError as exc:
        errors.append(
            ProtocolFamilyError("UNREADABLE_INPUT", str(canonical_lock_path), str(exc))
        )
    else:
        for repository in ("afp", "zkc", "zkm"):
            consumer_lock_path = roots[repository] / "protocol-family" / "snapshot-lock.json"
            try:
                consumer_lock_bytes = consumer_lock_path.read_bytes()
            except OSError as exc:
                errors.append(
                    ProtocolFamilyError("UNREADABLE_INPUT", str(consumer_lock_path), str(exc))
                )
                continue
            if consumer_lock_bytes != canonical_lock_bytes:
                errors.append(
                    ProtocolFamilyError(
                        "SNAPSHOT_BYTE_MISMATCH",
                        f"{repository}:protocol-family/snapshot-lock.json",
                        "consumer bytes differ from canonical ZKA lock bytes",
                    )
                )
    return sorted(errors, key=_error_key)


def canonical_commit_from_lock(root: Path) -> str:
    """Return the full immutable commit named by the canonical ZKA lock."""

    lock_path = root / "protocol-family" / "snapshot-lock.json"
    lock = load_json(lock_path)
    if not isinstance(lock, dict):
        raise ProtocolFamilyError("INVALID_TYPE", str(lock_path), "expected object")
    canonical_commit = lock.get("canonical_commit")
    if not isinstance(canonical_commit, str) or re.fullmatch(
        r"[0-9a-f]{40}", canonical_commit
    ) is None:
        raise ProtocolFamilyError(
            "INVALID_CANONICAL_COMMIT",
            f"{lock_path}:/canonical_commit",
            "expected full lowercase Git commit",
        )
    return canonical_commit


def validate_canonical_commit_snapshot(
    root: Path, canonical_commit: str
) -> list[ProtocolFamilyError]:
    """Verify the canonical commit contains the currently published snapshot bytes."""

    errors: list[ProtocolFamilyError] = []
    for _, relative in SNAPSHOT_FILES:
        try:
            result = subprocess.run(
                ["git", "-C", str(root), "show", f"{canonical_commit}:{relative}"],
                check=True,
                capture_output=True,
            )
            current_bytes = resolve_repo_path(root, relative).read_bytes()
        except (OSError, subprocess.CalledProcessError) as exc:
            errors.append(
                ProtocolFamilyError(
                    "UNREADABLE_CANONICAL_COMMIT", f"{canonical_commit}:{relative}", str(exc)
                )
            )
            continue
        if result.stdout != current_bytes:
            errors.append(
                ProtocolFamilyError(
                    "CANONICAL_COMMIT_MISMATCH",
                    f"{canonical_commit}:{relative}",
                    "reviewed commit bytes differ from the current canonical snapshot",
                )
            )
    return sorted(errors, key=_error_key)


def _as_of_argument(value: str) -> datetime.datetime:
    parsed = _parse_whole_second_utc(value)
    if parsed is None:
        raise argparse.ArgumentTypeError(
            "expected a real whole-second UTC timestamp such as 2026-09-10T12:00:00Z"
        )
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--repo", required=True, choices=REPOSITORIES)
    validate.add_argument("--root", required=True, type=Path)
    validate.add_argument(
        "--as-of",
        type=_as_of_argument,
        help="validation instant for reproducible expiry checks (default: current UTC)",
    )

    audit = subparsers.add_parser("audit")
    audit.add_argument("--zka-root", required=True, type=Path)
    audit.add_argument("--afp-root", required=True, type=Path)
    audit.add_argument("--zkc-root", required=True, type=Path)
    audit.add_argument("--zkm-root", required=True, type=Path)
    audit.add_argument(
        "--as-of",
        type=_as_of_argument,
        help="validation instant for reproducible expiry checks (default: current UTC)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            errors = validate_repository(args.root, args.repo, as_of=args.as_of)
            success = f"protocol-family validation OK: {args.repo}"
        else:
            canonical_commit = canonical_commit_from_lock(args.zka_root)
            errors = audit_roots(
                args.zka_root,
                args.afp_root,
                args.zkc_root,
                args.zkm_root,
                canonical_commit=canonical_commit,
                as_of=args.as_of,
            )
            errors = sorted(errors, key=_error_key)
            success = "protocol-family whole-family audit OK"
    except ProtocolFamilyError as error:
        print(error, file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(success)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
