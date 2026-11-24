"""Reference §5 disclosure binding; this is NOT a proof or receipt verifier.

Callers must additionally verify proofs, openings, lineage tags, inclusion,
scope coverage, and the recipient's expiring, single-use challenge state.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

from poseidon2 import FIELD_MODULUS, hash_fields

DOMAIN_ZKM_DISCLOSURE_BINDING = int(
    "0b5325387de003d1f3d1d3c85995e287af94e7bc9a3463bc93b60605a345ec9d", 16
)
SAFE_INTEGER = (1 << 53) - 1
HEX32 = re.compile(r"0x[0-9a-f]{64}\Z")


def _reject_number(value: str) -> Any:
    raise ValueError(f"non-integer or non-finite JSON number: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def parse_json(text: str) -> Any:
    """Reject ambiguities before parsing can erase them, at every depth."""
    value = json.loads(
        text, object_pairs_hook=_unique_object,
        parse_float=_reject_number, parse_constant=_reject_number,
    )
    canonical_json(value)  # Validate even the two members later excluded.
    return value


def canonical_json(value: Any) -> bytes:
    """RFC 8785 on §5's restricted integer-only I-JSON profile."""
    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if isinstance(item, bool):
            return "true" if item else "false"
        if isinstance(item, int):
            if abs(item) > SAFE_INTEGER:
                raise ValueError("JSON integer exceeds the exact interoperable range")
            return str(item)
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise ValueError("lone Unicode surrogate")
            return json.dumps(item, ensure_ascii=False)
        if isinstance(item, list):
            return "[" + ",".join(encode(element) for element in item) + "]"
        if isinstance(item, dict):
            for name in item:
                if not isinstance(name, str):
                    raise ValueError("JSON object member names must be strings")
                encode(name)
            names = sorted(item, key=lambda name: name.encode("utf-16-be"))
            return "{" + ",".join(encode(name) + ":" + encode(item[name]) for name in names) + "}"
        raise ValueError("unsupported JSON value (floating-point numbers are forbidden)")

    return encode(value).encode("utf-8")


def _members(value: Any, names: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError(f"{label} has missing or undeclared members")
    return value


def _hex32(value: Any, label: str) -> int:
    if not isinstance(value, str) or HEX32.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase 0x-prefixed 32-byte hex")
    parsed = int(value, 16)
    if parsed == 0:
        raise ValueError(f"{label} must be nonzero")
    return parsed


def field(value: Any, label: str) -> int:
    parsed = _hex32(value, label)
    if parsed >= FIELD_MODULUS:
        raise ValueError(f"{label} is not a canonical BN254 field element")
    return parsed


def projection(envelope: Any) -> dict[str, Any]:
    """Delete exactly the binding and its dependent attestations, nothing else."""
    canonical_json(envelope)
    root = _members(envelope, {"version", "metadata", "scope", "contents"}, "envelope")
    if root["version"] != "zkm:disclosure:v1":
        raise ValueError("unsupported disclosure version")
    metadata = _members(root["metadata"], {
        "generatedAt", "expiresAt", "context", "audienceId", "recipientNonce", "disclosureBinding",
    }, "metadata")
    for name in ("generatedAt", "expiresAt", "audienceId"):
        if not isinstance(metadata[name], str) or not metadata[name]:
            raise ValueError(f"{name} must be a nonempty string")
    field(metadata["context"], "context")
    _hex32(metadata["recipientNonce"], "recipientNonce")  # Bytes, NOT a reduced field.
    scope = _members(root["scope"], {"kind", "bounds"}, "scope")
    if not isinstance(scope["kind"], str) or scope["kind"] not in {"transition", "lineage", "portfolio"}:
        raise ValueError("unsupported disclosure scope")
    _members(scope["bounds"], {"notBefore", "notAfter"}, "scope.bounds")
    contents = _members(root["contents"], {
        "controlAttestations", "receipts", "delegationRecords", "noteOpenings",
    }, "contents")
    for name, entries in contents.items():
        if not isinstance(entries, list):
            raise ValueError(f"contents.{name} must be an array")
    result = copy.deepcopy(envelope)
    del result["metadata"]["disclosureBinding"]
    del result["contents"]["controlAttestations"]
    return result


def binding_material(envelope: Any) -> tuple[bytes, bytes, list[int], str]:
    canonical = canonical_json(projection(envelope))
    digest = hashlib.blake2b(canonical, digest_size=64).digest()
    limbs = [int.from_bytes(digest[offset:offset + 16], "big") for offset in range(0, 64, 16)]
    binding = hash_fields([DOMAIN_ZKM_DISCLOSURE_BINDING, *limbs], 5)
    if binding == 0:
        raise ValueError("zero disclosure binding; obtain a fresh recipient nonce")
    return canonical, digest, limbs, f"0x{binding:064x}"


def check_binding(
    envelope: Any, *, expected_audience: str, expected_nonce: str, expected_context: str,
) -> str:
    """Check binding equality only; success does not authenticate a disclosure."""
    _, _, _, computed = binding_material(envelope)
    metadata = envelope["metadata"]
    field(expected_context, "expected settlement context")
    field(metadata["disclosureBinding"], "disclosureBinding")
    if metadata["audienceId"] != expected_audience or metadata["recipientNonce"] != expected_nonce:
        raise ValueError("recipient audience or challenge mismatch")
    if metadata["context"] != expected_context:
        raise ValueError("recipient settlement context mismatch")
    if metadata["disclosureBinding"] != computed:
        raise ValueError("disclosure binding does not match the envelope")
    for attestation in envelope["contents"]["controlAttestations"]:
        if not isinstance(attestation, dict) or attestation.get("statement") != "zkm:control-attestation:v1":
            raise ValueError("disclosure may contain only control-attestation proofs in this slot")
        public = attestation.get("publicInputs")
        if not isinstance(public, dict):
            raise ValueError("control attestation has no named public inputs")
        if public.get("disclosure_binding") != computed or public.get("settlement_context") != metadata["context"]:
            raise ValueError("control attestation is bound to another envelope or domain")
    return computed
