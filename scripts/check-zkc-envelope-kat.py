#!/usr/bin/env python3
"""Verify the normative ZKC-envelope digest known-answer vector."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re


BN254_SCALAR_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
DOMAIN_PREFIX = b"ZKM-ZKC-Proof-v1"
EXPECTED_PROOF_BYTES = bytes.fromhex("fbff")
EXPECTED_PROOF_ENCODING = "-_8"
EXPECTED_JCS = (
    '{"metadata":{"context":{"profile":"zkc:context:transaction:v1",'
    '"timestamp":1785801600,"value":"0x0000000000000000000000000000000000000000000000000000000000000001"},'
    '"expiresAt":"2026-08-04T00:05:00Z","generatedAt":"2026-08-04T00:00:00Z"},'
    '"presentationBinding":{"profile":"zkc:presentation:scoped:v1",'
    '"pseudonym":"0x0000000000000000000000000000000000000000000000000000000000000002",'
    '"scopeId":"0x0000000000000000000000000000000000000000000000000000000000000003"},'
    '"proofs":[{"principalConsent":true,"proof":"-_8","proofType":"zkc:proof:example:v1",'
    '"publicInputs":{"presentationPseudonym":"0x0000000000000000000000000000000000000000000000000000000000000002",'
    '"proofContext":"0x0000000000000000000000000000000000000000000000000000000000000001",'
    '"scopeId":"0x0000000000000000000000000000000000000000000000000000000000000003"}}],'
    '"version":"zkc:proof:v2"}'
)
EXPECTED_BLAKE2B512_HEX = (
    "4bf2a36e5f21f6949fe41133675dc631b31bb441a1f54481477b023514f9d479"
    "a9c4586b495a73f4a91847277b627beaa07b45328370e4da28029dbce9ca5a3e"
)
EXPECTED_FIELD_HEX = (
    "0x13db598ebfff2a1dc254965eba1a9d14559423d3be40344f76898f0bc450e48a"
)


def canonical_proof_bytes(encoded: str) -> bytes:
    """Decode one canonical unpadded RFC 4648 base64url proof string."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise ValueError("proof is not unpadded base64url")

    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("proof is not canonical base64url") from error

    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != encoded:
        raise ValueError("proof has padding ambiguity or non-zero pad bits")
    return decoded


def vector_envelope() -> dict[str, object]:
    context = "0x" + "00" * 31 + "01"
    pseudonym = "0x" + "00" * 31 + "02"
    scope_id = "0x" + "00" * 31 + "03"
    return {
        "version": "zkc:proof:v2",
        "metadata": {
            "generatedAt": "2026-08-04T00:00:00Z",
            "expiresAt": "2026-08-04T00:05:00Z",
            "context": {
                "profile": "zkc:context:transaction:v1",
                "value": context,
                "timestamp": 1785801600,
            },
        },
        "proofs": [
            {
                "proofType": "zkc:proof:example:v1",
                "proof": EXPECTED_PROOF_ENCODING,
                "publicInputs": {
                    "proofContext": context,
                    "presentationPseudonym": pseudonym,
                    "scopeId": scope_id,
                },
                "principalConsent": True,
            }
        ],
        "presentationBinding": {
            "profile": "zkc:presentation:scoped:v1",
            "pseudonym": pseudonym,
            "scopeId": scope_id,
        },
    }


def main() -> None:
    if canonical_proof_bytes(EXPECTED_PROOF_ENCODING) != EXPECTED_PROOF_BYTES:
        raise SystemExit("proof-byte encoding KAT mismatch")

    for alternate in ("+/8=", "+/8", "-_8="):
        try:
            canonical_proof_bytes(alternate)
        except ValueError:
            pass
        else:
            raise SystemExit(f"alternate proof representation was accepted: {alternate}")

    if canonical_proof_bytes("fbff") == EXPECTED_PROOF_BYTES:
        raise SystemExit("hex text reproduced the KAT proof bytes")

    canonical_json = json.dumps(
        vector_envelope(),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if canonical_json != EXPECTED_JCS:
        raise SystemExit("RFC 8785 envelope serialization KAT mismatch")

    digest = hashlib.blake2b(
        DOMAIN_PREFIX + canonical_json.encode("utf-8"), digest_size=64
    ).digest()
    if digest.hex() != EXPECTED_BLAKE2B512_HEX:
        raise SystemExit("ZKC envelope Blake2b-512 KAT mismatch")

    field_value = int.from_bytes(digest, "little") % BN254_SCALAR_MODULUS
    if f"0x{field_value:064x}" != EXPECTED_FIELD_HEX:
        raise SystemExit("ZKC proof-digest field reduction KAT mismatch")

    print("ZKC envelope digest KAT: PASS")


if __name__ == "__main__":
    main()
