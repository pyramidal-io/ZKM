#!/usr/bin/env python3
"""Check the fixed §5 disclosure-binding KAT and its lifted-envelope negative."""

from __future__ import annotations

import copy
from pathlib import Path

from disclosure_binding import binding_material, check_binding, parse_json

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    vector = parse_json((ROOT / "tests/vectors/zkm_disclosure_binding_v1.json").read_text(encoding="utf-8"))
    envelope = vector["envelope"]
    canonical, digest, limbs, binding = binding_material(envelope)
    observed = {
        "canonicalProjection": canonical.decode("utf-8"),
        "blake2b512": digest.hex(),
        "digestLimbs": [f"{limb:032x}" for limb in limbs],
        "disclosureBinding": binding,
    }
    if observed != vector["expected"]:
        raise SystemExit("disclosure-binding known-answer vector mismatch")
    audience = envelope["metadata"]["audienceId"]
    nonce = envelope["metadata"]["recipientNonce"]
    context = envelope["metadata"]["context"]
    check_binding(envelope, expected_audience=audience, expected_nonce=nonce, expected_context=context)
    lifted = copy.deepcopy(envelope)
    lifted["contents"]["noteOpenings"] = []
    try:
        check_binding(lifted, expected_audience=audience, expected_nonce=nonce, expected_context=context)
    except ValueError:
        pass
    else:
        raise SystemExit("lifted-envelope negative was accepted")
    print("ZKM disclosure binding KAT and lifted-envelope negative: PASS")


if __name__ == "__main__":
    main()
