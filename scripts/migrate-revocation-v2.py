#!/usr/bin/env python3
"""Build a deterministic ZKM full-identifier revocation migration manifest.

Input must equal the accepted-auth set in an independently pinned frozen checkpoint.
Version 2 inserts each full root identifier as both leaf value and canonical
254-bit path. The output root is therefore deterministic, collision-free, and
reconstructible from the emitted leaf manifest without registering active ids.

This is a one-way migration. A deployment must atomically publish the output
root, switch to the v2 verification keys, and stop accepting v1 proofs.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import re
import json
import sys
from pathlib import Path

from poseidon2 import FIELD_MODULUS, poseidon2

DEPTH = 254
SCHEME = "POSEIDON2_SPARSE_FULL_ID_EXCLUSION_V2"
PATH_RULE = "canonical-bn254-field-254-lsb-first-v1"

ZERO_SUBTREES = [0]
for _ in range(DEPTH):
    ZERO_SUBTREES.append(poseidon2(ZERO_SUBTREES[-1], ZERO_SUBTREES[-1]))


def parse_field(value: object, label: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label} must be a lower-case 0x-prefixed 32-byte field string")
    parsed = int(value, 16)
    if not 0 < parsed < FIELD_MODULUS:
        raise ValueError(f"{label} must be in the canonical range 1..p-1")
    return parsed


def object_keys(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} must contain exactly {', '.join(sorted(keys))}")
    return value


def uint64(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"{label} must be a uint64 JSON integer")
    return value


def digest(value: object) -> str:
    """Hash this format's canonical JSON, not source-file whitespace."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def parse_json_document(text: str) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError(f"non-finite JSON number: {value}")

    result = json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)
    if not isinstance(result, dict):
        raise ValueError("document must be a JSON object")
    return result


def check_block(value: object, label: str) -> dict:
    block = object_keys(value, {"number", "hash"}, label)
    uint64(block["number"], f"{label}.number")
    if not isinstance(block["hash"], str) or re.fullmatch(r"0x[0-9a-f]{64}", block["hash"]) is None:
        raise ValueError(f"{label}.hash must be a lower-case 32-byte hash")
    return block


def field_hex(value: int) -> str:
    return f"0x{value:064x}"


class RevokedSet:
    def __init__(self, leaves: list[int]):
        self.leaves = leaves
        self.levels = self._build_levels()

    def _build_levels(self) -> list[dict[int, int]]:
        levels = [{root_id: root_id for root_id in self.leaves}]
        for height in range(DEPTH):
            below = levels[-1]
            above = {}
            for parent in sorted({position >> 1 for position in below}):
                left = below.get(parent << 1, ZERO_SUBTREES[height])
                right = below.get((parent << 1) | 1, ZERO_SUBTREES[height])
                above[parent] = poseidon2(left, right)
            levels.append(above)
        return levels

    def root(self) -> int:
        return self.levels[DEPTH].get(0, ZERO_SUBTREES[DEPTH])

    def witness(self, root_id: int) -> list[int]:
        siblings = []
        position = root_id
        for height in range(DEPTH):
            sibling_position = position ^ 1
            level = self.levels[height]
            siblings.append(level.get(sibling_position, ZERO_SUBTREES[height]))
            position >>= 1
        return siblings


def compute_root(leaf: int, root_id: int, siblings: list[int]) -> int:
    if not 0 < root_id < FIELD_MODULUS or len(siblings) != DEPTH:
        raise ValueError("invalid canonical depth-254 witness")
    current = leaf
    for level, sibling in enumerate(siblings):
        current = (
            poseidon2(sibling, current)
            if (root_id >> level) & 1
            else poseidon2(current, sibling)
        )
    return current


def migrate(document: dict, checkpoint: dict, accepted_log: dict,
            expected_checkpoint_sha256: str) -> dict:
    """Validate a candidate against an externally authenticated, frozen checkpoint.

    The caller supplies the trusted digest independently of all three documents.
    This offline check cannot establish chain finality or enforce a live freeze.
    """
    if not isinstance(expected_checkpoint_sha256, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", expected_checkpoint_sha256
    ) is None:
        raise ValueError("a canonical independently trusted checkpoint digest is required")
    object_keys(checkpoint, {"format", "legacyAccumulatorVersion", "settlementTarget",
                "settlementContext", "snapshotBlock", "cutoverEpoch", "activationEpoch",
                "v1FrozenUntilActivation", "acceptedLogSha256", "acceptedLogEntryCount"}, "checkpoint")
    if digest(checkpoint) != expected_checkpoint_sha256:
        raise ValueError("checkpoint differs from the independently trusted digest")
    if checkpoint["format"] != "zkm:revocation-migration-checkpoint:v1":
        raise ValueError("unsupported checkpoint format")
    if type(checkpoint["legacyAccumulatorVersion"]) is not int or checkpoint["legacyAccumulatorVersion"] != 1:
        raise ValueError("checkpoint legacyAccumulatorVersion must be exactly 1")
    target = checkpoint["settlementTarget"]
    if not isinstance(target, str) or re.fullmatch(r"[!-~]{1,256}", target) is None:
        raise ValueError("settlementTarget must be 1..256 printable ASCII characters without spaces")
    parse_field(checkpoint["settlementContext"], "checkpoint.settlementContext")
    check_block(checkpoint["snapshotBlock"], "checkpoint.snapshotBlock")
    cutover = uint64(checkpoint["cutoverEpoch"], "checkpoint.cutoverEpoch")
    activation = uint64(checkpoint["activationEpoch"], "checkpoint.activationEpoch")
    if activation <= cutover:
        raise ValueError("activationEpoch must be later than cutoverEpoch")
    if checkpoint["v1FrozenUntilActivation"] is not True:
        raise ValueError("checkpoint must attest continuous v1 freeze through activation")
    uint64(checkpoint["acceptedLogEntryCount"], "checkpoint.acceptedLogEntryCount")
    if not isinstance(checkpoint["acceptedLogSha256"], str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", checkpoint["acceptedLogSha256"]
    ) is None:
        raise ValueError("acceptedLogSha256 must be a canonical SHA-256 digest")

    object_keys(accepted_log, {"format", "settlementTarget", "settlementContext",
                              "snapshotBlock", "entries"}, "accepted auth log")
    if accepted_log["format"] != "zkm:accepted-revocation-auth-log:v1":
        raise ValueError("unsupported accepted auth log format")
    # Check nested types before equality: Python considers True equal to integer 1.
    check_block(accepted_log["snapshotBlock"], "accepted auth log.snapshotBlock")
    parse_field(accepted_log["settlementContext"], "accepted auth log.settlementContext")
    for key in ("settlementTarget", "settlementContext", "snapshotBlock"):
        if accepted_log[key] != checkpoint[key]:
            raise ValueError(f"accepted auth log {key} differs from checkpoint")
    entries = accepted_log["entries"]
    if not isinstance(entries, list) or len(entries) != checkpoint["acceptedLogEntryCount"]:
        raise ValueError("accepted auth log entry count differs from checkpoint")
    if digest(accepted_log) != checkpoint["acceptedLogSha256"]:
        raise ValueError("accepted auth log digest differs from checkpoint")
    accepted = set()
    previous = None
    for index, entry in enumerate(entries):
        label = f"entries[{index}]"
        object_keys(entry, {"position", "publicInputs"}, label)
        position = object_keys(entry["position"], {"blockNumber", "transactionIndex", "logIndex"}, label + ".position")
        order = tuple(uint64(position[k], label + "." + k) for k in
                      ("blockNumber", "transactionIndex", "logIndex"))
        if order[0] > checkpoint["snapshotBlock"]["number"] or (previous is not None and order <= previous):
            raise ValueError("accepted auth log positions must be unique, ordered and at or before snapshotBlock")
        previous = order
        public = object_keys(entry["publicInputs"], {"root_id", "settlement_context"}, label + ".publicInputs")
        root_id = parse_field(public["root_id"], label + ".root_id")
        parse_field(public["settlement_context"], label + ".settlement_context")
        if public["settlement_context"] != checkpoint["settlementContext"]:
            raise ValueError("accepted authorization has a foreign settlement context")
        accepted.add(root_id)  # Accepted duplicate/no-op calls remain in the pinned journal.

    object_keys(document, {"format", "legacyAccumulatorVersion", "cutoverEpoch",
                           "activationEpoch", "revokedRootIds"}, "migration input")
    if document["format"] != "zkm:revocation-migration-input:v2":
        raise ValueError("unsupported migration input format")
    if type(document["legacyAccumulatorVersion"]) is not int or document["legacyAccumulatorVersion"] != 1:
        raise ValueError("legacyAccumulatorVersion must be exactly 1")
    for key in ("cutoverEpoch", "activationEpoch"):
        uint64(document[key], key)
        if document[key] != checkpoint[key]:
            raise ValueError(f"{key} differs from frozen checkpoint plan")
    revoked_raw = document["revokedRootIds"]
    if not isinstance(revoked_raw, list):
        raise ValueError("revokedRootIds must be an array")
    revoked = [parse_field(value, f"revokedRootIds[{i}]") for i, value in enumerate(revoked_raw)]
    if len(set(revoked)) != len(revoked):
        raise ValueError("revokedRootIds must not contain duplicates")
    if set(revoked) != accepted:
        raise ValueError("revokedRootIds must equal the complete pinned accepted-auth set")
    revoked.sort()
    accumulator = RevokedSet(revoked)
    root = accumulator.root()
    for root_id in revoked:
        if compute_root(root_id, root_id, accumulator.witness(root_id)) != root:
            raise AssertionError("generated membership witness does not reconstruct the migration root")
    return {
        "format": "zkm:revocation-migration-manifest:v2",
        "accumulatorVersion": 2, "scheme": SCHEME, "depth": DEPTH, "pathRule": PATH_RULE,
        "legacyCutoverEpoch": cutover, "activationEpoch": activation,
        "accumulatorRoot": field_hex(root), "revokedLeafCount": len(revoked),
        "revokedLeaves": [{"pathIndex": field_hex(i), "rootId": field_hex(i)} for i in revoked],
        "legacyProofAcceptance": "disabled-at-activation",
        "sourceCheckpoint": {"sha256": expected_checkpoint_sha256,
            "settlementTarget": target, "settlementContext": checkpoint["settlementContext"],
            "snapshotBlock": copy.deepcopy(checkpoint["snapshotBlock"]),
            "acceptedLogSha256": checkpoint["acceptedLogSha256"],
            "acceptedLogEntryCount": len(entries), "v1FrozenUntilActivation": True},
        "trustBasis": "externally-authenticated-checkpoint; activation requires continuously enforced freeze",
    }


def test_documents(ids: list[int]) -> tuple[dict, dict, dict, str]:
    """Synthetic self-test data, never an authenticated deployment checkpoint."""
    context = field_hex(99)
    block = {"number": 100, "hash": "0x" + "ab" * 32}
    journal = {"format": "zkm:accepted-revocation-auth-log:v1", "settlementTarget": "test:target",
               "settlementContext": context, "snapshotBlock": block, "entries": [
        {"position": {"blockNumber": 100, "transactionIndex": 0, "logIndex": i},
         "publicInputs": {"root_id": field_hex(root_id), "settlement_context": context}}
        for i, root_id in enumerate(ids)]}
    checkpoint = {"format": "zkm:revocation-migration-checkpoint:v1", "legacyAccumulatorVersion": 1,
                  "settlementTarget": "test:target", "settlementContext": context, "snapshotBlock": block,
                  "cutoverEpoch": 9, "activationEpoch": 12, "v1FrozenUntilActivation": True,
                  "acceptedLogSha256": digest(journal), "acceptedLogEntryCount": len(ids)}
    document = {"format": "zkm:revocation-migration-input:v2", "legacyAccumulatorVersion": 1,
                "cutoverEpoch": 9, "activationEpoch": 12,
                "revokedRootIds": [field_hex(i) for i in sorted(set(ids))]}
    return document, checkpoint, journal, digest(checkpoint)


def self_test() -> None:
    assert poseidon2(1, 2) == int(
        "038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383", 16
    )
    assert ZERO_SUBTREES[DEPTH] == int(
        "0ec9cf7fbcbffa41bc1b25e7569f1bbc85ee742cbe1c6c6f4c6af987b9773f55", 16
    )
    low = 7
    high_collision = (1 << 128) + low
    migrated = migrate(*test_documents([low]))
    assert migrated["accumulatorRoot"] == (
        "0x2d034b66ce121eb3eb86ae45a4c959a68c77c01d71f3f43bbe205fe3ddbd588b"
    )
    accumulator = RevokedSet([low])
    assert compute_root(0, high_collision, accumulator.witness(high_collision)) == int(migrated["accumulatorRoot"], 16)
    assert low & ((1 << 128) - 1) == high_collision & ((1 << 128) - 1)
    valid = test_documents([low, high_collision, low])
    ordered = migrate(*valid)
    reversed_input = copy.deepcopy(valid)
    reversed_input[0]["revokedRootIds"].reverse()
    assert ordered == migrate(*reversed_input)
    assert ordered["activationEpoch"] == 12  # Explicit plan, not cutover + 1.
    assert migrate(*test_documents([]))["revokedLeafCount"] == 0
    migrate(*test_documents([FIELD_MODULUS - 1]))

    def refused(args):
        try:
            migrate(*args)
        except ValueError:
            return
        raise AssertionError("unsafe migration was accepted")

    # Flat export omission; journal omission even after its metadata is resealed.
    partial = copy.deepcopy(valid)
    partial[0]["revokedRootIds"].pop()
    refused(partial)
    partial = list(copy.deepcopy(valid))
    partial[2]["entries"].pop(1)
    partial[1]["acceptedLogSha256"] = digest(partial[2])
    partial[1]["acceptedLogEntryCount"] -= 1
    refused(partial)  # Trusted external checkpoint pin is unchanged.
    for value in (0, True, "7", "0x07", "+7", " 7", "0b111", "0o7", "0x0_7",
                  "0x" + "AB" * 32, field_hex(0), field_hex(FIELD_MODULUS)):
        args = copy.deepcopy(valid)
        args[0]["revokedRootIds"][0] = value
        refused(args)
    for index in (0, 1, 2):
        args = list(copy.deepcopy(valid))
        args[index]["legacyV1Root"] = field_hex(7)
        if index == 1:
            args[3] = digest(args[1])
        refused(args)
    for key, value in (("activationEpoch", 9), ("activationEpoch", 1 << 64),
                       ("v1FrozenUntilActivation", False), ("legacyAccumulatorVersion", True)):
        args = list(copy.deepcopy(valid))
        args[1][key] = value
        args[3] = digest(args[1])
        refused(args)
    stale = copy.deepcopy(valid)
    stale[0]["activationEpoch"] = 13
    refused(stale)
    duplicate = copy.deepcopy(valid)
    duplicate[0]["revokedRootIds"].append(field_hex(low))
    refused(duplicate)
    def reseal(args):
        # For structural negatives only, authenticate the deliberately malformed
        # reference so rejection exercises the schema rather than an earlier pin.
        args[1]["acceptedLogSha256"] = digest(args[2])
        args[3] = digest(args[1])
        return args

    for path in ((1, "snapshotBlock"), (2, "snapshotBlock"),
                 (2, "entries", 0), (2, "entries", 0, "position"),
                 (2, "entries", 0, "publicInputs")):
        args = list(copy.deepcopy(valid))
        obj = args
        for part in path:
            obj = obj[part]
        obj["unknown"] = 1
        refused(reseal(args))
    for key, value in (("blockNumber", 101), ("transactionIndex", True),
                       ("logIndex", -1), ("logIndex", 1 << 64)):
        args = list(copy.deepcopy(valid))
        args[2]["entries"][0]["position"][key] = value
        refused(reseal(args))
    args = list(copy.deepcopy(valid))
    args[2]["entries"][1]["position"] = copy.deepcopy(args[2]["entries"][0]["position"])
    refused(reseal(args))
    for key, value in (("settlementTarget", "test:foreign"),
                       ("settlementContext", field_hex(100)),
                       ("snapshotBlock", {"number": 99, "hash": "0x" + "cd" * 32})):
        args = list(copy.deepcopy(valid))
        args[2][key] = value
        refused(reseal(args))
    args = list(copy.deepcopy(valid))
    args[2]["entries"][0]["publicInputs"]["settlement_context"] = field_hex(100)
    refused(reseal(args))
    for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":{"y":1,"y":2}}'):
        try:
            parse_json_document(raw)
        except ValueError:
            continue
        raise AssertionError("ambiguous JSON was accepted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, help="legacy snapshot JSON")
    parser.add_argument("--output", "-o", type=Path, help="write manifest here (stdout by default)")
    parser.add_argument("--accepted-auth-log", type=Path, help="complete pinned accepted-auth journal JSON")
    parser.add_argument("--checkpoint", type=Path, help="independently authenticated frozen checkpoint JSON")
    parser.add_argument("--checkpoint-sha256", help="trusted checkpoint canonical-JSON sha256: digest")
    parser.add_argument("--self-test", action="store_true", help="run deterministic KATs and exit")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("revocation v2 migration self-test passed")
        return 0
    if any(value is None for value in (args.input, args.accepted_auth_log, args.checkpoint, args.checkpoint_sha256)):
        parser.error("input, --accepted-auth-log, --checkpoint and --checkpoint-sha256 are required")
    try:
        document, checkpoint, accepted_log = [parse_json_document(path.read_text(encoding="utf-8"))
            for path in (args.input, args.checkpoint, args.accepted_auth_log)]
        result = migrate(document, checkpoint, accepted_log, args.checkpoint_sha256)
        rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"migration refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
