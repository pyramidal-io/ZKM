# ZKM revocation accumulator v2 migration

This runbook is normative for moving a settlement target from the legacy low-128 exclusion tree to the full-identifier v2 tree. The migration is a protocol break: roots, witnesses, public vectors, circuit bytecode, and both transition verification keys change together.

## Authenticate history and freeze v1

Before exporting, the target MUST stop accepting v1 revocation insertions at a finalized end-of-block boundary and keep them frozen continuously until atomic v2 activation. Every v1 revocation accepted through that boundary MUST be included. An accepted insertion after the boundary invalidates the checkpoint: abort, establish a new freeze and finalized checkpoint, export the complete history again and reproduce the root. A one-time observation that the target was frozen is insufficient. Pending requests are not accepted history; process them against v2 after activation. The freeze adds operational delay to those requests; it does not retroactively revoke them. Ordinary ZKA transfers and exits remain independent of these ZKM gates.

Obtain the authoritative, complete append-only journal of **accepted revocation-auth invocations**, from inception through that exact finalized block, from authenticated settlement history. Retain both public inputs `(root_id, settlement_context)` and canonical block/transaction/log positions. Include accepted duplicate/no-op invocations and distinct full identifiers sharing a low-128 slot, even if the v1 root did not change. Do not use holder reports, submitted but rejected proofs, a cache, root-change events alone, or a low-128 slot list. Repeated full identifiers at distinct positions are legitimate journal entries; duplicate positions are not. The migrated set is the unique full identifiers whose revocation was authorized and accepted. V1's incidental collateral exclusion of an unauthorised identifier with the same low half is not an accepted authorization to revoke that identifier under v2.

Two independent operators MUST authenticate completeness, target/network identity, context, finality, the end-of-block boundary and continuous freeze enforcement against settlement state. They MUST agree on a checkpoint digest through an authenticated channel independent of the candidate export and journal. Recomputing an expected pin from the same untrusted candidate defeats the check. Where a deployed v1 root can be independently reconstructed, reconcile it too; a matching v1 root alone cannot detect omitted colliding or no-op authorizations. Stop on incomplete or unavailable history, mismatched state, ambiguous finality or inability to enforce the freeze. There is no unpinned fallback.

## Input formats and trusted pin

The CLI accepts three closed JSON objects. Unknown or duplicate keys at any depth, non-finite numbers and unsupported formats are errors. All fields named below are required. Field identifiers are exactly `0x` plus 64 lower-case hexadecimal digits, nonzero and less than the BN254 scalar modulus; decimal numbers, short hex, whitespace, separators and alternative bases are rejected. Epochs, counts and position components are JSON integers in `0..2^64-1`, never booleans. Block hashes are 32-byte lower-case hex byte strings, not field elements. `settlementTarget` is an authenticated network-and-target identifier, 1–256 printable ASCII characters without spaces; its interpretation and authority come from settlement, not the CLI.

The export (`snapshot.json`) contains exactly:

```json
{
  "format": "zkm:revocation-migration-input:v2",
  "legacyAccumulatorVersion": 1,
  "cutoverEpoch": 42,
  "activationEpoch": 45,
  "revokedRootIds": ["0x0000000000000000000000000000000000000000000000000000000000000007"]
}
```

The accepted journal (`accepted-auth-log.json`) contains exactly `format` (`zkm:accepted-revocation-auth-log:v1`), `settlementTarget`, `settlementContext`, `snapshotBlock` and `entries`. `snapshotBlock` contains exactly `number` and `hash`, denoting the finalized end of that block. Each entry contains exactly `position` and `publicInputs`:

```json
{
  "position": {"blockNumber": 100, "transactionIndex": 0, "logIndex": 3},
  "publicInputs": {
    "root_id": "0x0000000000000000000000000000000000000000000000000000000000000007",
    "settlement_context": "0x0000000000000000000000000000000000000000000000000000000000000063"
  }
}
```

Positions MUST be strictly increasing lexicographically and no later than `snapshotBlock.number`. Gaps in chain log indices may represent unrelated events; the CLI does not infer completeness from consecutive numbers. Every entry's context MUST match the target checkpoint. `entries` is an array, including an empty array only when authenticated history contains no accepted revocations.

The independently authenticated checkpoint (`checkpoint.json`) contains exactly:

- `format`: `zkm:revocation-migration-checkpoint:v1`;
- `legacyAccumulatorVersion`: integer `1`;
- `settlementTarget`, `settlementContext` and `snapshotBlock`: identical to the journal;
- `cutoverEpoch` and `activationEpoch`: identical to the export, with activation strictly later than cutover;
- `v1FrozenUntilActivation`: boolean `true`, attesting freeze from the snapshot boundary continuously through activation;
- `acceptedLogSha256`: the canonical JSON digest of the complete journal;
- `acceptedLogEntryCount`: the number of accepted invocations, including repeated/no-op calls.

For both journal and checkpoint, the digest is `sha256:` followed by the lower-case SHA-256 of this format's canonical JSON bytes: Python `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")`, after strict parsing and closed-schema validation. This is a format-specific encoding, not a claim to implement a general JSON canonicalization standard. Object-key order and whitespace do not affect it; journal array order does. The checkpoint's digest is supplied separately as `--checkpoint-sha256`; it MUST be authenticated and pinned before validating the candidate. Placeholder hashes or the synthetic self-test checkpoint are not authority.

## Build and cross-check the migration root

With the independently authenticated digest available in `TRUSTED_CHECKPOINT_SHA256`, run:

```bash
python3 scripts/migrate-revocation-v2.py snapshot.json \
  --accepted-auth-log accepted-auth-log.json \
  --checkpoint checkpoint.json \
  --checkpoint-sha256 "$TRUSTED_CHECKPOINT_SHA256" \
  --output migration.json
python3 scripts/migrate-revocation-v2.py --self-test
```

The old three-field input without reference history is rejected. The tool verifies the checkpoint pin, journal digest/count/boundary/target/context/order, exact equality of the exported set to the journal's unique full IDs, and the explicit frozen activation plan. Changing both a partial journal and its checkpoint cannot satisfy the original external pin. It sorts identifiers, rejects duplicate export IDs, inserts each identifier as both depth-254 path and leaf, and verifies reconstructed membership. It emits a deterministic versioned manifest with the trusted source pin, boundary and conditional trust basis. It does not invent an activation epoch by adding one.

**Offline trust boundary:** the tool validates consistency relative to the externally authenticated checkpoint. It does not query a chain, verify historical authorization proofs or finality, discover missing history in a dishonest trusted checkpoint, enforce the freeze, or execute activation. Matching outputs from two operators using the same incomplete untrusted export are insufficient. Both operators MUST independently authenticate the reference and reproduce the same canonical manifest. Archive that manifest, the checkpoint, external pin and complete journal with the settlement checkpoint.

## Atomic activation

At the exact planned activation epoch, recheck that the original target/context and finalized checkpoint remain valid and the v1 freeze has held without interruption. Stop if it was lifted or any v1 insertion was accepted after the snapshot. Rescheduling requires a newly authenticated checkpoint/plan and independently reproduced manifest; an old manifest does not authorize a new epoch.

Apply one atomic governance change that:

1. publishes the emitted v2 root under scheme `2`;
2. installs the reviewed `zkm:mandate-only:v2` and `zkm:spend-conjoined:v2` verification keys;
3. removes the two v1 statements and keys from the accepted registry; and
4. starts all later authorized revocations from the v2 tree state.

The target MUST support authenticated checkpoint installation and enforce the freeze and atomic activation. The Ethereum reference accumulator starts empty and has **no migrated-checkpoint activation lane**; this offline manifest does not add one or qualify a deployment. A target without that reviewed capability MUST stop. Preserve the target-owned mandate and ZKA spent history across adapter/key replacement as required by the consumer cutover note; do not reset replay protection.

Never relabel a v1 root as v2, accept both profiles after activation, or migrate from a partial revoked-id log. A partial migration revives authority and must fail closed. Active mandates are not enumerated in this exclusion construction, so unrevoked mandates require no registration.

## Recovery

Restore the activation checkpoint and its authenticated provenance. Replay `revokedLeaves` in canonical order, verify the reconstructed root byte-for-byte, then replay post-activation authorized insertions in settlement order. If any root, history or checkpoint differs, stop before accepting proofs; do not fall back to the legacy tree or reuse an invalidated frozen checkpoint.
