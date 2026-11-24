# ZKM v1 → v2 statement cutover note

**Status:** Normative for downstream consumers of ZKM proofs
**Applies to:** ZKM v0.1.0-draft rev 10 and later (`zkm:rev:10`+)
**Date:** 2026-10-27
**Family epoch:** `zka:protocol-family:2026-11-19.1`
**Published rev-13 statement set:** `sha256:f367e0504bcbbe4ca2a150f9c56a7640d5ed21bdb9dec1c1ce4acaa6e023ab49`
**Machine-readable form:** [`protocol-family/zkm-statement-registry-v1.json`](../protocol-family/zkm-statement-registry-v1.json)

**Rev-13 publication:** ZKA substantive target Forgejo PR69 merged at `b0f255e2340e8b0092422e50a3abac12cb452cec`; canonical republish PR94 merged at `7b900d5533183a99ee16ec6723c01e7a818d38cf`. The predecessor epoch `zka:protocol-family:2026-10-26.1` pins the combined insertion, recipient correction, positive-spend guard and policy diagnostics. Its final lock names the observed target merge and has no pending marker. Consumers MUST synchronize the final package before claiming family acceptance. Deployment adoption remains a separate reviewed atomic cutover; these publication records do not activate a target. Current epoch `zka:protocol-family:2026-11-19.1` retains AFP v0.3.14-draft carriage while preserving this statement set. Its lock names observed ZKA epoch merge `69bc82ac6685e91f23e386dfdacab78dd1e8cfbc`. Current family acceptance additionally requires the canonical lock republish, byte-identical consumer synchronization, and final AFP source reconciliation.

The first consumer this note is written for is a **ZKA §5.4.1 settlement
target**. A target that keeps the v1 keys installed alongside the v2 ones
stays exploitable through the exact revocation weakness rev 10 removed, and a
target implemented from a pre-cutover reading of §5.4.1 will not verify a
single proof against a current ZKM checkout.

## 1. What the family pin does and does not tell you

ZKM's spec version has been `0.1.0-draft` for every revision from rev 1 through rev 13, so it cannot, on its own, distinguish breaking statement surfaces. Current family epoch `zka:protocol-family:2026-11-19.1` pins ZKM as `protocols.zkm.version = "0.1.0-draft (rev 13)"` together with the combined statement-set identity, closing the temporary staged-publication window. Earlier epoch `zka:protocol-family:2026-09-10.1` pinned the rev-12 surface.

Two gaps remain, and they are what this note and the registry exist for.

1. **The label is prose, not the surface.** It pins a revision *name*, not a
   verification key, a public-input vector, a bytecode digest, or a
   toolchain. Any of those can move within a revision — a re-bless, an ABI
   reorder, a bb bump — without moving a single character the epoch pins.
2. **Nothing in the manifest makes a later breaking revision move the
   label.** A changelog-presence assertion remains true for historical
   revisions. A later breaking revision after rev 12 would leave that assertion
   green unless the family pin advances; the current statement-set assertion
   and ZKM's revision-bound checker are the surface checks.

[`protocol-family/zkm-statement-registry-v1.json`](../protocol-family/zkm-statement-registry-v1.json)
and its checker make the incomplete family cutover fail closed:
`statement_set_id` digests the actual statement/ABI/VK/toolchain surface, and
any pinned revision label must be **at least `last_breaking_revision`**. Rev
12 moves every verification key and the pinned toolchain; epoch
`2026-09-10.1` binds both changes to the same published family identity. Prefer
pinning the registry's `statement_set_id` field, and re-check on every ZKM bump
(a whole-file sha256 is also supported); §7 has the stanza that makes the family
enforce it too.

## 2. What rev 10 changed

| | Pre-cutover (rev 9 and earlier) | Post-cutover (rev 10+) |
|---|---|---|
| Spend statement | `zkm:spend-conjoined:v1` | `zkm:spend-conjoined:v2` |
| Mandate-only statement | `zkm:mandate-only:v1` | `zkm:mandate-only:v2` |
| Spend public vector | 13 elements | **14** elements (`revocation_scheme` added) |
| Mandate-only public vector | 8 elements | **9** elements (`revocation_scheme` added) |
| Revocation accumulator | depth-128 tree over the low half of `root_id` | **depth-254 full-identifier exclusion tree** |
| `revocation_scheme` wire value | absent | **2**; 0, 1 and 3..255 are invalid |
| Verification keys | rev-9 keys | **all keys re-blessed** |

The two v1 statements are **retired**. They are valid only under pre-cutover
v1 keys and roots; a post-cutover registry MUST omit them and MUST NOT
reinterpret or upgrade their proofs.

### 2.1 Rev-13 recipient-control correction

The companion now derives `spendingKey = H(zka/spending, S)` and `recipientAddress = H(zka/address, H(zka/viewing, spendingKey))`. The ZKC handle and the ZKM issuance key remain separate seed siblings. A note addressed by treating `S` itself as a spending key is rejected.

The companion retains `zkm:spend-zkc-binding:v1`: its intended same-subject authorization and five-element public vector are unchanged. The corrected constraints move its VK, bytecode and statement-set digest, so the identifier alone does not establish compatibility. Renaming it would also change the independent effect-profile statement allowlist despite unchanged effect semantics. This revision preserves `profile_set_id`.

At coordinated activation, replace the pre-rev-13 companion VK `25363035aaf7edcc6ed92e1198c135b6f4a8f72e56475e8587a6b41ebb6a1c86` with the corrected VK below, require the final rev-13 `statement_set_id`, and remove the earlier VK atomically. Do not accept both keys or reinterpret earlier proofs. The companion still settles nothing alone and MUST match `(nf, zka_cm_recipient, asset_id, settlement_context)` against the spend-conjoined proof before atomic effects. No mandate artifact, public-vector slot, issuance sibling, revocation scheme or monetary effect changes in this correction.

## 3. Current statement and verification-key identifiers

Verification-key hashes in this table are `bb write_vk`'s own `vk_hash`, produced under the pinned toolchain (nargo `1.0.0-beta.25`, barretenberg `5.0.0`) for the default `noir-recursive` target (Poseidon2 transcript). The complete VK identifier is `(scheme, transcript_target, vk_hash)` as defined in specification §6; table hashes omit only the `0x` display prefix. EVM/Keccak keys generated with `-t evm` have different hashes for the same circuit; the committed EVM provenance records that target's hashes. A consumer MUST pin the correct transcript target, key and toolchain, not copy a default-target hash into an EVM entry.

| Statement | Circuit package | Public inputs | Verification-key hash | Value-moving |
|---|---|---|---|---|
| `zkm:spend-conjoined:v2` | `zkm_spend_conjoined` | 14 | `0b7d35cd871089d6f0dd2629a728427fc29659b55a8060118a16e30320fb34f1` | **yes** |
| `zkm:mandate-only:v2` | `zkm_mandate_transition` | 9 | `0b91505084261b9268790023c77c9557af3330b8e9a04dcf07b75e006842ee98` | no |
| `zkm:possession:v1` | `zkm_delegate_possession` | 3 | `2194860ab13eb116ef5f2e6f27b92c1e7565cadbb742f237f976b16bf7baf18a` | no |
| `zkm:issuance:v1` | `zkm_issuance` | 2 | `2e1822f0075001abc11db03932d9786ba62f5370ae0cbd2760bac437fab0caa3` | no |
| `zkm:revocation-auth:v1` | `zkm_revocation_auth` | 2 | `018a6b96981489de7273ab6c5373e523e19f7a2f220f2a4a233c25366b50a654` | no |
| `zkm:revocation-insertion:v1` | `zkm_revocation_insertion` | 6 | `2ccd874af3c3eac2005a7f25c8150d3bc976094260da27b121d25a9f4d8c5379` | no |
| `zkm:control-attestation:v1` | `zkm_control_attestation` | 3 | `048caef435447318d1ff2fe6ade1b675ecca0df8633d96ea7429b81de39a48fe` | no |
| `zkm:issuance-zkc:v1` | `zkm_issuance_zkc` | 3 | `1a189ea01a7572797b0af6b79448724886db1f880b9a0310d50460b1853683f3` | no |
| `zkm:spend-zkc-binding:v1` | `zkm_spend_zkc_binding` | 5 | `19b990f4ff4bfadc451a0390e1ac18eb3430b59f4fe0eadb6ab7829071e78128` | no |

Retired: `zkm:spend-conjoined:v1` (13 inputs) and `zkm:mandate-only:v1`
(8 inputs) — both retired in rev 10, both superseded by their v2 successor,
neither reinterpretable.

The lifecycle below is normative. `current_since_revision` records when the
identifier became current, independently of later verification-key or toolchain
changes. A successor's `supersedes` names exactly its retired predecessor; a
statement with no predecessor records null in the registry (shown as — here).

| Statement | Current since revision | Supersedes |
|---|---|---|
| `zkm:spend-conjoined:v2` | 10 | `zkm:spend-conjoined:v1` |
| `zkm:mandate-only:v2` | 10 | `zkm:mandate-only:v1` |
| `zkm:possession:v1` | 4 | — |
| `zkm:issuance:v1` | 5 | — |
| `zkm:revocation-auth:v1` | 6 | — |
| `zkm:revocation-insertion:v1` | 13 | — |
| `zkm:control-attestation:v1` | 7 | — |
| `zkm:issuance-zkc:v1` | 9 | — |
| `zkm:spend-zkc-binding:v1` | 9 | — |

| Retired statement | Retired in revision | Superseded by | Public inputs |
|---|---|---|---|
| `zkm:spend-conjoined:v1` | 10 | `zkm:spend-conjoined:v2` | 13 |
| `zkm:mandate-only:v1` | 10 | `zkm:mandate-only:v2` | 8 |

### 3.1 The two v2 public vectors

Slots are in the declaration order of the reference circuits' `main`. Every
element is one BN254 field element; integers are zero-extended. An
independent encoder MUST reproduce this order and MUST NOT sort fields.

`zkm:spend-conjoined:v2` — 14 elements:

```text
(kind, nf, cm_out_1, cm_out_2, mandate_root, revocation_root,
 revocation_scheme, current_time, settlement_context, asset_id_pub,
 zka_note_root, zka_nullifier, zka_cm_recipient, zka_cm_change)
```

`zkm:mandate-only:v2` — 9 elements: the first nine of the above (through
`settlement_context`), with no ZKA value leg.

Against ZKA §5.4.1's naming, the change from the pre-cutover vector is one inserted slot: `revocationScheme` lands between `revocationRoot` and `currentTime`, so every element from `currentTime` onward shifts by one index. `kind` MUST still equal SPEND (`0`) and `cm_out_2` (`mandateSecondSuccessorCommitment`) MUST still be the zero sentinel. `amount` remains private in both forms. ZKA §5.4.1 has stated this vector since family epoch `zka:protocol-family:2026-09-10.1`. Current epoch `zka:protocol-family:2026-11-19.1` pins the combined rev-13 key surface: current ZKA and ZKM retain the same 14-element shape and agree on the new statement-set identity.

### 3.2 Rev-13 positive-amount cutover

The published rev-13 statement set requires a positive private spend amount and
corrects the mandate-only policy-witness diagnostics. The spend vector remains
14 fields; the mandate-only vector remains 9 fields. The mandate-only VK is
unchanged, while its bytecode digest records the diagnostic correction. The
current statement-set identity also binds insertion continuity and recipient
derivation. Final family epoch `zka:protocol-family:2026-10-26.1` pins that
combined surface; deployment adoption still requires the reviewed atomic
cutover below.

A target adopting this surface MUST select the reviewed successor spend
verifier/VK atomically with retiring the previous spend key. It MUST preserve
one shared mandate-nullifier set across statements and keys and preserve ZKA
nullifier state. It MUST NOT interpret a rev-12 proof as enforcing `amount > 0`.
The retained rev-12 fixture and verifier are historical recovery evidence, never
an additional accepted key after cutover. For every positive spend, including a
full-note spend, apply both output commitments atomically; no zero-change
sentinel or public amount is introduced. This document does not deploy or
activate a target.

## 4. What a post-cutover registry MUST contain

A deployment registry entry for a settlement target, per specification §5–§6:

1. It MUST map each of the **nine** current statement identifiers above to **exactly one** verification key, identified by its complete VK identifier, and all nine mapped keys MUST be pairwise distinct, including disabled entries. One key MUST NOT serve two statements; a different transcript label MUST NOT disguise reused key bytes. The published map fixes proof identity; it does not enable acceptance. Each mapping MUST explicitly state its enabled flag and allowed verification operations. A disabled statement, an unlisted operation, an unknown identifier or a different VK MUST be rejected without trying another key. A target MAY disable the ZKC statements, or disable base issuance while enabling credential-bound issuance, while retaining all nine mappings. This does not establish later mandate issuance provenance.
2. It MUST omit `zkm:spend-conjoined:v1` and `zkm:mandate-only:v1`, and MUST NOT reinterpret, upgrade, or re-map their proofs onto the v2 keys.
3. If enabled, its value-moving entry point MUST accept the mapped, enabled `zkm:spend-conjoined:v2` key and no other key. A proof verified under `zkm:mandate-only:v2`, a possession, control-attestation, revocation, or unknown key MUST NOT reach it.
4. It MUST authorize revocation only under the mapped, enabled `zkm:revocation-auth:v1` key, conjoined with the separately registered and enabled `zkm:revocation-insertion:v1` continuity proof (§7.1). It MUST match the id and context, require the current predecessor tip and authenticated epoch, and commit insertion plus ordered publication atomically. It MUST NOT accept a `zkm:control-attestation:v1` proof as insertion authority; a continuity proof cannot replace issuance authority. Both revocation-auth and revocation-insertion acceptance MUST be enabled before any mandate issuance or mandate-consuming operation and remain available while previously accepted lineages can remain live, even if issuance or transitions are disabled. Disabling statements MUST NOT bypass required possession or ZKC companions; an operation remains unavailable unless all its required verification operations are enabled and matched atomically.
5. It MUST publish `revocation_scheme = 2` and reject every other scheme value on both transition statements.
6. The **target** MUST own a single mandate-nullifier set per settlement context, shared across every accepted ZKM statement, verification key and adapter deployment — including across the cutover. Its ZKA-nullifier state MUST be the same state used by ordinary transfers and exits. Both check-and-inserts and every output insertion MUST be atomic. Replacing an adapter or VK MUST NOT reset either set. Targets MUST accept callbacks only from registered, reviewed adapters and honor exact statement/verifier/VK withdrawal on every attempt; ordinary mandate-free exits remain independent of those ZKM gates.
7. Each adapter's value-moving entry MUST be immutable or version-pinned for its lifetime. The versioned registry snapshot MUST record the `statement_set_id` and toolchain it was reviewed against and retain historical snapshots for receipt verification. The target's replay state survives adapter replacement. Registration and withdrawal MUST therefore select reviewed adapter code without creating an adapter-local or per-VK copy of the authoritative spent sets. Read replay state from the target rather than the retired adapter-local mapping getters. The registry snapshot MUST disclose `depth_max = 16` for the current statement set. A target MUST NOT accept a larger or smaller per-target depth build under the current statement identifiers and statement-set pin, even if it publishes the resulting VK hash. A different bound requires a coordinated breaking statement-surface revision; per-target variants remain forbidden until a versioned per-build identity/golden scheme and matching consumer pins exist. This restriction does not prevent generating the supported transcript-target keys from the unchanged pinned circuit, or per-mandate narrowing through v2 `depth_limit`.

**First-deployment gate.** Before the first target accepts a ZKM proof, its deployment delivery MUST provide the versioned registry JSON schema, CI validator and positive/negative fixtures required by specification §6. CI MUST validate its actual snapshot and match enabled operations and keys to the deployed configuration. This format is scheduled as a blocking first-deployment deliverable; the protocol statement registry is not a substitute, and no deployment-registry schema or validator is claimed to exist today.

## 5. Migration path for a target that verified v1 proofs

A target that accepted v1 proofs before the cutover MUST follow the [revocation v2 runbook](zkm_revocation_v2_migration.md); this is the consumer-facing summary of it, not a substitute.

1. **Freeze v1 revocation acceptance and authenticate complete history** at a finalized end-of-block checkpoint. Keep the freeze continuously through atomic activation. Retain every accepted revocation-auth invocation, including duplicate/no-op calls and full identifiers sharing a low-128 slot, with target/context and ordered settlement positions. Two independent operators MUST authenticate completeness, finality and freeze enforcement from settlement state and separately pin the checkpoint digest. A low-128 slot or matching legacy root alone is insufficient. Stop on incomplete or inconsistent history; an insertion accepted after the checkpoint invalidates it and requires a new freeze, checkpoint and export.
2. **Build the v2 root** with `scripts/migrate-revocation-v2.py` using the complete accepted-auth journal, frozen checkpoint and independently trusted `--checkpoint-sha256`, reproduced independently by at least two operators. The export set MUST exactly equal the journal’s unique full IDs; canonical encodings and closed schemas are mandatory. The explicit activation epoch MUST match the pinned plan. The offline tool checks consistency against the trusted checkpoint; it cannot authenticate the chain or enforce a live freeze. See the runbook for exact formats and operator obligations.
3. **Cut over atomically**, only at the pinned activation epoch after verifying uninterrupted freeze and checkpoint validity, in one governance change: publish the v2 root under scheme `2`; install the reviewed v2 keys; remove the two v1 statements and their keys from the accepted registry; and start all later authorized revocations from the v2 tree state. Retain the target-owned mandate and ZKA spent history, register the replacement adapters, and withdraw every old adapter that can reach obsolete lanes.
   The target MUST provide a reviewed authenticated-checkpoint activation lane. The Ethereum reference accumulator has no such lane; generating a manifest does not qualify or execute activation. Stop if that capability is unavailable.

4. **Do not run a dual-acceptance window.** Accepting v1 and v2 profiles simultaneously reintroduces the low-half collision the migration removes, and is unsafe even with shared target custody. Independently, deploying a replacement with a fresh adapter-local spent set forks replay protection; target-owned custody is required across the cutover. Relabelling a v1 root as v2 is likewise forbidden.

   Before activation, reconcile the complete historical mandate and ZKA nullifiers from every previously accepted adapter and ordinary value path into the target's authoritative state. Stop if history is missing, incomplete, duplicated inconsistently, non-canonical, or cannot be verified against settlement state; never activate with an empty or partial replay history. A benchmark snapshot restore is test isolation, not a migration mechanism.

5. **Re-pin every downstream artifact** that named a v1 identifier: registry entries, verifier artifacts, public-input encoders, ABI fixtures, and any specification text citing the 13-element vector.
6. **Recover** by restoring the activation checkpoint, replaying `revokedLeaves` in canonical order, verifying the reconstructed root byte-for-byte, then replaying post-activation insertions in settlement order. If any root differs, stop before accepting proofs; never fall back to the legacy tree.

In-flight v1 proofs do not survive the cutover and MUST NOT be re-verified under a v2 key. Mandates themselves are unaffected: the exclusion construction does not enumerate active mandates, so no live mandate is stranded by the migration.

## 6. The gate a consumer should execute

Run these against the ZKM checkout you are composing against — they are
cheap, need no proving toolchain except the last, and each one fails closed:

```bash
python3 scripts/check-zkm-statement-registry.py
# This scanner-clean public snapshot intentionally omits the standalone AFP-KDC v1.0.2 fixture.
python3 scripts/validate_protocol_family.py validate --repo zkm --root .
python3 scripts/migrate-revocation-v2.py --self-test
bash noir/scripts/check-circuit-goldens.sh
```

`python3 scripts/check-zkm-statement-registry.py` is the one that makes this
note enforceable: it re-derives every verification-key hash, opcode count,
bytecode digest and public-input vector in the registry from the blessed
structural goldens and the circuits' own `fn main` declarations, recomputes
the `statement_set_id`, and rejects a revision history that classifies a
moved statement surface as non-breaking. `--self-test` reintroduces each of
those regressions and requires the checks to catch them.

The two artifacts to pin in your own repository are
`protocol-family/zkm-statement-registry-v1.json` (prefer its `statement_set_id` field; whole-file sha256 is also supported) and, if you
verify proofs locally, `noir/scripts/goldens/circuits.txt`.

## 7. Pinning ZKM in the family matrix

The canonical family interface manifest is maintained in ZKA.dev. This
scanner-clean public snapshot carries a reviewed projection of that manifest:
it omits only the unavailable AFP-KDC fixture binding/assertion, and its public
snapshot lock recomputes the manifest digest from the projected bytes. The
projection remains validated against the published family schema and the
named canonical family revision; it is not a canonical-family mirror. Epoch
`zka:protocol-family:2026-09-10.1` supplies the rev-12 label and current
statement-set identity atomically; the canonical snapshot lock carries no
pending republish marker.

```json
{
  "id": "zkm-statement-set-id",
  "kind": "json_pointer_equals",
  "path": "protocol-family/zkm-statement-registry-v1.json",
  "pointer": "/statement_set_id",
  "expected": "sha256:<the registry's published statement_set_id>"
}
```

`check-zkm-statement-registry.py` accepts three pin forms on the registry
path: an `artifact_bindings` entry (whole-file sha256), a `sha256_equals`
projection assertion (whole-file sha256), or a `json_pointer_equals`
projection assertion on `/statement_set_id` (field pin). The field pin is
the preferred form. `statement_set_id` commits to every statement, ABI,
verification-key, revocation and toolchain field but deliberately excludes
prose (`note`/`reason` fields) — an editorial edit is not a protocol change.
A whole-file digest moves on prose too, so every editorial edit would break
the pin and force a new family epoch plus consumer snapshot resyncs; the
field pin moves exactly when the statement surface moves. Whichever form is
present, the shared validator (`validate_protocol_family.py validate
--repo zkm`) enforces it on every ZKM CI run, and any statement, ABI, VK or
toolchain move breaks the pin instead of passing silently — including moves
that leave the revision label untouched.

Both halves are cross-checked from the ZKM side by
`check-zkm-statement-registry.py`:

- the manifest's declared version must match `family_pin.declared_version`
  and every compatibility tuple, and its spec-version half must match the
  registry's;
- the manifest MUST discriminate ZKM by at least one of the two mechanisms —
  a revision label or a registry pin (any of the three forms above).
  Reverting to a bare version string with no pin is a red gate even when the
  registry is updated to agree with it, because that is the original defect
  restored;
- a pinned revision label MUST NOT exceed the revision ZKM has published, and
  MUST NOT be older than `last_breaking_revision` — this is what makes a
  breaking revision the family has not followed a red gate rather than a
  silent composition. A registry pin satisfies the discrimination requirement
  on its own: file digest and `statement_set_id` alike move on any
  statement-surface change, so neither can go stale across a breaking
  revision unnoticed;
- a file-shaped pin is compared against the registry's whole-file sha256; the
  field pin is compared against the registry's published `statement_set_id`,
  so a `statement_set_id` that moves without a ZKA re-bless is a red gate on
  the ZKM side as well as under the shared validator;
- `family_pin.statement_digest.pinned` must agree with what the manifest
  actually binds, in both directions — the registry can neither claim a pin
  it does not have (`pinned_by` must name an actual manifest pin) nor claim
  to be unpinned while ZKA carries one.

## 8. Version discipline going forward

A change is **breaking** if it adds, retires or renames a statement
identifier; changes any public-input vector (order, name, type or count);
moves any verification key, ACIR opcode count or bytecode digest; changes the
accepted revocation scheme; or moves the pinned toolchain. A breaking change
MUST bump the registry's `revision`, append a `revision_history` entry whose
`statement_set_id` differs from its predecessor's, and set
`last_breaking_revision` to that revision. A non-breaking revision MUST carry
its predecessor's `statement_set_id` unchanged. A breaking revision MUST also
be followed by the family manifest's revision label. Consumers compare
`statement_set_id`, not the spec version string.

## 9. Rev 13 insertion continuity cutover

Rev 13 adds one companion statement. The same revision corrects the recipient companion described in §2.1 and adds the positive-spend and policy-diagnostic changes in §3.2 under one statement-set identity. Existing proof vectors, identifier introduction revisions, the other six existing verification keys, scheme 2 and the pinned toolchain remain unchanged. Its ordered public vector is `(root_id, previous_root, next_root, revocation_scheme, epoch, settlement_context)`; the scheme is `u8`, the epoch `u64`, and other fields are canonical non-zero `Field`. The target derives the epoch from its clock and compares the predecessor to its current tip. Siblings are private and shared by the empty-leaf and full-id-leaf folds.

Predecessor family epoch `zka:protocol-family:2026-10-26.1` pins the combined rev-13 statement set and revision label. It closes the temporary component-staging window; the final canonical lock names target merge `b0f255e2340e8b0092422e50a3abac12cb452cec` without a pending marker. Copy the canonical package byte-for-byte rather than creating a local exception. Existing deployed targets still need a reviewed insertion verifier and atomic publication path; they MUST NOT accept arbitrary roots or treat authorization-only submissions as accepted insertions. The migration checkpoint and settlement/custody boundary remain governed by the migration runbook and ZKA §5.4.1.

## References

- ZKM specification §5 (statements, envelopes, registry rules), §7 (revocation):
  [`docs/zkm_specification.md`](zkm_specification.md)
- ZKM revocation v2 runbook: [`docs/zkm_revocation_v2_migration.md`](zkm_revocation_v2_migration.md)
- ZKM statement registry: [`protocol-family/zkm-statement-registry-v1.json`](../protocol-family/zkm-statement-registry-v1.json)
- ZKA v0.9.2-draft §5.4.1 (ZKM authorization carriage and atomic settlement),
  as pinned by the current family manifest. ZKA PR #293 reconciled the v2
  identifiers and 14-element vector and introduced the rev-10 label in epoch
  `zka:protocol-family:2026-08-15.1`; ZKA PR #297 added the unchanged
  `statement_set_id` field pin in epoch `zka:protocol-family:2026-08-15.2`.
  Current epoch `zka:protocol-family:2026-11-19.1` pins the combined rev-13 surface with no pending marker.
