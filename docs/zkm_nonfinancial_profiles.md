# ZKM Non-Financial Effect Profiles — Framework, Versioning and Compatibility

**Version:** 0.1.0-draft
**Date:** 2026-10-27
**Status:** Draft specification of the effect-profile framework. §§1–8 are normative; the introduction, worked examples and §10 are informative. This document specifies the type system, artifact bindings and compatibility rules, the reserved conserved-quota accounting profile in §4.2.1, the reserved reusable-permission and single-use-action lifecycle profiles in §§4.3–4.5, and the backend-assurance and recovery contract in §4.6.
**License:** Apache 2.0
**Domain:** ZKM.dev
**Canonical file:** `docs/zkm_nonfinancial_profiles.md`
**Machine-readable companion:** `protocol-family/zkm-effect-profile-registry-v1.json`
**Base specification:** [`docs/zkm_specification.md`](zkm_specification.md)
**Family:** ZKA · ZKC · ZKM · VXP

**Public snapshot scope (informative):** This companion is published at `docs/zkm_nonfinancial_profiles.md` alongside the base specification. The effect-profile registry, its checker and its conformance vectors are outside this source snapshot; their paths below identify canonical artifacts, not included files. This prose does not supply a pinned `profile_set_id` or an activation package. Non-financial profiles remain reserved and cannot be activated from this snapshot.

---

## Introduction *(informative)*

ZKM today authorizes exactly one kind of effect: moving value. A mandate names an `asset_id`, carries a `remaining_cap` in that asset's atomic units, and is exercised by a spend that conjoins a ZKA value leg. Everything the base specification proves — conservation, monotone attenuation, delegation depth, principal-only revocation — is proved about *that* effect.

The obvious way to make a mandate authorize something else is to reuse what is already there. Read `asset_id` as a resource identifier and `remaining_cap` as a count of API calls, and a quota mandate exists without a single new circuit. Emit a spend of amount zero, and a "non-financial action" has a settlement record. Both work in a demo. Both are unsafe for the same reason: they make one committed field mean two things under one commitment domain, so a single mandate opening authorizes two different effects and the difference between them lives nowhere in the cryptography — only in what the reader expected. A verifier holding a quota mandate can open it as a spend authorization. A holder of a spend mandate can exercise it as a quota. Neither party can prove which was intended, because nothing was ever bound.

This document defines the alternative: an **effect profile** is a committed type, and mandates of different types commit under different domains. The monetary mandate becomes profile `zkm:effect:value-transfer:v1` — a designation, not a change; no byte of its wire format, no public input, no verification key moves. Non-financial effects arrive as new profiles with their own artifact bindings, negotiated explicitly, and refused by default.

## Conformance Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

---

## 1. Scope and Ownership Boundaries

A non-financial capability grant is a multi-protocol composition. This section fixes which protocol owns which part, so that a ZKM profile is never read as a claim about a layer ZKM does not implement. The same boundary is carried in machine-readable form under `ownership` in the registry.

| Layer | Owns |
|---|---|
| **ZKM** | The effect-profile type system: classes, conservation semantics, and which base-specification invariants apply to each. The artifact binding each profile commits under. In-circuit authorization, quota conservation, monotone attenuation, delegation depth and revocation — unchanged from the base specification. The *content* of a negotiation acceptance set and the fail-closed rules that decide it. |
| **VXP** | The wire transport that carries acceptance sets and offers between parties. Negotiated acquisition of a grant, fulfillment, and recourse when an accepted exercise does not produce its effect. |
| **ZKC** | Scoped eligibility evidence about the parties, composed through the existing same-subject statements of base specification §5. ZKM does not restate credential semantics. |
| **Resource owner / backend** | Enforcement of access and performance of the effect itself. Assurance that an accepted exercise happened, and recovery when it did not. |
| **ZKA** | Settlement of value. Custody and exit remain independent of every profile defined here — see §7. |

**Non-goals.** No profile defined under this framework provides: arbitrary-effect exactly-once guarantees (§4.4); a universal capability registry — the registry enumerates *profiles*, never resources, principals, grants or delegations (§7, `fc-11`); public delegation lineage; or any revocation of ZKA custody or exit.

**What "specify" means here.** This document and its registry are a specification and a conformance surface. Filing or merging them authorizes no implementation and no deployment. Every non-financial profile is still `reserved` in the current published registry. The conserved-quota, reusable-permission and single-use-action profiles now have pinned mechanics and conformance vectors. None is usable until a later revision activates it under the discipline of §8.

---

## 2. The Two Surfaces

ZKM now pins two independent surfaces, and conflating them is the mistake this section exists to prevent.

| Surface | Artifact | Pins | Identity |
|---|---|---|---|
| **Statement** | `protocol-family/zkm-statement-registry-v1.json` | What is *proven*: public vectors, verification keys, accepted revocation scheme, pinned proving toolchain. | `statement_set_id` |
| **Effect profile** | `protocol-family/zkm-effect-profile-registry-v1.json` | What a proof *means*: the effect, its conservation semantics, its resource and purpose scoping, and the artifact it commits under. | `profile_set_id` |

Either can move without the other. A verification key re-bless moves the statement surface and leaves every profile's meaning intact; activating a profile moves the profile surface and may leave every existing key in place. Consequently:

1. A conforming release gate MUST validate both, and this document's registry MUST NOT be the reason `statement_set_id` moves.
2. A consumer holding a profile identifier and no `profile_set_id` MUST treat the profile surface as **unpinned** and reject — the same rule the statement registry already applies to its own identity. An identifier is prose; only the digest pins what it means.
3. Both digests appear in every offer and every acceptance set (§6). Agreement on one never excuses disagreement on the other.

`profile_set_id` digests a projection of the security-relevant content only — classes, artifact bindings, profiles including their activation requirements, the quota-accounting procedure, the negotiation procedure, the attenuation invariants and provenance rules, the permission/action lifecycle procedure, the backend-assurance contract and recovery graph, and the forbidden constructions, each projected to a fixed field list. Prose fields are excluded by construction: an editorial edit is not a protocol change, and an identifier that moved on prose would train reviewers to re-bless it. The derivation is stated in full in the registry and recomputed on every CI run by `scripts/check-zkm-effect-profiles.py`.

---

## 3. Shared Mandate Semantics

Every profile — monetary and non-financial alike — populates the same eight dimensions. This is what makes them one family rather than a bag of unrelated grants, and it is why a non-financial mandate inherits the base specification's security argument instead of needing a new one.

| # | Dimension | Requirement | Profile-configurable |
|---|---|---|---|
| 1 | Authority source | The self-issued, hidden principal and its preimage-knowledge issuance proof (base §3). A profile MUST NOT introduce an external attestor. | No |
| 2 | Agent scope | `holder_key`, derived under `zkm/holder_key/v1`. Where a class is consumptive, the nullifier-secret derivation binds to it unchanged. | No |
| 3 | Resource scope | A blinded commitment to the resource the effect acts on. | Yes |
| 4 | Purpose scope | A blinded commitment to the purpose the authority was granted for. | Yes |
| 5 | Duration | `expiry` as in base §3, plus `not_before` on every non-financial artifact binding. Duration MUST NOT extend across successors. | No |
| 6 | Attenuation | Monotone narrowing under the profile's declared narrowing registry. Widening is unprovable, not merely forbidden. | Yes |
| 7 | Delegation limits | `depth`, the VK-baked `depth_max` and the policy `depth_limit`, unchanged from base §6. | No |
| 8 | Disclosure | `zkm:disclosure:v1` unchanged. No profile may add a compulsory, operator-exercisable or third-party-exercisable disclosure surface. | No |

### 3.1 Attenuation invariants *(normative)*

Dimension 6 says a successor may only narrow. Half of that is per-profile — what makes one quota narrower than another quota depends on what the quota counts, and belongs to the profile's declared narrowing registry. The other half is **profile-independent**: it holds for every class, including reserved profiles whose mechanics remain unspecified. That half is fixed here, published in the registry's `attenuation` block, and evaluated as known-answer vectors independently of any one profile.

A **transition claim** carries `profile_id`, `artifact_binding`, `root_id`, `depth`, `not_before`, `expiry`, `resource_scope`, `purpose_scope`, `units` and `scope_blinding`. Each scope is `{commitment, narrows_predecessor}`: `true` when the successor carries a proof of the profile's narrowing relation, `false` when it carries a proof that it does not, and absent when the scope changed with no narrowing proof at all. This mirrors how base §4.3-3 and the rev-6 `assert_policy_narrows` treat `policy_hash` — preserved, or replaced by a proven-narrower value, and nothing else.

The invariants run in this order:

| # | Rule | Requirement | Reason code |
|---|---|---|---|
| 1 | `att-01` | A successor MUST NOT change its effect profile. | `REJECT_PROFILE_SWITCH` |
| 2 | `att-02` | A successor MUST NOT change its artifact binding. | `REJECT_BINDING_SWITCH` |
| 3 | `att-03` | A successor MUST preserve `root_id`. | `REJECT_LINEAGE_BREAK` |
| 4 | `att-04` | `depth` MUST NOT decrease. | `REJECT_DEPTH_REGRESSION` |
| 5 | `att-05` | `expiry` MUST NOT increase and `not_before` MUST NOT decrease. | `REJECT_DURATION_EXTENSION` |
| 6 | `att-06` | `resource_scope` preserved or proven narrower. | `REJECT_RESOURCE_WIDENING` |
| 7 | `att-07` | `purpose_scope` preserved or proven narrower. | `REJECT_PURPOSE_WIDENING` |
| 8 | `att-08` | On a conserved class `units` MUST NOT increase; on a class with no quantity both MUST be absent. | `REJECT_UNIT_INCREASE` |
| 9 | `att-09` | A successor changing either scope MUST carry fresh scope blinding. | `REJECT_BLINDING_REUSE` |
| — | Otherwise | | `NARROWS` |

`att-10` closes it: these are a **floor, not a ceiling**. A profile's narrowing relation MUST NOT relax any of them and MAY only add restrictions.

Four of these are worth a sentence of reasoning. **`att-01` and `att-02`** are what stop delegation from *translating* authority: a holder able to switch profile mid-lineage could emit successors authorizing effects the principal never issued. In-circuit `att-02` is already unwitnessable because the commitment domains differ (§5) — the rule states what the domains enforce, and its vector is what shows the framework agrees with the cryptography rather than merely hoping to. **`att-04`** permits equality deliberately: ROTATE is a rebind at unchanged depth, not a hop, so a rule demanding strict increase would make rotation unrepresentable. **`att-09`** carries base §5's `policy_blinding` argument onto the scope commitments: a narrowed successor reusing its predecessor's blinding links the two openings if either is ever disclosed, recovering through the disclosure channel exactly the lineage the commitments hide.

### 3.2 Authorization provenance and the sufficiency boundary *(normative)*

Attenuation bounds a lineage from above by its issuance. It says nothing about whether the *issuance* was legitimate — and it cannot, because ZKM issuance is self-issued and unbounded (base §3). A principal may issue a mandate naming a resource it has no rights over, exactly as it may issue a cap larger than any balance it holds.

In the monetary case that over-issuance is inert by construction: authority is exercisable only over value the holder custodies at spend time, so an inflated cap authorizes spending of nothing. **Non-financial effects have no custody analogue.** Nothing about a resource is held in a note the holder must produce, so nothing structurally deflates an over-broad grant. The inertness has to come from the enforcement point instead, and this specification says so rather than leaving it implied:

- A resource owner or backend MUST treat a verifying mandate proof as **necessary and never sufficient** for access, and MUST independently establish that the mandate's principal held the authority being claimed.
- A conforming deployment MUST NOT present profile validity, or a successful negotiation, as an access decision (`fc-13`).
- Delegation cannot create rights the principal does not hold because every successor preserves `root_id` and narrows (`att-03`, `att-06`, `att-07`): a subtree's authority is bounded above by its issuance. That bound is what a lineage guarantees; whether the issuance itself was legitimate is the enforcement point's question, not the proof's.

This is a boundary statement, and it is deliberately not a mechanism. ZKM could not supply one: a protocol that verified a principal's standing over a named resource would need a resource directory to check it against, and that directory is the public capability registry the epoch's non-goals exclude (`fc-11`). The honest construction is the one above — the proof carries what it can carry, and the party that owns the resource owns the decision. Detecting and recovering from an accepted exercise that should not have been honored is the backend assurance and recovery specification's.

Three of these carry consequences worth stating in full.

**Blinding is REQUIRED on `resource_scope` and `purpose_scope` (`fc-08`).** Both are low-entropy: a resource identifier is a path, an endpoint name or a model id; a purpose is drawn from a short vocabulary. An unblinded commitment to either is recoverable by dictionary attack, and because both are preserved across successors it is also a lineage-stable correlator that links every exercise of the same grant. This is exactly the argument base §3 makes for `policy_hash`, applied to two fields whose preimages are *lower* entropy than a policy's. The blinding term MUST be non-zero.

**Attenuation is per-profile but monotonicity is not (`fc-12`).** Each profile declares its own narrowing relation — what it means for one quota to be narrower than another is not what it means for one permission scope to be narrower than another. What no profile may do is permit a successor that widens `resource_scope`, `purpose_scope` or duration. A profile MUST declare a narrowing registry before it becomes active.

**The delegation burn hazard applies to every class.** Base §6 requires a matched possession companion on every permitted DELEGATE or ROTATE, including partial delegation. A `zkm:effect-class:reusable-permission` grant has no cap to probe with, and a small-cap probe is not a substitute for the mandatory proof in any class. Each non-financial profile requires a companion that opens its own typed artifact, as specified in §3.3.


### 3.3 Possession and revocation activation requirements *(normative)*

Every non-financial profile MUST publish `activation_requirements` in its registry entry. That object is committed by `profile_set_id`; changing it requires a breaking profile revision even while the profile remains reserved. The monetary designation has `activation_requirements: null` because its implemented possession and revocation rules remain those of the base specification. Publishing these prerequisites does not supply the missing statements or activate a profile.

**Artifact-specific possession.** Before activation, each non-financial profile MUST have a profile-specific possession statement and qualified VK that prove knowledge of the new holder's secret and a complete successor opening under that profile's own `artifact_binding`. The derived holder key MUST equal the committed successor holder key. The proof MUST bind `effect_profile_id`, `artifact_binding`, `cm_successor`, the consumed mandate nullifier `nf`, and `settlement_context`, using public inputs or pinned circuit constants as appropriate. The accepting target MUST match those bindings to the exact management transition and its designated handoff successor. The future registered encoder defines the concrete vector; this list of required bindings does not register a proof layout.

The quota profile requires that companion for DELEGATE_FULL, DELEGATE_PARTIAL and ROTATE. Permission and action profiles require it for their permitted DELEGATE_FULL and ROTATE transitions; their forbidden fanout operations remain forbidden. Every required companion MUST accompany the atomic management transition. Identity evidence, a probe, or an unmatched holder-key proof MUST NOT substitute for the typed opening proof. `zkm:possession:v1` opens the nine-field monetary `MandateNote` with nonzero `asset_id`; it MUST NOT be claimed or accepted as a non-financial companion. Reusing circuit-library code is permitted, but the profile-specific statements and keys MUST obey `neg-09`/`fc-06` and remain disjoint across profiles.

**Revocation namespace.** Each non-financial profile uses scheme 2's `revoked-set-exclusion-depth-254` algorithm: canonical BN254 `root_id` bits select the full 254-level path and the revoked leaf binds the full identifier. Its authenticated logical namespace is the exact tuple

```text
(settlement_context, effect_profile_id, artifact_binding)
```

The target MUST select this tuple from its authenticated context and accepted profile/artifact registry entry before selecting roots or keys. A prover-supplied root or raw `root_id` MUST NOT choose another namespace. Each tuple has separate logical revocation roots, epochs, ordered publications and root history; the namespace MUST NOT share state with the monetary accumulator or another profile. Equal raw identifiers or equal root values in two namespaces do not authorize a state change in the other namespace. A shared storage service may host the trees only if it preserves these logical boundaries and authenticated routing.

Within each namespace, `root_id` retains the base derivation `H_{zkm/mandate_root_id/v1}(principal_issuance_key, issuance_randomness)`, with fresh issuance randomness per grant, and every successor preserves it. The tuple scopes logical state and leaves that derivation and the monetary tree unchanged. A non-financial revocation authorization MUST use a qualified profile-specific statement binding the tuple and the exact `root_id`, while proving the principal's preimage knowledge without disclosing the issuance key. Existing monetary authorization keys MUST NOT authorize it. Before activation, the profile's revocation update path MUST verify empty-to-full-identifier insertion continuity against that namespace's current tip and epoch and atomically commit the insertion and its ordered publication. Missing continuity, a root or epoch from another namespace, and partial publication MUST fail closed. The namespace requirements supplement the existing profile freshness rules: permission/action checks still require current roots and no offline acceptance; namespace selection MUST NOT extend a root's permitted age or the declared revocation lag. Revocation remains principal-only and prospective and cannot encumber ZKA custody or exit.

---

## 4. Effect Classes

An **effect class** fixes the conservation semantics of a group of profiles. It is the part of a profile's meaning that determines which base-specification invariants apply, so it is deliberately a small, closed vocabulary rather than a free-text field.

### 4.1 `zkm:effect-class:value-transfer` *(active)*

The monetary class the base specification defines. Consumptive, conserved, serialized by the mandate nullifier, quantified in asset atomic units, permitted both statement forms, and the only class that carries a ZKA value leg. It is listed here so the type system has a populated shipping member rather than four reserved ones — and so the rules below are stated over a set that contains a case where they are already known to hold.

### 4.2 `zkm:effect-class:conserved-quota` *(reserved)*

A counted non-financial consumable: N calls, N invocations, N units of a metered resource. Consumptive and conserved, serialized by the mandate nullifier, quantified in units the profile declares. Every exercise decrements remaining units and nullifies the consumed note, so the base specification's conservation and non-amplification arguments carry over unchanged — the note tree does not care what the units count.

It carries **no ZKA value leg**, and that absence is what makes it non-financial *structurally* rather than by convention. A quota exercise is a mandate-only transition: no ZKA note root, no ZKA nullifier, no ZKA output commitments, no `asset_id`. It does emit ZKM mandate successors when authority remains. The verification key is therefore incapable of authorizing value movement, by the same argument base §5 already makes for the mandate-only form.

#### 4.2.1 `zkm:effect:resource-quota:v1` accounting profile *(specified, reserved)*

This section specifies the quota profile's meaning and the transition statement an implementation must prove. It does **not** activate the profile. The class, artifact binding and profile remain `reserved`; `zkm:quota-transition:v1` is not in the statement registry and no verifier may accept this profile until a generated verifier, real-proof vectors and the coordinated activation required by §8 have landed. "Specified" here means that the reserved identifier now has one pinned meaning, not that it is deployable.

**Typed denomination (`quota-01`).** `denomination_id` is a non-zero BN254 field element derived from the exact canonical descriptor members `namespace`, `unit`, `scale`, `metering_rule`, `backend_authority_domain` and `version`, with no extension members. Encode the descriptor as UTF-8 canonical JSON with sorted object keys and no insignificant whitespace, hash `b"zkm/quota_denomination/v1\x00" || descriptor` with SHA-256, interpret the digest as a big-endian integer, and reduce it modulo BN254.Fr; zero is invalid. This off-circuit derivation fixes one interoperable descriptor identifier without asking a future circuit to implement SHA-256—the transition circuit binds and preserves the resulting field element. A descriptor's decimal scale is an integer from 0 through 18; one committed tick is `10^-scale` of its named unit. The denomination, including its metering rule and authority domain, is immutable under one identifier. A successor MUST preserve `denomination_id`; a different namespace, unit, scale, rule, authority or version derives a different identifier and cannot be substituted within a lineage. A RESERVE operation and terminal evidence MUST name the descriptor's committed `backend_authority_domain`; a caller-supplied backend cannot override it.

Every quantity is an unsigned integer number of ticks in the u128 domain. A boundary request represented as `(coefficient, decimal_scale)` is converted to committed ticks only when the conversion is exact. If conversion would discard a non-zero digit, the request MUST be rejected with `QUOTA_REJECT_NON_INTEGRAL`; implementations MUST NOT round up, round down, use binary floating point, or carry a fractional remainder. A deployment needing finer precision chooses a finer denomination before issuance. Values outside `[0, 2^128 - 1]`, and zero-unit reservations or consumptions, fail with `QUOTA_REJECT_RANGE`. These rules make "1 analysis" and "1 service-hour" different typed quantities and never reinterpret `remaining_cap` or an asset's atomic units.

**Committed live states (`quota-02`).** The quota artifact is a tagged union with two live states:

| State | `quota_state` | Reservation fields | Permitted disposition |
|---|---:|---|---|
| `AVAILABLE` | 1 | `reservation_commitment = 0`, `reservation_expiry = 0` | SPLIT, DELEGATE, ROTATE, RESERVE or RETIRE |
| `RESERVED` | 2 | both non-zero; deadline no later than mandate `expiry` | CONSUME, RELEASE or RETIRE only |

`SPENT`, `RELEASED` and `RETIRED` are terminal accounting outcomes, not reusable mandate notes. `SPENT` can never become available again. `RELEASED` is represented by a fresh `AVAILABLE` successor only after the evidence rules below pass. A reserved note cannot be split, delegated, rotated or reserved again; this prevents a holder from moving a lock away from the backend and idempotency scope that made it safe.

`reservation_commitment` is derived under `zkm/quota_reservation/v1` from the exact canonical JSON members `backend`, `scope`, `key`, `request_hash`, `created_at`, `expires_at` and fresh non-zero `randomness`, using the same domain-prefixed SHA-256-to-BN254-field procedure as `denomination_id`. Here `backend`, `scope` and `key` are the authenticated backend-authority domain, idempotency scope and idempotency-key hash; `created_at` is the settlement clock on the RESERVE transition; the other members have the meanings above. These members remain private unless voluntarily disclosed. The commitment binds the reservation to exactly one backend authority and request without putting a backend, resource, principal, grant or delegation directory in this registry.

**Conservation and transitions (`quota-03` through `quota-08`).** For every accepted transition, using assertion-bearing u128 arithmetic before any comparison or subtraction:

```text
input_units = Σ available_output_units
            + Σ reserved_output_units
            + spent_units
            + retired_units
```

All outputs preserve the denomination and shared attenuation floor. Successor commitments are fresh and pairwise distinct; there is no MERGE. Canonical settlement ordering accepts at most one transition for an input nullifier, so racing uses cannot amplify authority.

| Operation | Input | Outputs / terminal terms | Additional rule |
|---|---|---|---|
| SPLIT | `AVAILABLE(q)` | `AVAILABLE(q1)`, `AVAILABLE(q2)`; `q1 + q2 = q` | Both outputs positive. |
| DELEGATE_FULL | `AVAILABLE(q)` | one delegated `AVAILABLE(q)` | Fresh non-zero holder, depth +1 within both limits, and the profile-specific possession companion of §3.3. |
| DELEGATE_PARTIAL | `AVAILABLE(q)` | retained `AVAILABLE(q-r)`, delegated `AVAILABLE(r)` | `0 < r < q`; retained holder/depth unchanged; delegated holder fresh, depth +1 within both limits, and possession companion required by this profile. |
| ROTATE | `AVAILABLE(q)` | one `AVAILABLE(q)` | Fresh non-zero holder, depth unchanged, possession companion required. |
| RESERVE | `AVAILABLE(q)` | `RESERVED(r)` and, when `r < q`, `AVAILABLE(q-r)` | `0 < r ≤ q`; unique scoped key; `current_time < reservation_expiry ≤ expiry`. |
| CONSUME | `RESERVED(r)` | terminal `SPENT(s)` and, when `s < r`, fresh `AVAILABLE(r-s)` | `0 < s ≤ r`; authoritative terminal completion evidence binds `s`. |
| RELEASE | `RESERVED(r)` | fresh `AVAILABLE(r)` | Authoritative terminal `NOT_PERFORMED` evidence is required. |
| RETIRE | either live state `q` | terminal `RETIRED(q)` | Safe destruction while the mandate clock is valid; an expired artifact is already inert and cannot prove a transition. Never reported as spend. |

The reference procedure returns `QUOTA_ACCEPT` only after the full trace preserves the equation. It rejects a missing or already consumed input as `QUOTA_REJECT_INPUT_NOT_LIVE`, denomination substitution as `QUOTA_REJECT_DENOMINATION`, sibling or terminal imbalance as `QUOTA_REJECT_CONSERVATION`, an illegal tagged-state transition as `QUOTA_REJECT_STATE`, and an invalid reservation interval as `QUOTA_REJECT_DEADLINE`. Terminal processing without authenticated evidence is `QUOTA_REJECT_EVIDENCE_REQUIRED`; evidence that authenticates but does not match the committed backend, request, denomination or outcome is `QUOTA_REJECT_EVIDENCE_MISMATCH`.

The per-profile narrowing registry is `zkm:narrowing-registry:resource-quota:v1`: it is the shared `att-01`–`att-10` floor plus denomination preservation, additive conservation across **all** siblings, the tagged-state transition table above, and the reservation rules below. The single-successor `att-08` check is necessary but not sufficient: only the additive equation prevents a split into two individually smaller children whose sum exceeds the parent.

The required proof statement is `zkm:quota-transition:v1`. Before activation its circuit MUST bind the transition kind, settlement context and clock, accepted mandate and revocation roots, input nullifier, zero-to-two successor commitments, denomination identifier, reservation commitment/deadline where present, and a backend-evidence digest for CONSUME or RELEASE. Its public vector, verification key, generated verifier and real-proof fixtures belong to the statement surface, not this profile surface. Until they exist, the profile stays reserved.

**Reservation, cancellation and recovery (`quota-09` through `quota-13`).** Reservation removes ticks from `AVAILABLE` authority at settlement; it does not prove that the backend performed an effect. `BACKEND_START`, `CANCEL_INTENT`, `RESPONSE_TIMEOUT` and `ADVANCE_TIME` in the conformance traces are backend observations, not ZKM transition kinds: they consume no mandate nullifier and produce no successor commitment. The only proof transitions are the eight operations in the table above. This separation prevents cancellation or timeout metadata from being mistaken for a proof-authorized state change.

The backend MUST maintain one linearizable idempotency record per `(backend_authority_domain, idempotency_scope, idempotency_key_hash)`. The first request fixes its canonical request hash and reservation result. An identical retry returns or reconciles that result without another authority transition; a different request under the same scoped key fails with `QUOTA_REJECT_IDEMPOTENCY_CONFLICT`.

A cancellation is intent, not evidence. A timeout is uncertainty, not failure. Neither cancellation, response timeout nor `reservation_expiry` automatically releases authority. At expiry the backend MUST refuse to *start* a new effect under that reservation, but an effect started before the deadline may already have completed. The reservation therefore remains `RESERVED` until the authoritative record reaches one terminal outcome:

- `COMPLETED(actual_ticks, evidence_digest)`: CONSUME exactly `actual_ticks` and release any exact residual atomically;
- `NOT_PERFORMED(0, evidence_digest)`: RELEASE the full reservation; or
- no trustworthy terminal evidence: keep it reserved or RETIRE it. It MUST NOT be refunded.

Evidence MUST authenticate the backend authority committed by the reservation, the same idempotency scope/key, canonical request hash, denomination, measured tick count and terminal status. `COMPLETED` carries a positive exact count and a start time satisfying `created_at ≤ started_at < reservation_expiry` and `started_at ≤ current_time < mandate expiry`; `NOT_PERFORMED` carries the exact count zero. Missing or mismatched evidence fails closed. Conflicting terminal evidence is an integrity failure: no release is permitted, and the reservation remains locked or is retired pending the backend-assurance process owned by the backend assurance and recovery specification. ZKM serializes quota **authority**; it does not claim exactly-once backend execution.

**Enforcement claims (`quota-14` through `quota-16`).** Every deployment advertises one scope for each layer, and a verifier MUST reject a stronger claim than the deployment can support:

- `settlement-target-global` is available only for conservation of finalized ZKM authority inside one authenticated settlement target, whose canonical nullifier ordering covers every accepted transition for that target. It is not cross-target global.
- `backend-scoped` is the strongest permitted claim for reservation, metering, idempotency and effect evidence, and only when every effect for the committed backend-authority domain passes through one linearizable authoritative record.
- `unavailable` applies when that complete view or authenticated evidence cannot be established. A verifier requiring conserved effect accounting MUST refuse the profile; best-effort local counters are not a conforming substitute.

Universal or cross-target `global` effect-accounting claims, and exactly-once backend-effect claims, are non-conforming and fail with `QUOTA_REJECT_SCOPE_OVERCLAIM`. The conformance vectors exercise both canonical race orders, exact-conversion boundaries, descriptor substitution, full and partial delegation, holder/depth/possession bypasses, tagged-union validity, pre- and post-deadline backend starts, reservation expiry, cancellation, timeout/retry reconciliation, duplicate keys, completed-effect evidence and the no-premature-refund rule.

The machine-readable registry publishes the normative rules individually as `quota-01`, `quota-02`, `quota-03`, `quota-04`, `quota-05`, `quota-06`, `quota-07`, `quota-08`, `quota-09`, `quota-10`, `quota-11`, `quota-12`, `quota-13`, `quota-14`, `quota-15` and `quota-16`; the grouped headings above are editorial shorthand only.

### 4.3 `zkm:effect-class:reusable-permission` *(reserved)*

A standing permission valid within its scope and duration: "may read this dataset", "may call this endpoint". Non-consumptive — exercising it does **not** nullify the mandate note. Nothing is conserved because nothing is spent; the bound is duration, scope and revocation.

Two consequences follow directly and are enforced by the registry's own consistency rules: a non-consumptive class MUST declare `serialized_by: none` (there is no serialization event to emit) and MUST NOT declare itself conserved. A third is the live-note obligation below: because exercise emits no authority-consuming event, the verifier must privately check current revocation and spentness state on every use. A permission's disclosed effectiveness lag is not a detail of its profile; it is the profile's principal security parameter.

The privacy side of the same property is a benefit only when the live-note proof remains zero knowledge: repeated exercises emit no stable mandate identifier. Their fresh challenges and public request context may still be linkable by the resource owner or application, so the profile claims no application-level unlinkability.

Profile `zkm:effect:resource-permission:v1` specializes the class as follows.

**Exact request binding.** The resource owner issues a fresh, authenticated, owner-clock-bounded challenge. The exercise statement binds the request under

```text
request_binding = H_{zkm/nf_request_binding/v1}(
  settlement_context,
  effect_profile_id,
  owner_binding,
  resource_binding,
  purpose_binding,
  operation_id,
  canonical_arguments_digest,
  audience_binding,
  challenge_id,
  challenge_expiry
)
```

The resource and purpose openings remain private; `resource_binding` and `purpose_binding` are opaque commitments to the exact request values. The proof establishes that those exact values are inside both committed scopes and are permitted by `policy_hash`. The owner recomputes the binding from the request it is about to execute. A different settlement context, owner, resource, purpose, operation, argument encoding, audience or challenge MUST be rejected. The raw resource, purpose, arguments and audience MUST NOT become public inputs merely to perform this check. `canonical_arguments_digest` uses the canonical encoding selected by the enforcement surface; defining that encoding and enforcing the normalized arguments immediately before tool execution remains the capability runtime specification's runtime responsibility. ZKM owns the equality and scope predicates, not a duplicate tool middleware.

**Live-note proof.** Append-only note membership is insufficient for a reusable mandate. A management transition can consume the note, while its old commitment and opening remain valid historical data. Publishing the deterministic mandate nullifier on every exercise would let the verifier check spentness, but would also serialize and link every exercise, contradicting the class definition. A conforming permission exercise MUST instead privately prove that the note's deterministic nullifier is absent from an authenticated mandate-nullifier accumulator at a verifier-selected current root. The exercise vector carries that root, never the nullifier. A statement or deployment without this private unspent proof MUST NOT activate this profile.

**Freshness and duration.** Permission exercises require `not_before <= owner_time < expiry`. Both the revocation root and mandate-nullifier root MUST be current (`root_age = 0`) at the owner's decision; the base §7.2 predecessor-root allowance does not apply. A detached verifier that cannot obtain both current roots MUST reject, and no offline permission verifier is conforming. A deployment MUST publish a finite `permission_max_lifetime`, reject a mandate whose `expiry - not_before` exceeds it, and disclose the current-root publication/finality bound. The effective end of future authority is the earliest of expiry, a management transition becoming visible in the current nullifier root, or principal revocation becoming visible in the current revocation root. Those events are prospective: they do not erase downloaded data or undo an arbitrary external effect already accepted.

**Resource-owner acceptance.** A verifying proof is necessary and never sufficient (§3.2). Before each effect, the owner MUST independently accept the principal's standing over the resource, authenticate and consume the challenge in an owner-local ledger, recompute the exact request binding, apply its own policy, and record the roots and owner time used. Challenge consumption prevents replay of one proof; it is not ZKM authority consumption and does not make the permission single-use. A reusable permission MUST be rechecked for every protected effect and MUST NOT be exchanged for a bearer session that outlives the checked roots or mandate expiry.

**Management and attenuation.** Exercise is non-consumptive; management is not. `RETIRE`, `DELEGATE_FULL` and `ROTATE` consume the predecessor note and create at most one successor. `SPLIT` and `DELEGATE_PARTIAL` are forbidden because they would clone one standing right into multiple live holders. A successor preserves `root_id`, profile, artifact binding and the absence of units; may only narrow resource, purpose, operation, argument, audience and duration; and carries fresh scope blinding after any scope change. `DELEGATE_FULL` and `ROTATE` require the profile-specific typed possession companion of §3.3. The existing monetary companion cannot open this artifact, and no probing fallback substitutes for possession.

The lifecycle is therefore:

```text
                         exercise (fresh challenge, current roots)
                        +-----------------------------------------+
                        |                                         |
                        v                                         |
issued/live --------> authorized; no mandate state change --------+
    |
    +-- RETIRE ----------------------------------------------> retired
    +-- DELEGATE_FULL / ROTATE --> predecessor spent + one live successor
    +-- expiry / effective revocation -----------------------> unusable
```

### 4.4 `zkm:effect-class:single-use-action` *(reserved)*

Authority for exactly one exercise — "may cast this vote", "may accept this offer" — consumed by nullification like a quota of one, but committed under its own artifact binding (§5) because a one-shot authority read as a quota, or a quota read as a repeatable action, are both authority-multiplying misreadings.

**The exactly-once boundary, stated plainly.** ZKM serializes *authority consumption*, not *effects*. What a single-use action guarantees is that the mandate note can be nullified once, in one settlement context, under one canonical order. What it does not and cannot guarantee is that the backend performed the effect once: the backend may have performed it zero times, or twice, or once and lost the record, and no ZKM public input can distinguish those cases. A profile that claims otherwise is non-conforming (`fc-10`), and the registry enforces it — `exactly_once_scope` may only take the value `zkm-authority-consumption`. Detecting and recovering from the gap between an accepted exercise and a performed effect is the backend's obligation, and recourse for it is VXP's; both are named in §9.

Profile `zkm:effect:resource-action:v1` binds one action before exercise:

```text
action_binding = H_{zkm/nf_action_binding/v1}(
  settlement_context,
  effect_profile_id,
  owner_binding,
  resource_binding,
  purpose_binding,
  operation_id,
  canonical_arguments_digest,
  audience_binding,
  action_nonce,
  action_blinding
)
```

`action_nonce` distinguishes otherwise identical grants and `action_blinding` MUST be non-zero. The consume proof opens `action_binding`, proves that the request binding of §4.3 names the same context, owner, resource, purpose, operation, canonical arguments and audience, and emits the mandate nullifier for canonical insertion. Substituting any member fails. The opaque `action_binding` MAY be recorded with the consumption result, but its opening and the low-entropy raw values remain private.

**Reservation and consumption are distinct.** `reserved` is an optional, durable, owner-local record keyed by `(settlement_context, mandate_nullifier, action_binding)`. It is created only after profile/statement negotiation, independent resource-owner standing acceptance, exact-request verification and current-root checks. Reservation is not ZKM state, does not consume authority and MUST NOT by itself cause the external effect. Replicated owners MUST establish reservations with linearizable uniqueness.

Authority becomes `consumed` only when the settlement target validates and canonically inserts the exact mandate nullifier. The consumption statement binds the reserved `action_binding`, current revocation and nullifier roots, and the settlement target's authenticated context and clock; the target rejects a proof delayed across a root advance, an intervening revocation, a noncanonical inclusion, or a mismatched execution tuple. At that point the owner performs the effect under the stable execution key

```text
execution_key = H_{zkm/nf_action_execution/v1}(
  settlement_context, mandate_nullifier, action_binding
)
```

and durably stores its result or receipt. A concurrent second consumption loses on the shared nullifier set. A second reservation attempt for the same execution key returns the existing `reserved` classification rather than creating another reservation. A retry while reservation is pending likewise returns `reserved`; a retry after a durable result returns the same result as `already_completed`; and an observed consumption with no durable result returns `consumed_unresolved`. None authorizes a second effect. `already_completed` is a backend result class, not another ZKM authority state. A blind re-execution from `consumed_unresolved` is forbidden; recovery belongs to the backend assurance and recovery specification and VXP recourse.

If a reservation expires before consumption is observed, the owner reconciles against an authenticated current mandate-nullifier root using the exact reserved execution tuple. An invalid, stale or mismatched reconciliation fails closed and leaves the reservation in place. A validated absent nullifier releases the reservation and leaves authority live for a fresh challenge. A validated present nullifier produces `consumed_unresolved`, never a refund. A settlement rejection is treated the same way. Timeout alone MUST NOT resurrect authority that may have been consumed.

The action is valid only while `not_before <= owner_time < expiry`, unrevoked, unspent and exactly bound to the request. Revocation before consumption prevents the action once effective under the accepted root policy; revocation after consumption cannot change the consumption result or the backend's recorded outcome. As with permissions, no result can erase prior external effects or condition ZKA custody or exit.

Management permits only `RETIRE`, `DELEGATE_FULL` and `ROTATE`, consuming one predecessor and creating at most one successor. `SPLIT` and `DELEGATE_PARTIAL` would turn one action into two independently consumable notes and are forbidden. Every successor preserves `action_binding` exactly in addition to the shared attenuation floor; a changed action is a new issuance, not attenuation.

```text
issued/live -- owner-local reserve --> reserved
    |                                  |   |
    |                                  |   +-- timeout + nf absent --> live
    |                                  |   +-- timeout + nf present -> consumed_unresolved
    |                                  +------ canonical nf insertion --> consumed
    |                                                                      |
    |                                                                      +-- durable effect/result --> completed
    |                                                                      +-- missing result --------> consumed_unresolved
    +-- RETIRE -----------------------------------------------------------> retired
    +-- DELEGATE_FULL / ROTATE --> predecessor spent + one live successor
    +-- expiry / effective revocation -----------------------------------> unusable

retry(reserved)            = reserved
retry(completed)           = already_completed (same result/receipt)
retry(consumed_unresolved) = consumed_unresolved (no blind re-execution)
```

### 4.5 Common acceptance order and statement obligations

The resource owner evaluates an exercise in this order: (1) run the §6 profile/statement negotiation; (2) authenticate the owner challenge and independently accept principal standing; (3) validate the revocation proof and, for a permission, the private current-root nullifier-absence proof; (4) verify the profile-specific statement against the exact request, current roots, owner clock and accepted scopes; then (5) for a permission, atomically consume the challenge before the effect, or for an action, establish the local reservation and require the settlement target to revalidate current roots and exact consumption binding at canonical nullifier insertion before the effect. Rejection reasons are local-only, as in §6.

Both profiles remain `reserved`. Their eventual statement surfaces MUST be profile-specific and disjoint, and MUST cover issuance, exercise (`permission`) or consumption (`action`), management transition, possession, and revocation authorization. The permission exercise statement additionally MUST expose neither `root_id` nor the deterministic mandate nullifier and MUST bind a current mandate-nullifier root; the action consumption statement MUST emit its mandate nullifier and bind `action_binding`. No statement may carry a ZKA value leg. The profile, class and artifact MUST NOT become `active` until those statements and VKs are in the statement registry, the profile narrowing registry is published, and real-proof vectors establish these public-input constraints.

### 4.6 Backend assurance, effect evidence and recovery

ZKM proves authority; it does not observe an arbitrary backend effect. This section defines the common contract a resource owner uses to bind its own effect evidence to an accepted ZKM exercise, and the recovery behavior required when authority state, process state and an external effect cross failure domains. The contract identifier is `zkm:backend-assurance:v1`. Each non-financial profile references that contract, but the concrete assurance class is selected per authenticated `backend_authority_domain` by the deployment registry and repeated in every evidence record. It is not fixed by the effect profile, and one deployment MUST NOT advertise a stronger class than every effect path in that backend domain supports.

Two assurance classes are defined.

| Class | Required commit boundary | Honest effect claim |
|---|---|---|
| `zkm:backend-assurance:atomic:v1` | The final authority/freshness recheck, profile-specific authority or challenge consumption, effect, idempotency record and terminal evidence commit or roll back in one linearizable transaction and failure domain. | A committed `COMPLETED` record establishes the backend's declared transactional effect. A crash before commit leaves none of them committed; a crash after commit is recovered by returning the same durable record. Any downstream side effect outside that transaction forbids this class. |
| `zkm:backend-assurance:reconciled:v1` | A linearizable execution record is durably reserved before dispatch under one stable execution key. Dispatch, the external effect and local evidence may cross failure domains. | Authenticated terminal evidence may establish `COMPLETED` or `NOT_PERFORMED`. Otherwise bounded reconciliation ends in `INDETERMINATE`. The class does not promise exactly-once execution. |

There is no authorization-only assurance class. A deployment unable to meet either contract may still verify a proof, but it MUST advertise backend assurance as unavailable and MUST NOT emit conforming effect evidence. `atomic` means atomic inside the declared backend transaction domain, not universal exactly-once delivery; `reconciled` permits duplicate transport attempts only where the target atomically deduplicates the same execution key. Neither class permits blind execution or redispatch after an unknown outcome.

**Normalized request and evidence binding (`ba-01` through `ba-04`).** The runtime that actually invokes the effect produces

```text
normalized_action_digest = H_{zkm/backend_normalized_action/v1}(
  normalization_profile_id,
  operation_id,
  canonical_arguments_digest,
  audience_binding
)
```

Defining canonical argument encodings and enforcing them immediately before tool execution remains the general capability runtime's responsibility (the capability runtime specification). ZKM requires equality between that runtime-produced digest, the proof-bound request and the backend evidence; it does not duplicate the middleware.

Every evidence record is authenticated by the deployment-pinned `evidence_key_set_id`, hash-chained by `sequence` and `previous_evidence_digest`, and binds exactly these members: `contract_id`, `assurance_class`, `backend_authority_domain`, `evidence_key_set_id`, `execution_key`, `request_binding`, `normalized_action_digest`, opaque `resource_binding`, opaque `purpose_binding`, request-scoped opaque `agent_binding`, `effect_profile_id`, `artifact_binding`, `profile_set_id`, `statement_id`, `statement_set_id`, `settlement_context`, a profile-specific `authority_reference`, `freshness_context_digest`, `evidence_kind`, `outcome`, `sequence`, `previous_evidence_digest`, `observed_at` and `result_digest`. The first record under an execution key fixes every binding member; an exact retry returns the same durable state, while a different binding under that key is an integrity conflict.

`agent_binding` connects the authenticated caller at the backend boundary to the accepted holder proof without exposing `holder_key`, `root_id`, a principal identity, a lineage, or a stable cross-backend identifier. `authority_reference` is tagged by profile: quota evidence binds the reservation commitment and committed backend/idempotency tuple; permission evidence binds the consumed owner challenge and request binding without publishing the mandate nullifier; action evidence binds the canonical mandate-nullifier insertion and its `zkm/nf_action_execution/v1` key. `freshness_context_digest` is computed under `zkm/backend_freshness_context/v1` over the owner and settlement clocks, `not_before`, `expiry`, the exact current revocation and mandate-nullifier roots and their authenticated positions, the root finality policy, challenge identifier and expiry, and canonical inclusion reference where the profile requires it. Evidence MUST NOT carry raw resource, purpose, arguments, audience, principal or delegation-path values.

`evidence_kind = AUTHORIZATION` has outcomes `ACCEPTED`, `RESERVED`, `CONSUMED` or `REJECTED`. `evidence_kind = EFFECT` has outcomes `PENDING`, `COMPLETED`, `NOT_PERFORMED`, `INDETERMINATE` or `INTEGRITY_FAILURE`. Authorization, reservation, consumption, dispatch, start, cancellation and timeout evidence are **not delivery evidence** (`ba-04`). Only authenticated `EFFECT/COMPLETED` evidence may support a VXP fulfillment decision, and only for the deployment's declared completion predicate. `NOT_PERFORMED`, `INDETERMINATE` and `INTEGRITY_FAILURE` are evidence for reconciliation or VXP recourse, not proof that authorization failed. Even `COMPLETED` attests the backend predicate; it does not claim that an arbitrary downstream human or system received the intended benefit.

**Effect boundary and concurrency (`ba-05` through `ba-08`).** Immediately before the first irreversible effect, the backend MUST repeat principal-standing, local-policy, exact request/agent binding, expiry, revocation and spentness checks against current authenticated roots. Revocation or expiry visible before that boundary prevents a start. A revocation or expiry that becomes effective after a recorded start is prospective: it cannot erase an effect already in flight or rewrite its terminal evidence. Each `(backend_authority_domain, execution_key)` has one linearizable record. Concurrent identical requests coalesce on it; a different request under that key fails closed. An atomic-class commit includes all boundary checks and mutations above. A reconciled-class backend durably records its reservation/outbox before dispatch and MUST use an authenticated status query or receipt plus a terminal fence before declaring `NOT_PERFORMED`.

**Recovery (`ba-09` through `ba-13`).** The append-only state graph is:

```text
NONE -> PREPARED -> STARTED_OR_UNKNOWN -> RECONCILING
                  |                    |-> COMPLETED
                  |                    |-> NOT_PERFORMED
                  |                    `-> INDETERMINATE -> COMPLETED | NOT_PERFORMED

COMPLETED | NOT_PERFORMED -- conflicting terminal evidence --> INTEGRITY_FAILURE
```

A crash before an atomic commit leaves authority, effect and terminal evidence unchanged; retry may execute once. A crash after commit returns the committed evidence without executing again. On the reconciled path, a crash before reservation commit leaves no record; a crash after reservation returns the same reservation; and a crash after dispatch but before result persistence enters `STARTED_OR_UNKNOWN` and may query but MUST NOT blindly redispatch. Cancellation, timeout, reservation expiry, process loss and a transient external "not found" response are observations of uncertainty, never `NOT_PERFORMED`.

Every reconciled deployment publishes both a finite reconciliation deadline and a finite attempt bound. Attempts use the same execution key and append-only evidence chain. Exhausting either bound appends `INDETERMINATE`, stops automatic execution and redispatch, and invokes the profile disposition below. `INDETERMINATE` is terminal for automation, not necessarily the last evidence record: later authenticated evidence MAY append `COMPLETED` or `NOT_PERFORMED` referencing the indeterminate record. It cannot rewrite history, re-execute work or resurrect consumed authority. Conflicting authenticated terminal evidence appends `INTEGRITY_FAILURE`, stops automatic action and retains or retires any locked authority pending operator investigation and VXP recourse.

| Profile | `COMPLETED` | `NOT_PERFORMED` | `INDETERMINATE` / integrity failure |
|---|---|---|---|
| Conserved quota | CONSUME the exact evidenced ticks and atomically release only the exact residual. | RELEASE the full reservation only from authenticated terminal zero-effect evidence. | Keep the quota `RESERVED` or RETIRE it; never refund from uncertainty. |
| Reusable permission | Record the result; ZKM authority remains live. | Record non-delivery; another attempt requires a fresh challenge and execution key. | Authority remains live, but the uncertain execution key is fenced from blind replay. |
| Single-use action | Return the durable result; authority remains consumed. | Before nullifier insertion, an authenticated current exact-key absence proof may release the local reservation; after insertion authority remains consumed. | A present nullifier is `consumed_unresolved`; never refund, resurrect or re-execute. |

`ba-14` limits every claim to the authenticated backend domain: no class claims global effect accounting or arbitrary-effect exactly-once delivery. `ba-15` preserves the ownership and privacy boundary: effect evidence creates no public resource, identity, mandate or delegation directory, and no outcome may condition ZKA custody or exit. The registry and conformance vectors pin the class prerequisites, evidence members, state graph, profile dispositions and all fifteen rules.

---

## 5. Artifact Bindings

An **artifact binding** is the committed shape of a mandate under a given class: its commitment domain, its nullifier domain and its field list. One binding per class, each with its own domains.

| Binding | Commitment domain | Fields | Status |
|---|---|---|---|
| `zkm:mandate-artifact:v1` | `zkm/mandate_commitment/v1` | the nine of base §3, unchanged | active, **wire-frozen** |
| `zkm:mandate-artifact:nf-quota:v1` | `zkm/mandate_commitment/nf_quota/v1` | `root_id`, `settlement_domain`, `effect_profile_id`, `denomination_id`, `resource_scope`, `purpose_scope`, `remaining_units`, `quota_state`, `reservation_commitment`, `reservation_expiry`, `not_before`, `expiry`, `policy_hash`, `holder_key`, `depth`, `randomness` | reserved; semantics specified |
| `zkm:mandate-artifact:nf-permission:v1` | `zkm/mandate_commitment/nf_permission/v1` | `root_id`, `settlement_domain`, `effect_profile_id`, `resource_scope`, `purpose_scope`, `not_before`, `expiry`, `policy_hash`, `holder_key`, `depth`, `randomness` | reserved |
| `zkm:mandate-artifact:nf-action:v1` | `zkm/mandate_commitment/nf_action/v1` | `root_id`, `settlement_domain`, `effect_profile_id`, `resource_scope`, `purpose_scope`, `action_binding`, `not_before`, `expiry`, `policy_hash`, `holder_key`, `depth`, `randomness` | reserved |

Each binding's nullifier domain mirrors its commitment domain (`zkm/mandate_nullifier/nf_quota/v1`, and so on).

Five properties do the work.

**1. Domain separation makes cross-profile reinterpretation unwitnessable.** A monetary opening is not a witness for any non-financial binding and no non-financial opening is a witness for the monetary one, because the commitment preimages are domain-separated before their contents are compared. This is the structural answer to the problem statement: a mandate cannot *gain* non-financial meaning, because meaning is fixed at issuance by the domain it commits under. Forbidden constructions `fc-02` and `fc-03` — `asset_id` reused as a resource identifier, `remaining_cap` reread as a unit count — are not merely prohibited; they are unprovable.

**2. No non-financial binding carries `asset_id` or `remaining_cap`.** The registry check enforces both absences. A quota mandate cannot name an asset, so it cannot be opened as a spend authorization however its units are read.

**3. Absence is structural, never a sentinel.** The permission binding has no units field *at all*. It is not a quota holding a reserved value, so there is no zero-value convention to misread and no field whose meaning depends on which class is reading it. This is the rule that keeps the framework from reintroducing, one level up, the ambiguity it was built to remove.

**4. Every non-financial binding commits `effect_profile_id`.** Domain separation distinguishes classes; the committed profile identifier distinguishes two profiles *within* a class. Without it, two quota profiles over different resources would share a commitment domain and be mutually openable.

**5. The monetary binding is frozen and is re-derived, not restated.** The registry's field list for `zkm:mandate-artifact:v1` is checked on every CI run against the base specification's own `H_{zkm/mandate_commitment/v1}` argument list *and* its §3 field table, and against the `zkm/mandate_nullifier/v1` line. A registry that drifts from the specification fails the gate rather than being believed, and a specification edit that moves the monetary preimage fails it too.

---

## 6. Profile Negotiation

Negotiation is where the "explicit, versioned" requirement becomes executable. ZKM defines the *content* of the exchange and the decision procedure over it; the transport that carries them is VXP's (§9).

### 6.1 The two messages

An **acceptance set**, published by the verifier or resource owner:

```text
profile_set_id                          the profile surface it is pinned to
statement_set_id                        the statement surface it is pinned to
accepted_profiles[]                     profile identifiers it will honor
allow_baseline_without_discriminator    whether it accepts the §6.3 exemption
```

An **offer**, presented by the prover:

```text
profile_id, profile_version             the explicit discriminator
profile_set_id, statement_set_id        both pins
statement                               which proof form is carried
artifact_binding                        which committed shape the mandate has
carries_zka_value_leg                   whether a ZKA spend accompanies it
```

### 6.2 The decision procedure *(normative)*

The steps run in exactly this order. The order is published in the registry and checked against the reference implementation, so it cannot drift into prose.

| # | Step | Reason code on failure |
|---|---|---|
| 1 | The offer carries both `profile_id` and `profile_version`, or both are absent and the offer qualifies for the §6.3 exemption. Exactly one absent discriminator is always rejected. | `REJECT_MISSING_DISCRIMINATOR` |
| 2 | Both parties carry a `profile_set_id`. | `REJECT_UNPINNED_PROFILE_SET` |
| 3 | Offer, acceptance set and registry agree on `profile_set_id`. | `REJECT_PROFILE_SET_MISMATCH` |
| 4 | Offer, acceptance set, effect-profile registry and supplied statement registry agree on `statement_set_id`. | `REJECT_STATEMENT_SET_MISMATCH` |
| 5 | The profile identifier is published by the agreed registry revision. | `REJECT_UNKNOWN_PROFILE` |
| 6 | `profile_version` agrees with the identifier's own suffix. | `REJECT_VERSION_MISMATCH` |
| 7 | The profile's status is `active`. | `REJECT_PROFILE_NOT_ACTIVE` |
| 8 | The verifier's acceptance set lists the profile. | `REJECT_PROFILE_NOT_ACCEPTED` |
| 9 | The offered artifact binding is the one the registry records for that profile. | `REJECT_ARTIFACT_BINDING_MISMATCH` |
| 10 | The offered statement is one the profile lists. | `REJECT_STATEMENT_NOT_IN_PROFILE` |
| 11 | If the profile's class declares no value leg, the offer carries none. | `REJECT_VALUE_LEG_ON_NONFINANCIAL_PROFILE` |
| 12 | `carries_zka_value_leg` is an explicit boolean equal to the offered statement's `value_moving` boolean in the pinned statement registry. Missing or non-boolean flags and statements absent from that registry fail closed. | `REJECT_VALUE_LEG_MISMATCH` |
| — | Otherwise | `ACCEPT` |

An acceptance returns the resolved `{profile_id, profile_version}` alongside its decision and local reason code. This includes an accepted baseline exemption. A rejection returns no resolved profile. Consumers MUST dispatch on this validated return value, never on the raw offer discriminator (`neg-12`). The implementation receives the pinned statement registry explicitly; it MUST NOT infer `value_moving` from a statement name.

Five rules govern how that procedure may be used.

**No default and no downgrade.** There is no implicit profile, no nearest match, and no fallback to the baseline when the offered profile is unknown (`fc-05`). A downgrade path is the most dangerous construction in this document: it converts an unrecognized non-financial grant into a spend authorization.

**A statement never selects a profile (`fc-04`, `fc-06`).** A statement identifies a proof *shape*; it does not identify the effect being authorized. Step 10 is a membership check, not a lookup: the profile is named explicitly and the statement must belong to it. The registry additionally enforces that no two profiles claim the same statement, because one verification key serving two profiles is the profile-level form of the aliasing hazard the base specification already resolves between control attestation and revocation authorization.

**Reserved is not activatable by agreement (`fc-07`).** Step 7 fails even when both parties list the profile. Activation is a registry revision with a moved `profile_set_id`, reviewable as a protocol change; bilateral agreement is not a substitute.

**Publication is not acceptance.** Step 8 is separate from step 7 for a reason: an active, published profile is still refused by a party that has not opted into it.

**Rejection is silent as to reason.** Reason codes are for local logs, for conformance vectors and for this document. Telling a counterparty *which* of twelve checks failed leaks the shape of an acceptance set, and an acceptance set is a description of what a party is willing to do.

### 6.3 The single exemption

`zkm:effect:value-transfer:v1` is the only profile whose `requires_explicit_discriminator` is false, for one reason: its envelopes were specified and deployed before this registry existed, so requiring a discriminator would retroactively invalidate conforming artifacts. Every other profile, present and future, MUST carry one — the registry check enforces that exactly one profile holds the exemption, that it is a designation of a pre-registry surface, and that it is bound to the monetary artifact.

The exemption is scoped to the **monetary artifact binding**, not merely to the baseline profile. An undiscriminated offer whose artifact binding is non-financial is rejected at step 1 even where the exemption is enabled. Without that scoping, the exemption would be precisely the laundering path the framework exists to close.

The exemption applies only when **both** `profile_id` and `profile_version` are absent (including null). A half-discriminated offer is malformed and MUST be rejected, even when it names an unknown or reserved profile and carries the monetary artifact binding. The acceptance set MUST explicitly opt in with `allow_baseline_without_discriminator: true`.

A pre-registry `zkm:proof:v1` envelope has no fields for the two registry pins. A profile-aware transport adapter therefore constructs a separate negotiation offer wrapper: it authenticates the envelope's artifact shape and statement, binds them to its deployment-selected `profile_set_id` and `statement_set_id`, and includes both pins in the offer. The verifier independently selects and authenticates its acceptance-set pins. Neither pin is inferred from the missing discriminator, and neither pin check is waived. The adapter MUST preserve the canonical envelope bytes and MUST refuse an envelope whose authenticated shape or statement does not match the selected monetary binding. The exemption designates the existing artifact; it does not change its wire format. An envelope presented without this pinned wrapper fails the ordinary pin checks. VXP owns the wrapper's transport and authentication, as it does for every offer.

---

## 7. Safeguard and Privacy Analysis

The base specification's §9 safeguard analysis applies unchanged; this section records what the profile framework adds.

**Custody and exit stay independent (`fc-09`).** No non-financial profile may condition ZKA custody or exit on an exercise, and no profile's revocation may encumber a ZKA note. Step 11 of the decision procedure is the negotiation-level enforcement — a class declaring no value leg cannot be offered with one — and the class-level rule that such a class may not permit the spend-conjoined statement form is the structural one. A permission that can freeze value is a Safeguard 3 violation whatever it is called.

**No public capability registry (`fc-11`).** The registry enumerates profiles: four identifiers, their classes and their artifact bindings. It contains no resource, no principal, no grant and no delegation, and nothing derived from it may. A resource directory is the universal capability registry the epoch's non-goals exclude; a delegation directory is the lineage graph the base specification exists to remove.

**Disclosure is unchanged.** `zkm:disclosure:v1` and its five rules apply to non-financial lineages exactly as to monetary ones. No profile may add a compulsory, operator-exercisable or third-party-exercisable disclosure surface, and no protocol behavior may condition on whether a disclosure was made.

**What a verifier learns.** For a monetary exercise: what base §5 already publishes. For a non-financial exercise the verifier learns that *some* valid, unrevoked, unexpired, in-scope authority of the named profile was exercised — not the resource, not the purpose, not the remaining units, not the principal, and not the delegation depth beyond the disclosed `depth_max`. Both scope commitments are blinded (§3), so neither the settlement record nor a colluding pair of verifiers recovers them.

**The zero-value construction, and why it is not merely discouraged (`fc-01`).** A zero-amount monetary spend used to signal a non-financial action fails on its own terms: a monetary envelope carries the baseline profile whatever its amount, and since rev 7 the amount is not on the public vector at all — so the signal would be invisible to the very verifier meant to read it. It is listed as a forbidden construction because it is the first thing an implementer reaches for, not because it is subtle.

---

## 8. Version Discipline

**Breaking.** Adding, removing, activating, retiring or renaming a profile, including a reserved profile. Changing any class's conservation semantics, serialization, statement forms or value-leg flag. Changing an artifact binding's commitment domain, nullifier domain or field list. Changing the negotiation acceptance-set or offer members, evaluation order, reason codes or any rule. Changing the attenuation claim members, invariant order, reason codes, any invariant, or the provenance rules. Changing quota denomination, state, transition, conservation, idempotency, evidence, recovery or enforcement semantics. Changing a permission/action request binding, execution key, lifecycle profile, evaluation order, reason code or rule. Changing a backend-assurance class, evidence binding, state transition, reconciliation bound, profile disposition, reason code or rule. Changing an active profile's statement list, artifact binding or narrowing registry. Changing a profile's activation requirements, possession bindings or revocation namespace, including while reserved. Adding, removing or re-verdicting a forbidden construction.

**Non-breaking.** Editorial changes to prose fields. Adding a compatibility-matrix row that records an already-decidable outcome.

**Rules.** A breaking revision MUST bump `revision`, append a `revision_history` entry whose `profile_set_id` differs from its predecessor's, and set `last_breaking_revision` to that revision. A non-breaking revision MUST carry its predecessor's `profile_set_id` unchanged. A revision that activates a profile MUST NOT be published before that profile's statements appear in the statement registry. A non-financial activation MUST also wait for the ZKA-owned canonical family manifest to pin its `profile_set_id` and for consumer snapshots to enforce that pin. The current ZKA-owned canonical family manifest carries no profile-surface pin; the upstream pin has been requested and all three non-financial profiles remain reserved. Moving this registry MUST NOT require a statement-registry revision, and MUST NOT move `statement_set_id`.


**Activation checklist (normative).** Before any non-financial profile becomes active, its implementation and release MUST satisfy all of the following:

1. Publish its profile-specific statements, including the §3.3 possession companion for every permitted handoff, in the statement registry with complete vectors, encoders, pinned keys, generated verifiers and real-proof fixtures. Demonstrate correct typed openings and rejection of monetary openings, wrong holders, mismatched handoff commitments, nullifiers, contexts and profiles.
2. Publish the §3.3 revocation namespace and qualify its separate roots, epochs and history, profile-specific principal authorization, insertion continuity, current-tip/epoch binding and atomic ordered publication. Real-proof and target tests MUST reject cross-namespace authorization, root substitution and partial updates. A declaration of `activation_requirements` without these artifacts is insufficient.
3. Publish the narrowing registry and obtain the ZKA-owned canonical family `profile_set_id` pin with enforcing consumer snapshots. Preserve the current hold until that upstream prerequisite is satisfied.
4. Publish activation as a breaking profile revision and coordinate the statement/profile pins. This revision satisfies none of the missing statement or family-pin prerequisites: all three non-financial profiles and their artifact bindings remain reserved and claim no current statements.

### 8.1 Compatibility matrix

The registry publishes seventeen rows; each is evaluated as a known-answer vector in `tests/vectors/zkm_effect_profile_negotiation_vectors.json`, and the gate fails if a row has no vector, if a vector disagrees with its row, or if any published reason code goes unexercised. A matrix row nobody evaluates is a claim nobody checked.

| Row | Situation | Outcome |
|---|---|---|
| `cm-01` | Baseline offer, fully discriminated, baseline-only acceptance set | accept |
| `cm-02` | Active non-financial offer, baseline-only acceptance set | `REJECT_PROFILE_NOT_ACCEPTED` |
| `cm-03` | Monetary artifact, no discriminator, exemption enabled | accept |
| `cm-04` | Reserved profile both parties list | `REJECT_PROFILE_NOT_ACTIVE` |
| `cm-05` | Non-financial artifact, no discriminator, exemption enabled | `REJECT_MISSING_DISCRIMINATOR` |
| `cm-06` | Offer carries no `profile_set_id` | `REJECT_UNPINNED_PROFILE_SET` |
| `cm-07` | Parties pin different profile surfaces | `REJECT_PROFILE_SET_MISMATCH` |
| `cm-08` | Parties pin different statement surfaces | `REJECT_STATEMENT_SET_MISMATCH` |
| `cm-09` | Baseline profile on a foreign artifact binding | `REJECT_ARTIFACT_BINDING_MISMATCH` |
| `cm-10` | Profile carrying a statement it does not list | `REJECT_STATEMENT_NOT_IN_PROFILE` |
| `cm-11` | Non-financial profile carrying a ZKA value leg | `REJECT_VALUE_LEG_ON_NONFINANCIAL_PROFILE` |
| `cm-12` | An identifier this revision never published | `REJECT_UNKNOWN_PROFILE` |
| `cm-13` | `profile_version` disagrees with the identifier suffix | `REJECT_VERSION_MISMATCH` |
| `cm-14` | Well-formed active non-financial offer, both parties accept | accept |
| `cm-15` | Unknown profile with its version absent, baseline exemption enabled | `REJECT_MISSING_DISCRIMINATOR` |
| `cm-16` | Baseline spend-conjoined statement with no ZKA value leg | `REJECT_VALUE_LEG_MISMATCH` |
| `cm-17` | Baseline revocation-authorization statement with a ZKA value leg | `REJECT_VALUE_LEG_MISMATCH` |

Rows `cm-02`, `cm-10`, `cm-11` and `cm-14` are evaluated against a **synthetic active profile** declared in the vector file, because no non-financial profile is active in the current published registry. The synthetic profile rests on the published `zkm:effect-class:conserved-quota` class, so the rules it exercises are the real ones; the checker refuses an overlay identifier that collides with a published one or that invents its own class. Without those four rows, the rules that bite only on active non-financial profiles would remain untested until a real profile passes the statement-surface activation gate, and `cm-14` in particular is what shows the other thirteen are discriminating rather than a procedure that rejects everything.

**Backward compatibility, stated directly.** A consumer that predates this framework keeps working: the monetary surface is untouched, and `cm-01` and `cm-03` are the executable statement of that. Presented with a non-financial envelope it refuses — either because the profile is not in its acceptance set, or, for a truly pre-registry consumer that never runs this procedure at all, because the non-financial statement is absent from its statement registry. Both paths end in refusal rather than reinterpretation, which is the property that matters.

### 8.2 Forbidden constructions

The registry carries nineteen, each with a rationale: `fc-01` zero-amount monetary spend as a non-financial signal; `fc-02` `asset_id` overloaded as a resource; `fc-03` `remaining_cap` reread as a unit count; `fc-04` profile inferred from the statement; `fc-05` downgrade to the baseline on an unknown profile; `fc-06` one verification key serving two profiles; `fc-07` activation by deployment agreement; `fc-08` unblinded scope commitments; `fc-09` a profile conditioning ZKA custody or exit; `fc-10` a claim of exactly-once backend effects; `fc-11` a public directory derived from the registry; `fc-12` a successor widening scope or duration; `fc-13` a backend treating a verifying proof or a successful negotiation as an access decision; `fc-14` a successor switching effect profile or artifact binding; `fc-15` a permission disguised as a quantity or exercised through a public/stable nullifier; `fc-16` a request whose context, operation, arguments or audience are not bound through execution; `fc-17` stale-root or offline permission acceptance; `fc-18` fan-out management for either M3 profile; and `fc-19` automatic action refund or blind execution after an ambiguous timeout/result.

### 8.3 Permission/action lifecycle vectors

The vector package evaluates the fifteen lifecycle rules `pa-01`, `pa-02`, `pa-03`, `pa-04`, `pa-05`, `pa-06`, `pa-07`, `pa-08`, `pa-09`, `pa-10`, `pa-11`, `pa-12`, `pa-13`, `pa-14` and `pa-15`: independent owner standing; authenticated one-use challenges; half-open duration; current roots; private permission spentness; exact request binding; non-mutating repeated permission use; no-fanout management; immutable action binding; owner-local non-consuming reservation; canonical authority consumption; retry classifications; reconciliation before release; prospective termination; and the privacy/ZKA/exactly-once boundaries. Every rule is cited by at least one vector and every published lifecycle reason is observed by at least one step.

The local-only reason vocabulary is: `PA_ACCEPT_PERMISSION`, `PA_ACTION_RESERVED`, `PA_ACTION_CONSUMED`, `PA_MANAGEMENT_ACCEPTED`, `PA_ACTION_RESERVATION_RELEASED`, `PA_RESULT_RESERVED`, `PA_RESULT_ALREADY_COMPLETED`, `PA_RESULT_CONSUMED_UNRESOLVED`, `PA_REJECT_OWNER_STANDING`, `PA_REJECT_INVALID_CHALLENGE`, `PA_REJECT_REPLAYED_CHALLENGE`, `PA_REJECT_NOT_YET_VALID`, `PA_REJECT_EXPIRED`, `PA_REJECT_STALE_REVOCATION_ROOT`, `PA_REJECT_STALE_NULLIFIER_ROOT`, `PA_REJECT_INVALID_REVOCATION_PROOF`, `PA_REJECT_INVALID_UNSPENT_PROOF`, `PA_REJECT_REVOKED`, `PA_REJECT_AUTHORITY_SPENT`, `PA_REJECT_SETTLEMENT_CONTEXT`, `PA_REJECT_RESOURCE_BINDING`, `PA_REJECT_RESOURCE_SCOPE`, `PA_REJECT_PURPOSE_BINDING`, `PA_REJECT_PURPOSE_SCOPE`, `PA_REJECT_OPERATION`, `PA_REJECT_ARGUMENTS`, `PA_REJECT_AUDIENCE`, `PA_REJECT_ACTION_BINDING`, `PA_REJECT_ILLEGAL_TRANSITION`, `PA_REJECT_ACTION_BINDING_CHANGE`, `PA_REJECT_DELEGATE_POSSESSION`, `PA_REJECT_NONCANONICAL_CONSUMPTION`, `PA_REJECT_CONSUMPTION_BINDING`, `PA_REJECT_INVALID_RECONCILIATION_PROOF`, `PA_REJECT_RECONCILIATION_BINDING` and `PA_REJECT_RESULT_WITHOUT_CONSUMPTION`. As with §6, these values are conformance/logging labels, never a wire oracle for probing owner policy.

### 8.4 Backend-assurance vectors

The vector package evaluates `ba-01`, `ba-02`, `ba-03`, `ba-04`, `ba-05`, `ba-06`, `ba-07`, `ba-08`, `ba-09`, `ba-10`, `ba-11`, `ba-12`, `ba-13`, `ba-14` and `ba-15` with a deterministic simulated backend. It covers the full atomic/reconciled × quota/permission/action matrix, crashes before and after commit, exact and conflicting duplicates, stale authorization at the effect boundary, lost asynchronous results, authenticated terminal evidence, timeouts, finite reconciliation and indeterminate outcomes. The checker requires every rule and reason code to be exercised and verifies the profile dispositions in §4.6.

The local-only reason vocabulary is: `BA_ACCEPTED`, `BA_ATOMIC_COMPLETED`, `BA_PENDING`, `BA_RECONCILING`, `BA_COMPLETED`, `BA_NOT_PERFORMED`, `BA_INDETERMINATE`, `BA_REPLAYED`, `BA_REJECT_BINDING`, `BA_REJECT_OWNER_STANDING`, `BA_REJECT_NOT_YET_VALID`, `BA_REJECT_EXPIRED`, `BA_REJECT_STALE_ROOT`, `BA_REJECT_REVOKED`, `BA_REJECT_IDEMPOTENCY_CONFLICT`, `BA_REJECT_ATOMICITY_OVERCLAIM`, `BA_REJECT_EVIDENCE`, `BA_REJECT_CONFLICTING_EVIDENCE` and `BA_REJECT_DELIVERY_CLAIM`. These values are diagnostic results, not evidence in their own right.

---

## 9. Handoffs *(informative)*

This framework remains deliberately incomplete in one cross-protocol place. The quota handoff is complete at specification strength in registry revision 4, the permission/action handoff in revision 3, and backend assurance/recovery in revision 5; activation remains gated on the profile-specific statement artifacts named in §§4.2.1 and 4.5.

| Deliverable | Owner |
|---|---|
| Reserved quota unit semantics, narrowing relation, accounting transitions and conformance vectors for `zkm:effect:resource-quota:v1` | Conserved consumable quota specification (specified in §4.2.1; activation still requires its statement/VK prerequisites) |
| Reserved exercise mechanics, narrowing relations, statement obligations and lifecycle vectors for `zkm:effect:resource-permission:v1` and `zkm:effect:resource-action:v1` | Reusable permission and single-use action specification (specified in §§4.3–4.5; activation still requires the statement/VK prerequisites there) |
| The negotiation transport, plus negotiated acquisition, fulfillment and recourse | VXP negotiation and fulfillment specification (VXP) |

Each profile MUST, before activation, satisfy §8's full checklist, including its typed possession statement and isolated revocation namespace (§3.3), land its statements in the statement registry, declare a narrowing registry, satisfy the ZKA-owned family profile-pin prerequisite, and publish activation as a breaking revision here. The quota profile has declared its relation but has not satisfied the statement-surface gate.

---

## 10. Open Questions *(informative)*

1. **Cross-profile mandates.** Nothing here permits one mandate to carry two effect profiles, and the artifact bindings make it unrepresentable. Whether a principal wanting "500 calls *and* read access" should hold two mandates or a future composite binding is undecided; two mandates is the presumption.
2. **Purpose vocabularies.** `purpose_scope` is a blinded commitment to *something*; this framework does not say to what. A shared vocabulary would make purposes comparable across deployments, at the cost of shrinking the preimage space that blinding is protecting.

---

## Document History

**Revision 8 (2026-10-27).** Pins per-profile activation requirements for typed successor possession and separate scheme-2 revocation namespaces scoped by settlement context, profile and artifact binding. Adds possession to the permission/action statement-role checklist and requires every permitted quota delegate leg, including partial delegation, to carry a matched typed companion. The monetary companion is not a substitute. Reuses the existing root-identifier derivation and full-identifier exclusion algorithm while requiring isolated logical roots, epochs and history and qualified profile-specific authorization with atomic ordered insertion/publication. Breaking because these prerequisites enter the profile identity; all non-financial profiles remain reserved, with no current statement, key, monetary artifact or family-file change.

**Revision 7 (2026-10-04).** Conformance integrity for the effect-profile surface. The identity projection now commits negotiation offer members as well as acceptance members. The checker enforces exact artifact field lists and known profile bindings, required negotiation/attenuation/forbidden-construction inventories, and bidirectional compatibility-vector references; conflicting-failure probes exercise the actual negotiation guard order. Adding a reserved profile is breaking because profiles are committed by `profile_set_id`. Non-financial activation also requires an upstream ZKA-owned family profile pin and consumer enforcement, which remain pending. Breaking because the identity projection changes; no profile activated and `statement_set_id` is unchanged.

**Revision 6 (2026-10-04).** Fail-closed negotiation and resolved-profile dispatch. §6 rejects every partial discriminator, confines the baseline exemption to an explicitly opted-in pinned adapter for unchanged legacy monetary envelopes, returns the resolved profile on acceptance, and requires the offer's value-leg boolean to equal the pinned statement registry's `value_moving` flag. The twelve-step procedure adds `REJECT_VALUE_LEG_MISMATCH`; the compatibility matrix and vectors cover partial discriminators and both directions of the statement/value-leg requirement. Breaking because the negotiation rules, evaluation order and reason codes changed. No profile activated, no monetary artifact or statement moved, and `statement_set_id` is unchanged.

**Revision 5 (2026-09-11).** Backend assurance and recovery. §4.6 defines the deployment-selected atomic and reconciled assurance classes, one authenticated and privacy-preserving effect-evidence contract, effect-boundary freshness checks, linearizable idempotency, crash behavior, finite reconciliation, indeterminate and integrity-failure outcomes, VXP-safe delivery semantics and profile-specific quota, permission and action dispositions. The three non-financial profiles reference `zkm:backend-assurance:v1`; the selected class remains a backend-deployment property. Conformance vectors simulate both assurance classes across all three profiles, including before/after-commit crashes, duplicates, stale authority and unknown external completion. Breaking because the backend-assurance contract and the previously omitted profile assurance pointer enter the pinned projection. No profile activated, no monetary artifact or statement moved, and `statement_set_id` is unchanged.

**Revision 4 (2026-09-11).** Conserved consumable quotas. §4.2.1 fixes a domain-separated denomination descriptor, exact u128 tick arithmetic with no rounding, the additive sibling-conservation equation, AVAILABLE/RESERVED tagged note states, SPLIT/delegation/rotation/reservation/consumption/release/retirement transitions, backend-scoped idempotency and evidence reconciliation, and the rule that cancellation, timeout or reservation expiry never refunds an effect that may have completed. The artifact binding grows from 12 to 16 fields while still reserved. `quota-01`–`quota-16` and 46 executable traces cover both race orders, descriptor and precision substitution, full and partial delegation, holder/depth/possession checks, tagged-union validity, exact mandate expiry, bounded start evidence, persisted expired reservations, cancellation, retries, safe release, completed-effect reconciliation, retirement and enforcement overclaims. Breaking because the reserved binding and pinned quota-accounting projection moved. No profile activated, no monetary artifact or statement moved, and `statement_set_id` is unchanged.

**Revision 3 (2026-09-11).** Reusable-permission and single-use-action lifecycle profiles. §§4.3–4.5 define exact request, operation, canonical-argument and audience binding; independent resource-owner acceptance; current-root permission freshness; the private unspent-nullifier proof that keeps a consumed reusable note from remaining exercisable without publishing a linkable nullifier; no-fanout management; immutable action binding; and the owner-local reservation, canonical consumption, retry, `already_completed` and `consumed_unresolved` states. Both profiles remain reserved and non-deployable until their profile-specific statements, VKs, narrowing registries and real-proof vectors land. No monetary artifact, statement, public vector or verification key moved.

**Revision 2 (2026-09-06).** Attenuation invariants and authorization provenance. §3.1 fixes the nine profile-independent narrowing invariants (`att-01`–`att-09`) that hold for every class including unspecified ones, and `att-10` makes them a floor no profile's narrowing relation may relax; each is evaluated as a known-answer vector against a reference procedure, alongside three positive cases — a well-formed partial delegation, a both-scopes narrowing, and a ROTATE at unchanged depth — without which the rejections would pass against a procedure that refuses all change. §3.2 states the sufficiency boundary: a mandate is a claim of authority, never a grant of access. The monetary surface is safe from over-issuance because custody bounds it; a non-financial effect has no custody analogue, so the enforcement point supplies the inertness instead, and a backend MUST treat a verifying proof as necessary and never sufficient (`fc-13`). Delegation cannot manufacture rights because every successor preserves `root_id` and narrows — that bounds a subtree by its issuance, and whether the issuance was legitimate is the resource owner's question, not the proof's. ZKM deliberately supplies no mechanism for it: verifying a principal's standing over a named resource would need the public resource directory `fc-11` excludes. Also adds `fc-14`. Breaking: the attenuation block enters the pinned projection. No profile activated, no monetary artifact touched, `statement_set_id` unmoved.

**Revision 1 (2026-09-06).** Initial publication of the effect-profile framework: the two-surface model and `profile_set_id` (§2); the eight shared semantic dimensions (§3); four effect classes, three of them reserved (§4); four artifact bindings with per-class commitment and nullifier domain separation (§5); the eleven-step fail-closed negotiation procedure, its reason codes and its single scoped exemption (§6); the safeguard and privacy analysis (§7); version discipline, the fourteen-row compatibility matrix and twelve forbidden constructions (§8). No change to any monetary artifact, public input, verification key, statement identifier or envelope: `zkm:effect:value-transfer:v1` designates the existing surface and `statement_set_id` does not move.
