# Decision: `amount` in the spend-conjoined public vector

**Status:** Decided — implemented in rev 7
**Date:** 2026-08-04
**Scope:** `noir/zkm_spend_conjoined`, spec §1.1 / §4.6 / §5 / §8
**Decision:** **Remove `amount` from the public vector entirely.** Do not replace it with an amount commitment.
**VK impact:** `zkm_spend_conjoined` re-blessed (14 → 13 public inputs). All five other VK hashes byte-identical.

---

## 1. The question

Through rev 6, `zkm_spend_conjoined` published `amount: pub u128` — the recipient-leg value, in the clear, on the settlement record. The question raised in review was whether that should become a commitment `amount_cm = H(amount, amount_blinding)`.

The prior question, which had to be answered first: **is ZKM's amount publicity merely inheriting the settlement layer's own baseline, or is it a ZKM-specific addition?** If ZKA publishes amounts natively, the concern is moot and the right outcome is a pointer in §4.6 saying so.

## 2. Finding: ZKA hides amounts. This was a ZKM-specific leak.

Every ZKA circuit's public vector was enumerated directly from source. The result is unambiguous, and the boundary/internal distinction is the whole point:

| ZKA circuit | Category | Publishes cleartext value? |
|---|---|---|
| `zka_transfer` | internal shielded | no |
| `zka_transfer_multi` | internal shielded | no |
| `zka_transfer_binding` | internal shielded | no (and it demotes `asset_commitment` to private) |
| `zka_pay_transition` | internal shielded (2-in/3-out, change + fee) | no — **not even the fee amount** |
| `zka_pay_batch` | rollup batch | no (deposit amounts are private witnesses) |
| `bridge_namada_export`, `bridge_penumbra_export` | shielded→shielded cross-chain | no |
| `zka_pay_deposit` | **boundary** (value entering the pool) | yes |
| `zka_pay_withdrawal` | **boundary** (value leaving) | yes |
| `zka_withdrawal` | **boundary** (bridge exit) | yes |

Cleartext value appears in exactly three ZKA circuits, all of them boundary crossings where a contract must move real funds — `zka_withdrawal`'s own header says so. ZKA's specification lists "note value distribution" as a residual **risk**, not a design choice.

A ZKM spend-conjoined transition is **not** a boundary crossing: both outputs are ZKA note commitments inserted into the ZKA note tree, `recipient_address` is a private ZKA address, and no value leaves the pool. Its closest ZKA analogue is `zka_pay_transition` — a strictly harder statement — which publishes nothing.

**Conclusion: publishing `amount` put ZKM below its own settlement layer's privacy baseline at an internal hop.** Not moot. Worth fixing.

Two independent reviewers were tasked with refuting this finding. Neither could; the adversarial pass additionally checked the candidates the first pass missed (`zka_root_update`'s `prev_total`/`new_total` are Merkle leaf *counts*, asserted as such in-circuit; `zka_pay_transition`'s `announcement_bundle_hash_hi/lo` are opaque hash limbs; `asset_commitment` is an unblinded function of the asset id alone and reveals type, not value) and confirmed at the contract layer that `ZKAEthPool.sol` touches its value ledger only at deposit and withdrawal.

## 3. Decision: delete the input, do not commit to it

Three options were weighed.

### Option 1 — keep public `amount` (status quo). Rejected.

It publishes a value **no consumer reads**:

- **Settlement layer.** The circuit's own settlement-obligations block enumerates a pre-condition and five state effects (insert `nf`, insert `zka_nullifier`, insert `cm_out_1`, insert `zka_cm_recipient`, insert `zka_cm_change`). Not one reads `amount`. ZKA notes are shielded; the layer inserts opaque leaves.
- **The counterparty** — the party §4.6 used to invoke to justify the disclosure ("the verifier is being paid in that asset, that amount"). A public `amount` never established *"I am being paid 50"*, because `recipient_address` is a private witness. The public scalar said only that **some** value went to **some** policy-permitted address. To actually establish payment the payee recomputes `zka_cm_recipient` from the note opening it must receive anyway in order to ever spend the note — a strictly *stronger* check, since Poseidon binding makes the opened value the unique one the proof settled.
- **The policy.** `amount ≤ max_per_spend` is proven in-circuit either way.

So the old §4.6 justification — publicity "inherent to being paid" — was simply false, and §4.6 now says so.

### Option 2 — replace with `amount_cm`. Rejected as dominated.

`zka_cm_recipient` is **already** a binding commitment to `amount`: the circuit asserts `zka_cm_recipient == compute_zka_note_commitment(asset_cm, amount, recipient_address, recipient_randomness)`, and `zkm_lib`'s two-layer construction places `value` in slot 2 of the inner hash. It is already public, already in this vector, and already hiding under a uniform `recipient_randomness` the prover obligations require.

A second commitment to the same scalar therefore buys **no hiding the first does not already provide**, while costing: a new domain tag (`zkm/amount_commitment/v1`), a fourth uniform-independent randomness in the prover-obligations block, a new zero-blinding failure mode, and a public input with no named consumer.

The one argument that could have carried it — minimal disclosure, since opening `amount_cm` would reveal only the amount whereas opening the ZKA note also reveals the recipient address and randomness — does not survive contact with a named use case. The parties who need an amount-only opening are the counterparty (who already has the full note opening, and to whom the recipient address is *their own*) and a disclosure recipient (§5), who receives openings by the envelope's design. No party was found who needs the amount and must not learn the recipient.

**A commitment with no distinguishable consumer is complexity, not privacy.**

### Option 3 — delete `amount` from the public vector. **Chosen.**

It is the only option that removes the disclosure, and it does so by deleting a line rather than adding a primitive. Its privacy rests on exactly the hiding assumption the vector already depends on — `recipient_randomness` blinding `zka_cm_recipient` — so it introduces no new cryptographic assumption, no new domain tag, no new prover-entropy obligation, and no new adversarial test class.

## 4. Range safety — measured, not assumed

The review gate on Option 3 was the DCE hazard: does moving `amount` from public to witness lose its `u128` range bound? Two measurements say no.

1. **ACIR opcode count is unchanged: 1454 before, 1454 after.** If range constraints had been contributed by public-input status, they would have vanished with it and the count would have dropped. It did not move at all. Only `public_input_count` (14 → 13), `vk_hash`, and `bytecode_sha256` changed in the golden.
2. **The type cannot be weakened even deliberately.** Rewriting the witness as `amount: Field` — the mutation that would actually remove the bound — does not compile:

   ```
   error: No matching impl found for `Field: Ord`
   error: Types in a binary operation should match, but found Field and u128
   ```

   The policy ceiling comparison `amount ≤ max_per_spend` requires `Ord`, which `Field` does not implement. The range bound is carried by the type and is structural, not incidental.

## 5. Consequences, all landed in rev 7

- **§5.** Rev 7 reduced the public vector to 13 elements. Revocation statement v2 subsequently adds the public `revocation_scheme` discriminator, so the current spend-conjoined vector is 14 elements without republishing `amount`. The mandate-only VK's deployment-safety argument was **restated**: it rests on carrying no ZKA value leg (no note root, no ZKA nullifier, no output commitments, no `asset_id`), not on carrying no `amount` — which no longer discriminates, since neither form publishes one. The same correction was applied to `check-circuit-goldens.sh` and `prove-shape-classes.sh`, whose error messages asserted the old phrasing.
- **§4.6.** Claim 1 drops `amount` from the coarse public attributes and states plainly that the counterparty still learns it from the note opening — rev 7 hides the amount from *observers*, not from the party being paid. Residual surface (a) records why the old "inherent to being paid" line was wrong. TL-IND's equal-attribute restriction no longer needs to name `amount`.
- **§5 Receipts.** The ZKA recipient-note opening is now **REQUIRED** in a spend-conjoined `zkm:receipt:v1`. This used to be redundant — the public vector carried the value — but without it a receipt can no longer discharge its own rule ("open every commitment it claims to open") for `zka_cm_recipient`, and a holder could not later demonstrate what it paid.
- **§8.** The AFP Introduction Profile §14 worked example is unaffected and now says why: the per-interaction envelope check happens inside the session, where the counterparty holds the note opening. Nothing in the composition ever needed the amount on the settlement record.
- **Not changed:** `asset_id` stays public. The verifier is being paid in that asset; asset-hiding is a different problem and is out of scope.

## 6. The one deployment question a target must answer

A settlement target that wants **ad-valorem fees** or amount-tiered compliance gating on internal ZKM spends cannot read the amount from the public vector.

This is not a regression ZKM introduced. Such a target cannot do it for native ZKA internal spends either — `zka_pay_transition` publishes neither the value nor the fee — so the capability was never available at this layer. A target needing it must charge at the pool boundary (deposit/withdrawal), where amounts are public by necessity, or define its own disclosure. Recorded here so the question is answered rather than discovered.

## 7. Provenance

Branch-A/branch-B mootness check, adversarial refutation, and the three-option comparison were run as independent analyses over the ZKA and ZKM sources; the refutation attempt failed and the option ranking put Option 3 first. Every number in §4 was measured on this machine with the pinned toolchain (nargo 1.0.0-beta.22, bb 5.0.0-nightly.20260522), not derived on paper.
