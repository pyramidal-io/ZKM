# Decision: zero-value outputs in spend-conjoined proofs

**Status:** Decided; positive-amount enforcement is implemented in the rev-13 candidate, pending coordinated family publication.
**Date:** 2026-10-04
**Scope:** `noir/zkm_spend_conjoined`, specification §4.6 / §5, and ZKA settlement consumers.
**Decision:** Retain the fixed recipient and change output slots, including a freshly blinded zero-value change note on full-note spends. Reject `amount = 0` in the next breaking revision.
**Current surface:** Rev 12 remains unchanged. This decision does not add an assertion, alter a public vector, move a VK or registry identity, or change settlement acceptance.

## Rev-12 behavior at the decision baseline

The spend-conjoined circuit proves `amount <= zka_in_value` and computes
`change_value = zka_in_value - amount`. It reconstructs two distinct, nonzero
ZKA commitments: a recipient note carrying `amount` and a change note carrying
`change_value`. A nonzero commitment does not imply a positive note value.

Two existing positive tests pin the boundary behavior:

- `test_spend_zero_amount`: the mandate and input value are refreshed under
  fresh randomness; cap is unchanged and a zero-value recipient note is created.
- `test_full_note_spend_change_zero`: the recipient receives the full input
  value and a zero-value change note is created.

The reference settlement adapter forwards both commitments to the target in the
same atomic operation as both nullifiers and the mandate successor. A conforming
settlement target must insert both leaves, even when one privately opens to zero.
This is a target obligation, not evidence of an upstream deployment. These leaves
carry no monetary value; their cost is note-tree growth and the work of constructing
and recording them. They are not a loss of funds. Tree capacity and storage
costs depend on the settlement target.

The original review's claim that no native ZKA circuit can consume such a note
was too broad. At ZKA commit `5dda0bb8835c9d6facdbd6e138f61d2b86510b8a`:

| Circuit | Zero-value behavior |
|---|---|
| `zka_transfer` and `zka_transfer_binding` | Reject a zero-valued input. |
| `zka_pay_transition` | Reject every active zero-valued input. |
| `zka_pay_withdrawal` | Requires a positive withdrawal amount. |
| `zka_transfer_multi` | Allows a zero-valued active slot alongside a positive slot, but per-slot conservation recreates a zero-valued output. |

Thus a batch transfer can nullify a zero note, but that path does not eliminate
the zero-valued output or reclaim the append-only tree leaf. The relevant
limitation is economically inert dust, not a universal inability to produce a
proof involving the note.

## Retain the change output

`amount` and `zka_in_value` are private witnesses. Today, both a partial spend
and a full-note spend publish the same two opaque ZKA output slots. The
[amount-privacy decision](zkm_amount_commitment_decision.md) explains why
internal settlement exposes commitments instead of cleartext values.

An absent-change sentinel would disclose `change_value = 0`, hence
`amount = zka_in_value`, on the public record. It would not reveal either scalar
by itself, but it would add a full-note-spend correlation signal. Keeping the
freshly blinded change note preserves the current fixed output shape at the
cost of one dust leaf for each full-note spend.

Consumers of the current statement still apply both ZKA output effects. A
consumer cannot infer a note's value from its commitment, omit a change leaf
because a wallet reports zero change, or reinterpret a zero-valued note as an
absent slot. The zero sentinel for an unused **mandate** successor does not
define an absent **ZKA** change output.

The sentinel alternative is declined for this revision. A later proposal
would need to price the additional public signal and coordinate the circuit,
statement registry, settlement interface, and downstream consumers.

## Rev-13 candidate enforcement

A zero-amount spend moves no value to the counterparty and consumes no cap.
Refreshing notes in this way is not a payment, and zero amounts do not acquire
non-financial effect semantics. Those require a separate typed profile surface,
as stated in [the specification's non-goals](zkm_specification.md#13-non-goals).

The rev-13 candidate requires `amount > 0`
inside the spend-conjoined circuit. The existing upper bounds then also imply
that the consumed value note is positive. Full-note spends remain valid:
`amount = zka_in_value > 0` still emits a freshly blinded zero-value change note.
Amount privacy, positive-spend cap conservation, and the two ZKA output slots
are retained.

This is a new circuit rule under the successor VK; it does not change the
meaning of proofs under the rev-12 VK. Adding it moves the spend-conjoined VK even
if its 14-element public vector stays the same. It must be batched with the
other planned breaking changes rather than introduced through an isolated
golden re-bless.

Before that coordinated cutover, its implementing change must:

1. Replace `test_spend_zero_amount` with a negative that fails specifically on
   the positive-amount constraint; retain positive partial and full-note spends.
2. Cover the positive lower boundary (`amount = 1`) and the zero-input/zero-amount
   case, and prove and verify the supported positive shapes with real proofs.
3. Reproduce ABI, bytecode, VK, generated EVM verifier, and real-proof fixtures;
   update the statement registry and its breaking revision history together.
4. Verify settlement integration and ZKA profile interoperability: a positive
   full-note spend still applies both output effects atomically, and consumers
   reject an old VK as evidence of the new positive-amount rule after cutover.
5. Coordinate the ZKA-owned family snapshot and downstream VK acceptance using
   [the consumer cutover discipline](zkm_v1_to_v2_cutover.md). No consumer may
   treat an old accepted key as enforcing the new positive-amount rule.

## Provenance

This records the owner decision following the 2026-10-03 circuit review.
ZKM behavior was checked at Forgejo main
`e83ec2476b1ba4215e78a075e8b2a7d2550c7ea0`; the ZKA qualification above uses
the review's immutable source pin. The owner approved retaining zero-change
dust and scheduling zero-amount rejection on 2026-10-04. Circuit enforcement is implemented in the successor candidate; family
publication and consumer acceptance remain pending.

Deferred enforcement is tracked separately from this decision record. Recording
the decision does not complete circuit implementation or consumer activation.
