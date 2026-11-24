// ZKM mandate transition circuit — spec §4.3 statement in the §5 MANDATE-ONLY
// proof form.
//
// Accepted kinds: SPLIT, RETIRE, DELEGATE_FULL, DELEGATE_PARTIAL, ROTATE —
// exactly the set §5 names as the mandate-only form. SPEND is REJECTED here;
// it lives in `zkm_spend_conjoined`, the §5 spend-conjoined form.
//
// WHY TWO PACKAGES RATHER THAN ONE. Not privacy: §5 requires `kind` to be a
// public input of BOTH proof forms, so the transition shape is disclosed either
// way and a single circuit would hide nothing. The split is a DEPLOYMENT-SAFETY
// property. §5's mandate-only form carries NO ZKA VALUE LEG — no value-note
// root, no ZKA nullifier, no output commitments, and no `asset_id` — and this
// circuit's public vector matches that layout exactly. A verification key whose
// vector cannot NAME a value note, and that rejects kind 0, is STRUCTURALLY
// INCAPABLE of authorizing value movement: a settlement layer cannot be tricked
// (or misconfigured) into settling a spend against a mandate-only proof,
// because there is no note to nullify and no output commitment to insert. One
// circuit carrying both forms would put that safety property behind a soft
// in-circuit branch instead of behind the verification key.
//
// The discriminator is the VALUE LEG, not the absence of an `amount` public
// input — `amount` is private in the spend-conjoined form too, so neither
// vector carries one. Anyone re-deriving this property should check for the
// ZKA leg, not for an amount.
//
// It proves the §4.3 transition statement ALONE: conservation of authority,
// bound checks, monotone narrowing, membership + nullification,
// non-revocation, and temporal validity. It carries NO ZKA component.
//
// POLICY ENFORCEMENT ON THIS VK — ENFORCED. What this circuit enforces today:
//   - THE DELEGATION GATE (rev 5). On DELEGATE_FULL / DELEGATE_PARTIAL the
//     policy is opened against the mandate's committed `policy_hash` and §6's
//     "subject to the mandate policy permitting delegation" is asserted:
//     Standard Policy v1 is permit-all by documented normative semantic, v2
//     asserts `depth(successor) <= depth_limit`. The policy witnesses are
//     pinned to zero on every other kind.
//   - §4.3-3 POLICY NARROWING (rev 6, `assert_policy_narrows`). A live
//     successor whose committed policy hash differs from the input's opens
//     both policies and proves the registry relation; a preserving successor
//     pins its opening witnesses to zero.
// SPEND-PERMISSION is not enforced here and never will be: this circuit
// REJECTS kind 0. The spend policy predicate lives on the spend-conjoined VK,
// which deliberately enforces strict policy PRESERVATION rather than narrowing
// — narrowing accompanies authority distribution, never spending (§5).
//
// ONE NULLIFIER SET ACROSS ALL ZKM VERIFICATION KEYS. `nf` is a function of
// the consumed note and settlement_context only — it binds neither `kind` nor
// this VK. The same note therefore yields the SAME `nf` under this circuit and
// under `zkm_spend_conjoined` (and any future ZKM proof form). A
// settlement layer MUST maintain a SINGLE mandate nullifier set per
// settlement_context, shared across every ZKM verification key it accepts;
// per-VK nullifier sets would let one note be consumed once per VK.
//
// SETTLEMENT PRECONDITION. Before serializing this transition's `nf`, the
// settlement layer MUST reject it unless `mandate_root` is a recent root in the
// target's OWN mandate state-tree root history (a recent-root window), and MUST
// recognize `revocation_root` in its own accumulator-root history and DERIVE
// the epoch from that history for the §7.2 staleness window — the root, not any
// prover-supplied label, states the epoch (there is no `revocation_epoch`
// public input; it was removed as a free lie-vector). A `mandate_root` the
// layer cannot place in its history proves membership against a tree that is not
// the target's, and MUST NOT be settled.
//
// Provisional surface, singular, and flagged at its definition in `zkm_lib`:
// `DEPTH_MAX` is a provisional VK-baked bound pending the §6 depth-bound
// registry.

use zkm_lib::{
    assert_policy_narrows, assert_policy_opens, assert_policy_permits_delegation, delegated_depth,
    InputWitness, KIND_DELEGATE_FULL, KIND_DELEGATE_PARTIAL, KIND_MAX, KIND_RETIRE, KIND_ROTATE,
    KIND_SPEND, KIND_SPLIT, NO_SUCCESSOR, StandardPolicyV2, successor_commitment_with_policy,
    TransitionContext, verify_input_mandate,
};

fn main(
    // ---- public inputs -------------------------------------------------
    // §5: every proof MUST bind the transition kind, the emitted mandate
    // nullifier, each successor commitment, the mandate tree root and the
    // revocation accumulator root. The INPUT commitment is deliberately absent —
    // publishing it would link successor states (§4.6).
    //
    // This vector is the §5 MANDATE-ONLY layout: it carries no ZKA value leg
    // (no note root, no ZKA nullifier, no output commitments) and no
    // `asset_id`. That absence is load-bearing (see the header), not an
    // omission. `amount` and `policy_hash` are absent too, but as of rev 7 and
    // rev 5 respectively neither is public in the spend form either, so
    // neither distinguishes the two vectors.
    //
    // DEDUP KEY: `nf` alone is the canonical uniqueness key a settlement layer
    // must serialize on (§4.3-4, §4.4) — NOT the public tuple, and not any
    // hash of it. The tuple is not canonical: successor randomness is the
    // prover's choice, so the same consumption of the same note can be
    // presented with different `cm_out_*`, and only `nf` is invariant across
    // those presentations.
    kind: pub u8,
    nf: pub Field,
    cm_out_1: pub Field,
    cm_out_2: pub Field,
    mandate_root: pub Field,
    // The version-2 full-id accumulator root the non-membership proof is against. It
    // carries NO prover-supplied epoch label: the verifier MUST recognize this
    // root in its own accumulator-root history, derive its epoch from that
    // history, and apply the §7.2 staleness window. See `TransitionContext`.
    revocation_root: pub Field,
    // Versioned proof statement. Only the full-identifier exclusion profile is
    // accepted; legacy low-128 exclusion roots fail closed.
    revocation_scheme: pub u8,
    // The settlement target's own clock (§4.3-6). The verifier MUST substitute
    // it; ZKM defines no clock.
    current_time: pub u64,
    // Settlement-domain binding (§5 "settlement context"). Asserted equal to
    // the mandate note's committed `settlement_domain` in `verify_input_mandate`
    // (the AUTHORITY binding that stops cross-domain cap multiplication) AND
    // folded into the nullifier preimage as replay hygiene.
    settlement_context: pub Field,
    // ---- private witnesses ---------------------------------------------
    // The input mandate opening. `holder_key` is NOT witnessed: it is derived
    // from `holder_sk` in `verify_input_mandate`, which is what binds the note
    // to its holder.
    in_root_id: Field,
    // The settlement domain the mandate was ISSUED for (§5). `verify_input_mandate`
    // asserts it equals `settlement_context`, so a mandate cannot be transitioned
    // on a domain it was not issued for.
    in_settlement_domain: Field,
    in_asset_id: Field,
    in_remaining_cap: u128,
    in_expiry: u64,
    in_policy_hash: Field,
    in_depth: u8,
    in_randomness: Field,
    holder_sk: Field,
    merkle_path_index: Field,
    merkle_siblings: [Field; 32],
    revocation_siblings: [Field; 254],
    out1_cap: u128,
    out1_expiry: u64,
    out1_randomness: Field,
    out2_cap: u128,
    out2_expiry: u64,
    out2_randomness: Field,
    // Read by both DELEGATE kinds and ROTATE. §5 requires proof of the new
    // key's possession for both DELEGATE kinds and ROTATE. This circuit
    // deliberately does NOT carry it — witnessing `delegate_sk` here would
    // put the delegate's secret inside the DELEGATOR's witness, the exact
    // key-sharing collapse §6 forbids. The statement lives in the COMPANION
    // circuit `zkm_delegate_possession` (§5): a settlement layer MUST NOT
    // accept either DELEGATE kind or ROTATE under this VK without a companion proof whose
    // public vector matches this transition's (cm_out_1, nf,
    // settlement_context).
    delegate_holder_key: Field,
    // ---- private: input policy opening (delegation or narrowing) ----------
    // §6 makes both DELEGATE forms "subject to the mandate policy permitting
    // delegation"; these witnesses open the mandate's committed `policy_hash`
    // so that permission is PROVEN, not assumed. v1 policies permit
    // delegation (documented semantic); v2 policies gate it by `depth_limit`.
    // SPLIT and ROTATE also use these witnesses when a successor narrows its
    // policy. When there is neither delegation nor narrowing, all six MUST be
    // zero; an unused witness is malleable surface.
    policy_version: Field,
    policy_max_per_spend: u128,
    policy_recipient_restricted: Field,
    policy_recipient_set_root: Field,
    policy_depth_limit: u8,
    policy_blinding: Field,
    // ---- private: successor policy hashes + openings (§4.3-3 narrowing) ---
    // Each LIVE successor commits to `out<i>_policy_hash`. Equal to
    // `in_policy_hash` = preservation (opening witnesses pinned to zero);
    // different = §5 registry-v1 NARROWING, in which case both the input
    // policy and the successor policy are opened and the relation is
    // asserted (`assert_policy_narrows`). Absent successors carry zero.
    out1_policy_hash: Field,
    out2_policy_hash: Field,
    out1_policy_version: Field,
    out1_policy_max_per_spend: u128,
    out1_policy_recipient_restricted: Field,
    out1_policy_recipient_set_root: Field,
    out1_policy_depth_limit: u8,
    out1_policy_blinding: Field,
    out2_policy_version: Field,
    out2_policy_max_per_spend: u128,
    out2_policy_recipient_restricted: Field,
    out2_policy_recipient_set_root: Field,
    out2_policy_depth_limit: u8,
    out2_policy_blinding: Field,
) {
    // -- Admissible kinds: 1..=5, the §5 mandate-only set -------------------
    assert(kind != KIND_SPEND, "SPEND requires the spend-conjoined proof form (§5)");
    assert(kind <= KIND_MAX, "unknown transition kind");

    // -- Input side (§3, §4.3-4/5/6), shared with the spend-conjoined VK ----
    let ctx = TransitionContext {
        mandate_root,
        revocation_root,
        revocation_scheme,
        current_time,
        settlement_context,
    };
    let (input, cm_in) = verify_input_mandate(
        ctx,
        InputWitness {
            root_id: in_root_id,
            settlement_domain: in_settlement_domain,
            asset_id: in_asset_id,
            remaining_cap: in_remaining_cap,
            expiry: in_expiry,
            policy_hash: in_policy_hash,
            depth: in_depth,
            randomness: in_randomness,
            holder_sk,
            merkle_path_index,
            merkle_siblings,
            revocation_siblings,
        },
        nf,
    );
    let holder_key = input.holder_key;

    // -- Per-kind conservation (§4.3-1), bounds (§4.3-2) and shape ---------
    //
    // Every branch is assertion-bearing. beta.25's dead-code elimination will
    // drop any intermediate that no constraint reads, so nothing here is
    // computed "for its own sake": each successor commitment is compared to a
    // public input, and each cap relation is asserted, not merely evaluated.
    //
    // Successors are BUILT from the input's root_id / asset_id / policy_hash
    // (see `zkm_lib::successor_commitment`), so §4.3-3's preservation of those
    // fields holds by construction and cannot be violated by a witness.

    if kind == KIND_SPLIT {
        // Two successors, same holder and depth; authority is neither created
        // nor destroyed. SPLIT is the concurrency primitive (§4.5).
        assert(
            out1_cap + out2_cap == in_remaining_cap,
            "SPLIT successor caps must sum to the remaining cap",
        );
        assert_two_live_successors(cm_out_1, cm_out_2);
        assert(
            successor_commitment_with_policy(
                input,
                cm_in,
                out1_cap,
                out1_expiry,
                holder_key,
                in_depth,
                out1_randomness,
                out1_policy_hash,
            )
                == cm_out_1,
            "successor 1 commitment mismatch",
        );
        assert(
            successor_commitment_with_policy(
                input,
                cm_in,
                out2_cap,
                out2_expiry,
                holder_key,
                in_depth,
                out2_randomness,
                out2_policy_hash,
            )
                == cm_out_2,
            "successor 2 commitment mismatch",
        );
    }

    if kind == KIND_RETIRE {
        // No successors: `retired_amount = remaining_cap(input)`. Authority is
        // destroyed, never spent (§4.3-1).
        assert(cm_out_1 == NO_SUCCESSOR, "RETIRE must have no first successor");
        assert(cm_out_2 == NO_SUCCESSOR, "RETIRE must have no second successor");
    }

    if kind == KIND_DELEGATE_FULL {
        // §6 full rebind: one successor at the delegate's key, delegator
        // retains nothing.
        assert(
            out1_cap == in_remaining_cap,
            "DELEGATE_FULL successor cap must equal the remaining cap",
        );
        assert_rebinds_to_a_new_holder(delegate_holder_key, holder_key);
        assert(cm_out_1 != NO_SUCCESSOR, "successor 1 commitment must be non-zero");
        assert(cm_out_2 == NO_SUCCESSOR, "DELEGATE_FULL must have no second successor");
        let out_depth = delegated_depth(in_depth);
        assert_policy_permits_delegation(
            StandardPolicyV2 {
                version: policy_version,
                max_per_spend: policy_max_per_spend,
                recipient_restricted: policy_recipient_restricted,
                recipient_set_root: policy_recipient_set_root,
                depth_limit: policy_depth_limit,
                policy_blinding,
            },
            in_policy_hash,
            out_depth,
        );
        assert(
            successor_commitment_with_policy(
                input,
                cm_in,
                out1_cap,
                out1_expiry,
                delegate_holder_key,
                out_depth,
                out1_randomness,
                out1_policy_hash,
            )
                == cm_out_1,
            "successor 1 commitment mismatch",
        );
    }

    if kind == KIND_DELEGATE_PARTIAL {
        // §6 partial delegation: a SPLIT in which EXACTLY ONE successor is
        // rebound to the delegate with depth+1; the other retains the
        // delegator's key at the unchanged depth.
        assert(
            out1_cap + out2_cap == in_remaining_cap,
            "DELEGATE_PARTIAL successor caps must sum to the remaining cap",
        );
        assert_rebinds_to_a_new_holder(delegate_holder_key, holder_key);
        assert_two_live_successors(cm_out_1, cm_out_2);
        let out_depth = delegated_depth(in_depth);
        assert_policy_permits_delegation(
            StandardPolicyV2 {
                version: policy_version,
                max_per_spend: policy_max_per_spend,
                recipient_restricted: policy_recipient_restricted,
                recipient_set_root: policy_recipient_set_root,
                depth_limit: policy_depth_limit,
                policy_blinding,
            },
            in_policy_hash,
            out_depth,
        );
        assert(
            successor_commitment_with_policy(
                input,
                cm_in,
                out1_cap,
                out1_expiry,
                delegate_holder_key,
                out_depth,
                out1_randomness,
                out1_policy_hash,
            )
                == cm_out_1,
            "successor 1 commitment mismatch",
        );
        assert(
            successor_commitment_with_policy(
                input,
                cm_in,
                out2_cap,
                out2_expiry,
                holder_key,
                in_depth,
                out2_randomness,
                out2_policy_hash,
            )
                == cm_out_2,
            "successor 2 commitment mismatch",
        );
    }

    if kind == KIND_ROTATE {
        // §6 handoff: one successor, full cap, NEW key, SAME depth. Rotation
        // spends no depth budget and does not consult the policy's delegation
        // gate. BE CLEAR ABOUT WHAT THIS IS: same-holder-ness is not provable
        // in-circuit (a key is the only notion of identity, and rotation's
        // point is changing it), so cryptographically ROTATE is an
        // UNRESTRICTED clean handoff of the whole note — §6 states this
        // openly and prices it against the alternative (a holder denied
        // rotation shares its key instead, which transfers the mandate AND
        // retains access — strictly worse). The §5 companion possession
        // proof is REQUIRED for it at settlement.
        assert(out1_cap == in_remaining_cap, "ROTATE successor cap must equal the remaining cap");
        assert_rebinds_to_a_new_holder(delegate_holder_key, holder_key);
        assert(cm_out_1 != NO_SUCCESSOR, "successor 1 commitment must be non-zero");
        assert(cm_out_2 == NO_SUCCESSOR, "ROTATE must have no second successor");
        assert(
            successor_commitment_with_policy(
                input,
                cm_in,
                out1_cap,
                out1_expiry,
                delegate_holder_key,
                in_depth,
                out1_randomness,
                out1_policy_hash,
            )
                == cm_out_1,
            "successor 1 commitment mismatch",
        );
    }

    // -- §4.3-3 narrowing (per successor) -----------------------------------
    // A live successor's policy hash is either the input's (preservation) or
    // a §5 registry-v1 narrowing of it, proven by opening both policies.
    let succ1_live = (kind == KIND_SPLIT)
        | (kind == KIND_DELEGATE_FULL)
        | (kind == KIND_DELEGATE_PARTIAL)
        | (kind == KIND_ROTATE);
    let succ2_live = (kind == KIND_SPLIT) | (kind == KIND_DELEGATE_PARTIAL);
    if succ1_live {
        assert(out1_policy_hash != 0, "live successor 1 must carry a policy hash");
    } else {
        assert(out1_policy_hash == 0, "absent successor 1 must carry a zero policy hash");
    }
    if succ2_live {
        assert(out2_policy_hash != 0, "live successor 2 must carry a policy hash");
    } else {
        assert(out2_policy_hash == 0, "absent successor 2 must carry a zero policy hash");
    }
    let narrow1 = succ1_live & (out1_policy_hash != in_policy_hash);
    let narrow2 = succ2_live & (out2_policy_hash != in_policy_hash);
    let in_carrier = StandardPolicyV2 {
        version: policy_version,
        max_per_spend: policy_max_per_spend,
        recipient_restricted: policy_recipient_restricted,
        recipient_set_root: policy_recipient_set_root,
        depth_limit: policy_depth_limit,
        policy_blinding,
    };
    if narrow1 | narrow2 {
        assert_policy_opens(in_carrier, in_policy_hash);
    }
    if narrow1 {
        let to1 = StandardPolicyV2 {
            version: out1_policy_version,
            max_per_spend: out1_policy_max_per_spend,
            recipient_restricted: out1_policy_recipient_restricted,
            recipient_set_root: out1_policy_recipient_set_root,
            depth_limit: out1_policy_depth_limit,
            policy_blinding: out1_policy_blinding,
        };
        assert_policy_opens(to1, out1_policy_hash);
        assert_policy_narrows(in_carrier, to1);
    } else {
        assert(
            out1_policy_version == 0,
            "non-narrowing successor 1 must carry a zero policy opening",
        );
        assert(
            out1_policy_max_per_spend == 0,
            "non-narrowing successor 1 must carry a zero policy opening",
        );
        assert(
            out1_policy_recipient_restricted == 0,
            "non-narrowing successor 1 must carry a zero policy opening",
        );
        assert(
            out1_policy_recipient_set_root == 0,
            "non-narrowing successor 1 must carry a zero policy opening",
        );
        assert(
            out1_policy_depth_limit == 0,
            "non-narrowing successor 1 must carry a zero policy opening",
        );
        assert(
            out1_policy_blinding == 0,
            "non-narrowing successor 1 must carry a zero policy opening",
        );
    }
    if narrow2 {
        let to2 = StandardPolicyV2 {
            version: out2_policy_version,
            max_per_spend: out2_policy_max_per_spend,
            recipient_restricted: out2_policy_recipient_restricted,
            recipient_set_root: out2_policy_recipient_set_root,
            depth_limit: out2_policy_depth_limit,
            policy_blinding: out2_policy_blinding,
        };
        assert_policy_opens(to2, out2_policy_hash);
        assert_policy_narrows(in_carrier, to2);
    } else {
        assert(
            out2_policy_version == 0,
            "non-narrowing successor 2 must carry a zero policy opening",
        );
        assert(
            out2_policy_max_per_spend == 0,
            "non-narrowing successor 2 must carry a zero policy opening",
        );
        assert(
            out2_policy_recipient_restricted == 0,
            "non-narrowing successor 2 must carry a zero policy opening",
        );
        assert(
            out2_policy_recipient_set_root == 0,
            "non-narrowing successor 2 must carry a zero policy opening",
        );
        assert(
            out2_policy_depth_limit == 0,
            "non-narrowing successor 2 must carry a zero policy opening",
        );
        assert(
            out2_policy_blinding == 0,
            "non-narrowing successor 2 must carry a zero policy opening",
        );
    }

    // -- Scratch-witness denial for the policy opening ----------------------
    // The input policy opening is consulted by the DELEGATE_* kinds (the §6
    // gate) and by any narrowing successor (above). When neither applies,
    // the six witnesses MUST be canonical zero: they feed no constraint,
    // and the house rule (see assert_policy_permits_spend's allowlist
    // discipline in zkm_lib) is that a witness that means nothing must be
    // pinned, not left malleable.
    // Delegation and policy narrowing both consume the policy opening.
    let is_delegate = (kind == KIND_DELEGATE_FULL) | (kind == KIND_DELEGATE_PARTIAL);
    if !(is_delegate | narrow1 | narrow2) {
        assert(
            policy_version == 0,
            "transitions without delegation or narrowing must carry a zero policy_version",
        );
        assert(
            policy_max_per_spend == 0,
            "transitions without delegation or narrowing must carry a zero policy_max_per_spend",
        );
        assert(
            policy_recipient_restricted == 0,
            "transitions without delegation or narrowing must carry a zero policy_recipient_restricted",
        );
        assert(
            policy_recipient_set_root == 0,
            "transitions without delegation or narrowing must carry a zero policy_recipient_set_root",
        );
        assert(
            policy_depth_limit == 0,
            "transitions without delegation or narrowing must carry a zero policy_depth_limit",
        );
        assert(
            policy_blinding == 0,
            "transitions without delegation or narrowing must carry a zero policy_blinding",
        );
    }
}

/// Shape guard for the two-successor kinds (SPLIT, DELEGATE_PARTIAL).
///
/// The non-zero checks turn `NO_SUCCESSOR`'s probabilistic argument ("a
/// Poseidon2 image is never 0") into a constraint, so the sentinel cannot be
/// smuggled into a live slot.
///
/// DISTINCTNESS IS NOT REDUNDANT. Both commitments are checked against
/// independently reconstructed successors below, but those reconstructions
/// differ only in cap and randomness — so a prover choosing equal caps and the
/// SAME randomness for both sides produces `cm_out_1 == cm_out_2`, and both
/// equality checks pass. The settlement layer then inserts one commitment
/// (it is one value), and a 50/50 split silently collapses to a single
/// spendable note: half the authority is destroyed. Conservation (§4.3-1) is
/// satisfied on paper and violated in state.
fn assert_two_live_successors(cm_out_1: Field, cm_out_2: Field) {
    assert(cm_out_1 != NO_SUCCESSOR, "successor 1 commitment must be non-zero");
    assert(cm_out_2 != NO_SUCCESSOR, "successor 2 commitment must be non-zero");
    assert(cm_out_1 != cm_out_2, "successors must be distinct commitments");
}

/// §6 requires a DELEGATE successor's `holder_key` to be "the delegate's key".
///
/// Without this, `delegate_holder_key = holder_key` is accepted and DELEGATE
/// degenerates into a depth-consuming self-transition: the delegator keeps the
/// authority while the chain advances toward `DEPTH_MAX`. That is not a
/// delegation, and a verifier reading `kind = DELEGATE_*` would be told a
/// rebind happened when none did.
fn assert_rebinds_to_a_new_holder(delegate_holder_key: Field, holder_key: Field) {
    // Zero is reserved (same discipline as asset_id / policy_hash / root_id):
    // a real holder key is a Poseidon2 image, and a successor bound to key 0
    // is unspendable by anyone — a silent authority burn.
    assert(delegate_holder_key != 0, "delegate holder key must be non-zero");
    assert(delegate_holder_key != holder_key, "delegation must rebind to a different holder key");
}

// =============================================================================
// Tests
//
// Fixtures build a single-leaf mandate state tree (the note at index 0, empty
// siblings) and an all-empty revocation accumulator, then drive `main`
// directly. `Transition` mirrors `main`'s parameter list so a test can state
// only the fields it cares about and mutate one thing at a time; every
// negative test therefore differs from a PASSING transition in exactly the
// property it is probing.
// =============================================================================

use zkm_lib::{
    compute_mandate_commitment, compute_mandate_nullifier, compute_mandate_root_id,
    compute_merkle_root, compute_policy_hash, compute_policy_hash_v2, compute_revocation_root,
    DEPTH_MAX, derive_holder_key, derive_holder_nullifier_secret, empty_merkle_siblings,
    empty_revocation_siblings, MandateNote, POLICY_VERSION_V1, POLICY_VERSION_V2,
    REVOCATION_ACCUMULATOR_FULL_ID_SPARSE_V2, StandardPolicyV1,
};

global HOLDER_SK: Field = 4242;
global DELEGATE_SK: Field = 7373;
global THIRD_PARTY_SK: Field = 8484;
global PRINCIPAL_ISSUANCE_KEY: Field = 991;
global ISSUANCE_RANDOMNESS: Field = 13;
global ASSET_ID: Field = 7;
global POLICY_HASH: Field = 33;
global IN_RANDOMNESS: Field = 555;
global OUT1_RANDOMNESS: Field = 6001;
global OUT2_RANDOMNESS: Field = 6002;
global CAP: u128 = 1000;
global EXPIRY: u64 = 2000;
global CURRENT_TIME: u64 = 1000;

/// Fixture settlement context. Deliberately the same value zkm_lib's KATs use,
/// so this package's nullifier golden and zkm_lib's are the same number and
/// cross-check each other. A deployment derives this the way zka_lib derives
/// its spend context (epoch / chain_id / application_id).
global SETTLEMENT_CONTEXT: Field = 0x5e77_1e3c;

struct Transition {
    kind: u8,
    nf: Field,
    cm_out_1: Field,
    cm_out_2: Field,
    mandate_root: Field,
    revocation_root: Field,
    revocation_scheme: u8,
    current_time: u64,
    settlement_context: Field,
    in_root_id: Field,
    in_settlement_domain: Field,
    in_asset_id: Field,
    in_remaining_cap: u128,
    in_expiry: u64,
    in_policy_hash: Field,
    in_depth: u8,
    in_randomness: Field,
    holder_sk: Field,
    merkle_path_index: Field,
    merkle_siblings: [Field; 32],
    revocation_siblings: [Field; 254],
    out1_cap: u128,
    out1_expiry: u64,
    out1_randomness: Field,
    out2_cap: u128,
    out2_expiry: u64,
    out2_randomness: Field,
    delegate_holder_key: Field,
    policy_version: Field,
    policy_max_per_spend: u128,
    policy_recipient_restricted: Field,
    policy_recipient_set_root: Field,
    policy_depth_limit: u8,
    policy_blinding: Field,
    out1_policy_hash: Field,
    out2_policy_hash: Field,
    out1_policy: StandardPolicyV2,
    out2_policy: StandardPolicyV2,
}

impl Transition {
    fn run(self) {
        main(
            self.kind,
            self.nf,
            self.cm_out_1,
            self.cm_out_2,
            self.mandate_root,
            self.revocation_root,
            self.revocation_scheme,
            self.current_time,
            self.settlement_context,
            self.in_root_id,
            self.in_settlement_domain,
            self.in_asset_id,
            self.in_remaining_cap,
            self.in_expiry,
            self.in_policy_hash,
            self.in_depth,
            self.in_randomness,
            self.holder_sk,
            self.merkle_path_index,
            self.merkle_siblings,
            self.revocation_siblings,
            self.out1_cap,
            self.out1_expiry,
            self.out1_randomness,
            self.out2_cap,
            self.out2_expiry,
            self.out2_randomness,
            self.delegate_holder_key,
            self.policy_version,
            self.policy_max_per_spend,
            self.policy_recipient_restricted,
            self.policy_recipient_set_root,
            self.policy_depth_limit,
            self.policy_blinding,
            self.out1_policy_hash,
            self.out2_policy_hash,
            self.out1_policy.version,
            self.out1_policy.max_per_spend,
            self.out1_policy.recipient_restricted,
            self.out1_policy.recipient_set_root,
            self.out1_policy.depth_limit,
            self.out1_policy.policy_blinding,
            self.out2_policy.version,
            self.out2_policy.max_per_spend,
            self.out2_policy.recipient_restricted,
            self.out2_policy.recipient_set_root,
            self.out2_policy.depth_limit,
            self.out2_policy.policy_blinding,
        );
    }
}

/// All-zero policy carrier: the pinned value for non-narrowing successors.
fn zero_policy() -> StandardPolicyV2 {
    StandardPolicyV2 {
        version: 0,
        max_per_spend: 0,
        recipient_restricted: 0,
        recipient_set_root: 0,
        depth_limit: 0,
        policy_blinding: 0,
    }
}

fn note_with(cap: u128, expiry: u64, depth: u8, holder_sk: Field) -> MandateNote {
    MandateNote {
        root_id: compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS),
        settlement_domain: SETTLEMENT_CONTEXT,
        asset_id: ASSET_ID,
        remaining_cap: cap,
        expiry,
        policy_hash: POLICY_HASH,
        holder_key: derive_holder_key(holder_sk),
        depth,
        randomness: IN_RANDOMNESS,
    }
}

fn default_note() -> MandateNote {
    note_with(CAP, EXPIRY, 0, HOLDER_SK)
}

global POLICY_BLINDING: Field = 777;

/// A v1 policy carrier (delegation permitted by the documented v1 semantic).
fn policy_v1_carrier() -> StandardPolicyV2 {
    StandardPolicyV2 {
        version: POLICY_VERSION_V1,
        max_per_spend: CAP,
        recipient_restricted: 0,
        recipient_set_root: 0,
        depth_limit: 0,
        policy_blinding: POLICY_BLINDING,
    }
}

/// A v2 policy carrier gating delegation at `depth_limit`.
fn policy_v2_carrier(depth_limit: u8) -> StandardPolicyV2 {
    StandardPolicyV2 {
        version: POLICY_VERSION_V2,
        max_per_spend: CAP,
        recipient_restricted: 0,
        recipient_set_root: 0,
        depth_limit,
        policy_blinding: POLICY_BLINDING,
    }
}

/// Test-side version-dispatched policy hash (mirrors `assert_policy_opens`).
fn policy_hash_of(p: StandardPolicyV2) -> Field {
    if p.version == POLICY_VERSION_V1 {
        compute_policy_hash(
            StandardPolicyV1 {
                version: p.version,
                max_per_spend: p.max_per_spend,
                recipient_restricted: p.recipient_restricted,
                recipient_set_root: p.recipient_set_root,
                policy_blinding: p.policy_blinding,
            },
        )
    } else {
        compute_policy_hash_v2(p)
    }
}

/// `note`, rebuilt to commit to policy `p` (delegation tests need a REAL
/// policy opening, not the opaque `POLICY_HASH` constant).
fn with_policy(note: MandateNote, p: StandardPolicyV2) -> MandateNote {
    MandateNote {
        root_id: note.root_id,
        settlement_domain: note.settlement_domain,
        asset_id: note.asset_id,
        remaining_cap: note.remaining_cap,
        expiry: note.expiry,
        policy_hash: policy_hash_of(p),
        holder_key: note.holder_key,
        depth: note.depth,
        randomness: note.randomness,
    }
}

/// Copy a policy carrier's fields into the transition's policy witnesses.
fn set_policy_witnesses(t: Transition, p: StandardPolicyV2) -> Transition {
    let mut t = t;
    t.policy_version = p.version;
    t.policy_max_per_spend = p.max_per_spend;
    t.policy_recipient_restricted = p.recipient_restricted;
    t.policy_recipient_set_root = p.recipient_set_root;
    t.policy_depth_limit = p.depth_limit;
    t.policy_blinding = p.policy_blinding;
    t
}

/// A transition over `note`, valid in everything except the per-kind
/// successor fields, which each test fills in. Unused successor slots are left
/// at the zero sentinel with expiry 0 (which trivially satisfies the
/// narrowing bound), so an untaken kind branch can never be the reason a test
/// fails.
fn transition_for(note: MandateNote, kind: u8) -> Transition {
    let merkle_siblings = empty_merkle_siblings();
    let revocation_siblings = empty_revocation_siblings();
    let cm_in = compute_mandate_commitment(note);
    Transition {
        kind,
        nf: compute_mandate_nullifier(
            derive_holder_nullifier_secret(HOLDER_SK),
            cm_in,
            SETTLEMENT_CONTEXT,
        ),
        cm_out_1: 0,
        cm_out_2: 0,
        mandate_root: compute_merkle_root(cm_in, 0, merkle_siblings),
        revocation_root: compute_revocation_root(0, note.root_id, revocation_siblings),
        revocation_scheme: REVOCATION_ACCUMULATOR_FULL_ID_SPARSE_V2,
        current_time: CURRENT_TIME,
        settlement_context: SETTLEMENT_CONTEXT,
        in_root_id: note.root_id,
        in_settlement_domain: note.settlement_domain,
        in_asset_id: note.asset_id,
        in_remaining_cap: note.remaining_cap,
        in_expiry: note.expiry,
        in_policy_hash: note.policy_hash,
        in_depth: note.depth,
        in_randomness: note.randomness,
        holder_sk: HOLDER_SK,
        merkle_path_index: 0,
        merkle_siblings,
        revocation_siblings,
        out1_cap: 0,
        out1_expiry: 0,
        out1_randomness: OUT1_RANDOMNESS,
        out2_cap: 0,
        out2_expiry: 0,
        out2_randomness: OUT2_RANDOMNESS,
        delegate_holder_key: 0,
        policy_version: 0,
        policy_max_per_spend: 0,
        policy_recipient_restricted: 0,
        policy_recipient_set_root: 0,
        policy_depth_limit: 0,
        policy_blinding: 0,
        out1_policy_hash: 0,
        out2_policy_hash: 0,
        out1_policy: zero_policy(),
        out2_policy: zero_policy(),
    }
}

/// Independent (test-side) reconstruction of a successor commitment. It
/// deliberately does NOT call `zkm_lib::successor_commitment`, so the narrowing
/// assertion lives only in the circuit and a test can build an out-of-bounds
/// successor to probe it.
fn expected_successor(
    note: MandateNote,
    cap: u128,
    expiry: u64,
    holder_key: Field,
    depth: u8,
    randomness: Field,
) -> Field {
    compute_mandate_commitment(
        MandateNote {
            root_id: note.root_id,
            settlement_domain: note.settlement_domain,
            asset_id: note.asset_id,
            remaining_cap: cap,
            expiry,
            policy_hash: note.policy_hash,
            holder_key,
            depth,
            randomness,
        },
    )
}

/// Test-side commitment builder for a successor whose policy changes. Keeping
/// this separate from the circuit helper makes policy-hash binding observable.
fn expected_successor_with_policy(
    note: MandateNote,
    cap: u128,
    expiry: u64,
    holder_key: Field,
    depth: u8,
    randomness: Field,
    policy_hash: Field,
) -> Field {
    let mut successor = note;
    successor.remaining_cap = cap;
    successor.expiry = expiry;
    successor.holder_key = holder_key;
    successor.depth = depth;
    successor.randomness = randomness;
    successor.policy_hash = policy_hash;
    compute_mandate_commitment(successor)
}

/// A complete, valid SPLIT of `note` into `cap1` / `cap2`.
fn split_of(note: MandateNote, cap1: u128, cap2: u128) -> Transition {
    let mut t = transition_for(note, KIND_SPLIT);
    t.out1_policy_hash = note.policy_hash;
    t.out2_policy_hash = note.policy_hash;
    t.out1_cap = cap1;
    t.out1_expiry = note.expiry;
    t.out2_cap = cap2;
    t.out2_expiry = note.expiry;
    t.cm_out_1 = expected_successor(
        note,
        cap1,
        note.expiry,
        note.holder_key,
        note.depth,
        t.out1_randomness,
    );
    t.cm_out_2 = expected_successor(
        note,
        cap2,
        note.expiry,
        note.holder_key,
        note.depth,
        t.out2_randomness,
    );
    t
}

/// A complete, valid DELEGATE_FULL of `note` (rebuilt to commit to policy
/// `p`) to `DELEGATE_SK`'s holder key.
fn delegate_full_with_policy(note: MandateNote, p: StandardPolicyV2) -> Transition {
    let note = with_policy(note, p);
    let mut t = set_policy_witnesses(transition_for(note, KIND_DELEGATE_FULL), p);
    t.out1_policy_hash = note.policy_hash;
    t.delegate_holder_key = derive_holder_key(DELEGATE_SK);
    t.out1_cap = note.remaining_cap;
    t.out1_expiry = note.expiry;
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        t.delegate_holder_key,
        note.depth + 1,
        t.out1_randomness,
    );
    t
}

/// DELEGATE_FULL under the default v1 policy (delegation permitted).
fn delegate_full_of(note: MandateNote) -> Transition {
    delegate_full_with_policy(note, policy_v1_carrier())
}

/// A complete, valid ROTATE of `note` to `DELEGATE_SK`'s key: full cap, same
/// depth, new holder. (The rotation target reuses the DELEGATE_SK fixture —
/// the circuit constrains the key's relation to the OLD key, not whose it is.)
fn rotate_of(note: MandateNote) -> Transition {
    let mut t = transition_for(note, KIND_ROTATE);
    t.out1_policy_hash = note.policy_hash;
    t.delegate_holder_key = derive_holder_key(DELEGATE_SK);
    t.out1_cap = note.remaining_cap;
    t.out1_expiry = note.expiry;
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        t.delegate_holder_key,
        note.depth,
        t.out1_randomness,
    );
    t
}

/// A complete, valid DELEGATE_PARTIAL under policy `p`: `cap1` to the
/// delegate at depth+1, `cap2` retained by the delegator at the unchanged
/// depth.
fn delegate_partial_with_policy(
    note: MandateNote,
    cap1: u128,
    cap2: u128,
    p: StandardPolicyV2,
) -> Transition {
    let note = with_policy(note, p);
    let mut t = set_policy_witnesses(transition_for(note, KIND_DELEGATE_PARTIAL), p);
    t.out1_policy_hash = note.policy_hash;
    t.out2_policy_hash = note.policy_hash;
    t.delegate_holder_key = derive_holder_key(DELEGATE_SK);
    t.out1_cap = cap1;
    t.out1_expiry = note.expiry;
    t.out2_cap = cap2;
    t.out2_expiry = note.expiry;
    t.cm_out_1 = expected_successor(
        note,
        cap1,
        note.expiry,
        t.delegate_holder_key,
        note.depth + 1,
        t.out1_randomness,
    );
    t.cm_out_2 = expected_successor(
        note,
        cap2,
        note.expiry,
        note.holder_key,
        note.depth,
        t.out2_randomness,
    );
    t
}

/// DELEGATE_PARTIAL under the default v1 policy.
fn delegate_partial_of(note: MandateNote, cap1: u128, cap2: u128) -> Transition {
    delegate_partial_with_policy(note, cap1, cap2, policy_v1_carrier())
}

// -----------------------------------------------------------------------------
// Positive: one per admissible kind, plus the boundary and chaining cases
// -----------------------------------------------------------------------------

#[test]
fn test_split() {
    split_of(default_note(), 300, 700).run();
}

#[test]
fn test_split_with_zero_side() {
    // Degenerate but conserving: 0 + cap = cap. The two successors are still
    // distinct commitments, because their caps differ.
    split_of(default_note(), 0, CAP).run();
}

#[test]
fn test_retire() {
    transition_for(default_note(), KIND_RETIRE).run();
}

#[test]
fn test_delegate_full() {
    delegate_full_of(default_note()).run();
}

#[test]
fn test_delegate_partial() {
    delegate_partial_of(default_note(), 250, 750).run();
}

#[test]
fn test_delegate_full_under_v2_policy_within_limit() {
    // depth 0 -> successor depth 1 <= depth_limit 3.
    delegate_full_with_policy(default_note(), policy_v2_carrier(3)).run();
}

#[test]
fn test_delegate_full_at_v2_depth_limit_boundary() {
    // successor depth 1 == depth_limit 1: the bound is inclusive.
    delegate_full_with_policy(default_note(), policy_v2_carrier(1)).run();
}

#[test]
fn test_delegate_partial_under_v2_policy() {
    delegate_partial_with_policy(default_note(), 250, 750, policy_v2_carrier(2)).run();
}

#[test(should_fail_with = "delegation exceeds the policy depth limit")]
fn test_delegate_partial_under_no_delegation_policy_rejected() {
    delegate_partial_with_policy(default_note(), 250, 750, policy_v2_carrier(0)).run();
}

#[test(should_fail_with = "delegation exceeds the policy depth limit")]
fn test_delegate_partial_checks_successor_depth_not_input_depth() {
    // Input depth 1 fits the limit, while the delegated successor depth 2
    // exceeds it. Passing input depth to the policy gate would accept this.
    delegate_partial_with_policy(
        note_with(CAP, EXPIRY, 1, HOLDER_SK),
        250,
        750,
        policy_v2_carrier(1),
    )
        .run();
}

#[test(should_fail_with = "policy opening mismatch")]
fn test_delegate_partial_cannot_forge_permissive_policy_opening() {
    let mut t = delegate_partial_with_policy(default_note(), 250, 750, policy_v2_carrier(0));
    t.policy_depth_limit = 5;
    t.run();
}

#[test(should_fail_with = "successor 1 commitment mismatch")]
fn test_delegate_partial_slot1_cannot_mint_unrelated_successor() {
    let mut t = delegate_partial_of(default_note(), 250, 750);
    let mut minted = default_note();
    minted.root_id = 0xabc;
    minted.asset_id = 0x99;
    minted.remaining_cap = 1_000_000_000;
    minted.holder_key = derive_holder_key(DELEGATE_SK);
    minted.randomness = 0x5eed;
    t.cm_out_1 = compute_mandate_commitment(minted);
    t.run();
}

#[test(should_fail_with = "delegation exceeds the policy depth limit")]
fn test_delegate_beyond_v2_depth_limit_rejected() {
    // note at depth 1 -> successor depth 2 > depth_limit 1.
    delegate_full_with_policy(note_with(CAP, EXPIRY, 1, HOLDER_SK), policy_v2_carrier(1)).run();
}

#[test(should_fail_with = "delegation exceeds the policy depth limit")]
fn test_v2_zero_depth_limit_forbids_delegation() {
    // depth_limit 0: a delegated successor's depth is >= 1, so no delegation
    // can satisfy it — the per-mandate "no delegation" switch.
    delegate_full_with_policy(default_note(), policy_v2_carrier(0)).run();
}

#[test(should_fail_with = "policy opening mismatch")]
fn test_delegate_with_wrong_policy_opening_rejected() {
    // Witness a DIFFERENT policy than the one the mandate committed to.
    let mut t = delegate_full_with_policy(default_note(), policy_v1_carrier());
    t.policy_blinding = POLICY_BLINDING + 1;
    t.run();
}

#[test(should_fail_with = "unsupported policy version")]
fn test_delegate_with_unknown_policy_version_rejected() {
    let mut t = delegate_full_with_policy(default_note(), policy_v1_carrier());
    t.policy_version = 3;
    t.run();
}

#[test(should_fail_with = "v1 policy must carry a zero depth_limit witness")]
fn test_v1_delegate_with_nonzero_depth_limit_witness_rejected() {
    // depth_limit is not in the v1 preimage — an unpinned witness there would
    // be free malleable surface.
    let mut t = delegate_full_with_policy(default_note(), policy_v1_carrier());
    t.policy_depth_limit = 1;
    t.run();
}

#[test(should_fail_with = "transitions without delegation or narrowing must carry a zero policy_blinding")]
fn test_split_with_policy_scratch_witness_rejected() {
    let mut t = split_of(default_note(), 300, 700);
    t.policy_blinding = POLICY_BLINDING;
    t.run();
}

// -----------------------------------------------------------------------------
// §4.3-3 narrowing (in-circuit, registry v1)
// -----------------------------------------------------------------------------

/// A SPLIT of a v1-policy note where successor 1 NARROWS the policy (lower
/// ceiling, fresh blinding) and successor 2 preserves it.
fn narrowed_split_of(cap1: u128, cap2: u128) -> Transition {
    let from = policy_v1_carrier();
    let note = with_policy(default_note(), from);
    let mut to = policy_v1_carrier();
    to.max_per_spend = CAP / 2;
    to.policy_blinding = POLICY_BLINDING + 1;
    let mut t = set_policy_witnesses(transition_for(note, KIND_SPLIT), from);
    t.out1_policy_hash = policy_hash_of(to);
    t.out1_policy = to;
    t.out2_policy_hash = note.policy_hash;
    t.out1_cap = cap1;
    t.out1_expiry = note.expiry;
    t.out2_cap = cap2;
    t.out2_expiry = note.expiry;
    t.cm_out_1 = compute_mandate_commitment(
        MandateNote {
            root_id: note.root_id,
            settlement_domain: note.settlement_domain,
            asset_id: note.asset_id,
            remaining_cap: cap1,
            expiry: note.expiry,
            policy_hash: t.out1_policy_hash,
            holder_key: note.holder_key,
            depth: note.depth,
            randomness: t.out1_randomness,
        },
    );
    t.cm_out_2 = expected_successor(
        note,
        cap2,
        note.expiry,
        note.holder_key,
        note.depth,
        t.out2_randomness,
    );
    t
}

/// A valid slot-2 narrowing, with slot 1 preserving the input policy.
fn narrowed_split_slot2_of() -> Transition {
    let from = policy_v1_carrier();
    let note = with_policy(default_note(), from);
    let mut to = from;
    to.max_per_spend = CAP / 2;
    to.policy_blinding = POLICY_BLINDING + 2;
    let mut t = set_policy_witnesses(split_of(note, 300, 700), from);
    t.out2_policy_hash = policy_hash_of(to);
    t.out2_policy = to;
    t.cm_out_2 = expected_successor_with_policy(
        note,
        t.out2_cap,
        t.out2_expiry,
        note.holder_key,
        note.depth,
        t.out2_randomness,
        t.out2_policy_hash,
    );
    t
}

/// A valid ROTATE that narrows policy while rebinding the holder at the same
/// depth. ROTATE does not consult the delegation gate.
fn narrowed_rotate_of() -> Transition {
    let from = policy_v1_carrier();
    let note = with_policy(default_note(), from);
    let mut to = policy_v2_carrier(0);
    to.max_per_spend = CAP / 2;
    to.policy_blinding = POLICY_BLINDING + 3;
    let mut t = set_policy_witnesses(rotate_of(note), from);
    t.out1_policy_hash = policy_hash_of(to);
    t.out1_policy = to;
    t.cm_out_1 = expected_successor_with_policy(
        note,
        t.out1_cap,
        t.out1_expiry,
        t.delegate_holder_key,
        note.depth,
        t.out1_randomness,
        t.out1_policy_hash,
    );
    t
}

/// Partial delegation whose retained (slot-2) successor further narrows a v2
/// depth limit. The delegated leg preserves the input policy.
fn narrowed_delegate_partial_of() -> Transition {
    let from = policy_v2_carrier(2);
    let note = with_policy(default_note(), from);
    let mut to = policy_v2_carrier(1);
    to.max_per_spend = CAP / 2;
    to.policy_blinding = POLICY_BLINDING + 4;
    let mut t = delegate_partial_with_policy(default_note(), 250, 750, from);
    t.out2_policy_hash = policy_hash_of(to);
    t.out2_policy = to;
    t.cm_out_2 = expected_successor_with_policy(
        note,
        t.out2_cap,
        t.out2_expiry,
        note.holder_key,
        note.depth,
        t.out2_randomness,
        t.out2_policy_hash,
    );
    t
}

/// The input commits to a restricted 500 ceiling, but the prover claims an
/// unrestricted, larger input policy so a wider successor appears to narrow.
/// Only binding the input opening to its commitment rules this out.
fn forged_narrowing_input(kind: u8) -> Transition {
    let mut real = policy_v1_carrier();
    real.max_per_spend = 500;
    real.recipient_restricted = 1;
    real.recipient_set_root = 0x77;
    let note = with_policy(default_note(), real);
    let mut fake_from = policy_v1_carrier();
    fake_from.max_per_spend = 2_000_000;
    fake_from.policy_blinding = POLICY_BLINDING + 5;
    let mut wide = policy_v1_carrier();
    wide.max_per_spend = 1_000_000;
    wide.policy_blinding = POLICY_BLINDING + 6;
    let mut t = if kind == KIND_SPLIT {
        split_of(note, 300, 700)
    } else {
        rotate_of(note)
    };
    t = set_policy_witnesses(t, fake_from);
    t.out1_policy_hash = policy_hash_of(wide);
    t.out1_policy = wide;
    t.cm_out_1 = expected_successor_with_policy(
        note,
        t.out1_cap,
        t.out1_expiry,
        if kind == KIND_SPLIT {
            note.holder_key
        } else {
            t.delegate_holder_key
        },
        note.depth,
        t.out1_randomness,
        t.out1_policy_hash,
    );
    t
}

/// A slot-2 successor commits to `wide`; `to2` can either be that widening
/// (to test the relation) or a decoy narrowing (to test the opening).
fn widened_split_slot2(decoy_opening: bool) -> Transition {
    let mut from = policy_v1_carrier();
    from.max_per_spend = 500;
    from.recipient_restricted = 1;
    from.recipient_set_root = 0x77;
    let note = with_policy(default_note(), from);
    let mut wide = policy_v1_carrier();
    wide.max_per_spend = 1_000_000;
    wide.policy_blinding = POLICY_BLINDING + 6;
    let mut t = set_policy_witnesses(split_of(note, 300, 700), from);
    t.out2_policy_hash = policy_hash_of(wide);
    t.out2_policy = wide;
    if decoy_opening {
        let mut decoy = from;
        decoy.max_per_spend = 400;
        decoy.policy_blinding = POLICY_BLINDING + 7;
        t.out2_policy = decoy;
    }
    t.cm_out_2 = expected_successor_with_policy(
        note,
        t.out2_cap,
        t.out2_expiry,
        note.holder_key,
        note.depth,
        t.out2_randomness,
        t.out2_policy_hash,
    );
    t
}

#[test]
fn test_split_with_narrowed_successor() {
    narrowed_split_of(300, 700).run();
}

#[test]
fn test_split_with_narrowed_slot2() {
    narrowed_split_slot2_of().run();
}

#[test]
fn test_rotate_with_narrowed_policy() {
    narrowed_rotate_of().run();
}

#[test]
fn test_delegate_partial_with_narrowed_retained_policy() {
    narrowed_delegate_partial_of().run();
}

#[test(should_fail_with = "policy opening mismatch")]
fn test_split_narrowing_rejects_forged_input_opening() {
    forged_narrowing_input(KIND_SPLIT).run();
}

#[test(should_fail_with = "policy opening mismatch")]
fn test_rotate_narrowing_rejects_forged_input_opening() {
    forged_narrowing_input(KIND_ROTATE).run();
}

#[test(should_fail_with = "policy blinding must be non-zero")]
fn test_slot2_narrowing_requires_its_predicate() {
    // A changed slot-2 hash with no opening must enter the narrow2 branch.
    let mut t = narrowed_split_slot2_of();
    t = set_policy_witnesses(t, zero_policy());
    t.out2_policy = zero_policy();
    t.run();
}

#[test(should_fail_with = "policy opening mismatch")]
fn test_slot2_narrowing_rejects_wrong_target_opening() {
    widened_split_slot2(true).run();
}

#[test(should_fail_with = "narrowing may not raise max_per_spend")]
fn test_slot2_narrowing_rejects_widening_relation() {
    widened_split_slot2(false).run();
}

#[test]
fn test_delegate_full_narrowing_v1_to_v2() {
    // Delegation that simultaneously narrows the delegate's policy to a v2
    // with a tighter delegation budget — the canonical §6 use of narrowing.
    let from = policy_v1_carrier();
    let note = with_policy(default_note(), from);
    let mut to = policy_v2_carrier(0);
    to.policy_blinding = POLICY_BLINDING + 2;
    let mut t = set_policy_witnesses(transition_for(note, KIND_DELEGATE_FULL), from);
    t.delegate_holder_key = derive_holder_key(DELEGATE_SK);
    t.out1_policy_hash = policy_hash_of(to);
    t.out1_policy = to;
    t.out1_cap = note.remaining_cap;
    t.out1_expiry = note.expiry;
    t.cm_out_1 = compute_mandate_commitment(
        MandateNote {
            root_id: note.root_id,
            settlement_domain: note.settlement_domain,
            asset_id: note.asset_id,
            remaining_cap: t.out1_cap,
            expiry: t.out1_expiry,
            policy_hash: t.out1_policy_hash,
            holder_key: t.delegate_holder_key,
            depth: note.depth + 1,
            randomness: t.out1_randomness,
        },
    );
    t.run();
}

#[test(should_fail_with = "narrowing may not raise max_per_spend")]
fn test_widening_successor_rejected() {
    let mut t = narrowed_split_of(300, 700);
    let mut wide = policy_v1_carrier();
    wide.max_per_spend = CAP * 2;
    wide.policy_blinding = POLICY_BLINDING + 1;
    t.out1_policy_hash = policy_hash_of(wide);
    t.out1_policy = wide;
    let note = with_policy(default_note(), policy_v1_carrier());
    t.cm_out_1 = compute_mandate_commitment(
        MandateNote {
            root_id: note.root_id,
            settlement_domain: note.settlement_domain,
            asset_id: note.asset_id,
            remaining_cap: t.out1_cap,
            expiry: t.out1_expiry,
            policy_hash: t.out1_policy_hash,
            holder_key: note.holder_key,
            depth: note.depth,
            randomness: t.out1_randomness,
        },
    );
    t.run();
}

#[test(should_fail_with = "policy opening mismatch")]
fn test_narrowing_with_wrong_target_opening_rejected() {
    let mut t = narrowed_split_of(300, 700);
    t.out1_policy.max_per_spend += 1;
    t.run();
}

#[test(should_fail_with = "non-narrowing successor 1 must carry a zero policy opening")]
fn test_preserving_successor_with_scratch_opening_rejected() {
    let mut t = split_of(default_note(), 300, 700);
    t.out1_policy = policy_v1_carrier();
    t.run();
}

#[test(should_fail_with = "absent successor 1 must carry a zero policy hash")]
fn test_retire_with_successor_policy_hash_rejected() {
    let mut t = transition_for(default_note(), KIND_RETIRE);
    t.out1_policy_hash = POLICY_HASH;
    t.run();
}

// -----------------------------------------------------------------------------
// ROTATE (§6 cross-holder handoff)
// -----------------------------------------------------------------------------

#[test]
fn test_rotate() {
    rotate_of(default_note()).run();
}

#[test]
fn test_rotate_at_nonzero_depth_preserves_depth() {
    rotate_of(note_with(CAP, EXPIRY, 5, HOLDER_SK)).run();
}

#[test]
fn test_rotate_at_depth_max_is_still_possible() {
    // Rotation spends no depth budget: legal even where delegation no longer is.
    rotate_of(note_with(CAP, EXPIRY, DEPTH_MAX, HOLDER_SK)).run();
}

#[test]
fn test_rotate_may_narrow_expiry() {
    let note = default_note();
    let mut t = rotate_of(note);
    t.out1_expiry = EXPIRY - 1;
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        t.delegate_holder_key,
        note.depth,
        t.out1_randomness,
    );
    t.run();
}

#[test(should_fail_with = "ROTATE successor cap must equal the remaining cap")]
fn test_rotate_cannot_change_cap() {
    let mut t = rotate_of(default_note());
    t.out1_cap = CAP - 1;
    t.run();
}

#[test(should_fail_with = "successor 1 commitment mismatch")]
fn test_rotate_cannot_increment_depth() {
    // A successor built at depth+1 is a delegation in rotation's clothing.
    let note = default_note();
    let mut t = rotate_of(note);
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        t.delegate_holder_key,
        note.depth + 1,
        t.out1_randomness,
    );
    t.run();
}

#[test(should_fail_with = "delegation must rebind to a different holder key")]
fn test_rotate_to_same_key_rejected() {
    let note = default_note();
    let mut t = rotate_of(note);
    t.delegate_holder_key = note.holder_key;
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        note.holder_key,
        note.depth,
        t.out1_randomness,
    );
    t.run();
}

#[test(should_fail_with = "ROTATE must have no second successor")]
fn test_rotate_with_second_successor_rejected() {
    let note = default_note();
    let mut t = rotate_of(note);
    t.cm_out_2 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        note.holder_key,
        note.depth,
        t.out2_randomness,
    );
    t.run();
}

#[test]
fn test_delegate_at_depth_max_boundary() {
    // in_depth = DEPTH_MAX - 1, so the successor lands exactly on DEPTH_MAX.
    delegate_full_of(note_with(CAP, EXPIRY, DEPTH_MAX - 1, HOLDER_SK)).run();
}

#[test]
fn test_delegate_partial_at_depth_max_boundary() {
    delegate_partial_of(note_with(CAP, EXPIRY, DEPTH_MAX - 1, HOLDER_SK), 250, 750).run();
}

#[test]
fn test_successor_may_narrow_expiry() {
    // §4.3-3 bounds expiry from above only; narrowing is allowed.
    let note = default_note();
    let mut t = split_of(note, 300, 700);
    t.out1_expiry = EXPIRY - 1;
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        note.holder_key,
        note.depth,
        t.out1_randomness,
    );
    t.run();
}

#[test]
fn test_split_at_max_depth_is_provable() {
    // Guards branch predication, which the multi-kind circuit depends on: the
    // DELEGATE branches compute `in_depth + 1`, which traps at 255. If that
    // check were not gated by `kind == DELEGATE_*`, a perfectly ordinary SPLIT
    // by a depth-255 holder would be unprovable. It must not be.
    split_of(note_with(CAP, EXPIRY, 255, HOLDER_SK), 300, 700).run();
}

#[test]
fn test_split_chain_two_steps() {
    // SPLIT, then SPLIT one of the successors. The state tree is re-rooted
    // around that successor as the single leaf (index 0), which is what the
    // settlement layer's atomic nullifier-insert + commitment-insert (§4.3-4)
    // produces for a one-note tree.
    let note = default_note();
    let step1 = split_of(note, 400, 600);
    step1.run();

    let successor = MandateNote {
        root_id: note.root_id,
        settlement_domain: note.settlement_domain,
        asset_id: note.asset_id,
        remaining_cap: step1.out1_cap,
        expiry: step1.out1_expiry,
        policy_hash: note.policy_hash,
        holder_key: note.holder_key,
        depth: note.depth,
        randomness: step1.out1_randomness,
    };
    // The re-rooted tree must contain exactly the commitment step 1 published.
    assert(compute_mandate_commitment(successor) == step1.cm_out_1);

    let step2 = split_of(successor, 150, 250);
    step2.run();
    // Authority is conserved down the chain: 1000 -> (400, 600) -> (150, 250).
    assert(step2.out1_cap + step2.out2_cap == step1.out1_cap);
    // Distinct nullifiers, so the settlement layer sees two distinct consumptions.
    assert(step1.nf != step2.nf);
}

// -----------------------------------------------------------------------------
// Negative: admissible kinds (§5 proof-form separation)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "SPEND requires the spend-conjoined proof form (§5)")]
fn test_spend_kind_rejected() {
    // The whole point of the package split: this VK has no `amount` public
    // input, so it must not admit the one kind that moves value.
    let mut t = split_of(default_note(), 300, 700);
    t.kind = KIND_SPEND;
    t.run();
}

#[test(should_fail_with = "unknown transition kind")]
fn test_unknown_kind_rejected() {
    let mut t = split_of(default_note(), 300, 700);
    t.kind = KIND_MAX + 1;
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: conservation and bounds (§4.3-1, §4.3-2)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "SPLIT successor caps must sum to the remaining cap")]
fn test_split_conservation_violation_rejected() {
    // 300 + 800 > 1000: authority created out of nothing.
    split_of(default_note(), 300, 800).run();
}

#[test(should_fail_with = "attempt to add with overflow")]
fn test_split_cap_overflow_rejected() {
    // The conservation check is an equality over a u128 SUM, so the obvious
    // attack is to make the sum wrap: pick caps whose true total exceeds 2^128
    // but whose wrapped total equals `remaining_cap`, and mint 2^128 units of
    // authority. Noir's u128 addition is CHECKED, so the wrap never happens —
    // the add traps before the equality is ever evaluated. This test pins that
    // it is the ADD that fails (and pins the exact runtime message), so a
    // future switch to wrapping arithmetic would be caught here rather than
    // silently re-opening the mint.
    let mut t = split_of(default_note(), 300, 700);
    t.out1_cap = 0xffffffffffffffffffffffffffffffff; // u128::MAX
    t.out2_cap = 1;
    t.run();
}

#[test(should_fail_with = "DELEGATE_PARTIAL successor caps must sum to the remaining cap")]
fn test_delegate_partial_conservation_violation_rejected() {
    // 250 + 800 > 1000: the delegate side is inflated at no cost to the
    // retained side.
    delegate_partial_of(default_note(), 250, 800).run();
}

#[test(should_fail_with = "DELEGATE_FULL successor cap must equal the remaining cap")]
fn test_delegate_full_cap_change_rejected() {
    // A full rebind moves the WHOLE cap; a "full" delegation that also inflates
    // it would create authority (§4.3-1).
    let note = default_note();
    let mut t = delegate_full_of(note);
    t.out1_cap = CAP + 1;
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        t.delegate_holder_key,
        note.depth + 1,
        t.out1_randomness,
    );
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: successor shape (§4.3-1 in state, not just on paper)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "successors must be distinct commitments")]
fn test_split_duplicate_successors_rejected() {
    // Equal caps AND reused randomness: both successors are literally the same
    // commitment, so the settlement layer inserts one note and half the
    // authority evaporates. Both per-successor equality checks pass — only
    // distinctness catches this.
    let note = default_note();
    let mut t = split_of(note, 500, 500);
    t.out2_randomness = t.out1_randomness;
    t.cm_out_2 = expected_successor(
        note,
        t.out2_cap,
        t.out2_expiry,
        note.holder_key,
        note.depth,
        t.out2_randomness,
    );
    t.run();
}

#[test(should_fail_with = "successors must be distinct commitments")]
fn test_delegate_partial_duplicate_successors_rejected() {
    // The same collapse via DELEGATE_PARTIAL is impossible to reach with a
    // reused randomness alone (the two sides carry different holder keys and
    // depths), so this probes the constraint directly.
    let mut t = delegate_partial_of(default_note(), 500, 500);
    t.cm_out_2 = t.cm_out_1;
    t.run();
}

#[test(should_fail_with = "successor 1 commitment must be non-zero")]
fn test_split_zero_successor_1_rejected() {
    let mut t = split_of(default_note(), 300, 700);
    t.cm_out_1 = 0;
    t.run();
}

#[test(should_fail_with = "successor 2 commitment must be non-zero")]
fn test_split_zero_successor_2_rejected() {
    let mut t = split_of(default_note(), 300, 700);
    t.cm_out_2 = 0;
    t.run();
}

#[test(should_fail_with = "successor 1 commitment must be non-zero")]
fn test_delegate_full_zero_successor_rejected() {
    let mut t = delegate_full_of(default_note());
    t.cm_out_1 = 0;
    t.run();
}

#[test(should_fail_with = "RETIRE must have no first successor")]
fn test_nonzero_cm_out_1_on_retire_rejected() {
    let mut t = transition_for(default_note(), KIND_RETIRE);
    t.cm_out_1 = 99;
    t.run();
}

#[test(should_fail_with = "RETIRE must have no second successor")]
fn test_nonzero_cm_out_2_on_retire_rejected() {
    let mut t = transition_for(default_note(), KIND_RETIRE);
    t.cm_out_2 = 99;
    t.run();
}

#[test(should_fail_with = "DELEGATE_FULL must have no second successor")]
fn test_nonzero_cm_out_2_on_delegate_full_rejected() {
    let mut t = delegate_full_of(default_note());
    t.cm_out_2 = 99;
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: monotone narrowing and inheritance (§4.3-3)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "successor expiry must not extend the input expiry")]
fn test_successor_expiry_extension_rejected() {
    let note = default_note();
    let mut t = split_of(note, 300, 700);
    t.out1_expiry = EXPIRY + 1;
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        note.holder_key,
        note.depth,
        t.out1_randomness,
    );
    t.run();
}

#[test(should_fail_with = "successor 1 commitment mismatch")]
fn test_successor_asset_substitution_rejected() {
    // asset_id is inherited by construction, so a successor under a different
    // asset simply is not the commitment the circuit builds.
    let note = default_note();
    let mut t = split_of(note, 300, 700);
    let mut forged = note;
    forged.asset_id = ASSET_ID + 1;
    t.cm_out_1 = expected_successor(
        forged,
        t.out1_cap,
        t.out1_expiry,
        note.holder_key,
        note.depth,
        t.out1_randomness,
    );
    t.run();
}

#[test(should_fail_with = "successor 2 commitment mismatch")]
fn test_split_successor_2_forged_rejected() {
    // The same forgery on the SECOND slot. Without this the suite only ever
    // exercised the successor-1 comparison, and a copy-paste bug that compared
    // slot 2 against slot 1's reconstruction would pass every other test.
    let note = default_note();
    let mut t = split_of(note, 300, 700);
    let mut forged = note;
    forged.policy_hash = POLICY_HASH + 1;
    t.cm_out_2 = expected_successor(
        forged,
        t.out2_cap,
        t.out2_expiry,
        note.holder_key,
        note.depth,
        t.out2_randomness,
    );
    t.run();
}

#[test(should_fail_with = "successor 2 commitment mismatch")]
fn test_delegate_partial_retained_side_rebind_rejected() {
    // §6: in a partial delegation EXACTLY ONE successor is rebound. Rebinding
    // the retained side too would hand the delegate everything while the public
    // shape still says "partial".
    let note = default_note();
    let mut t = delegate_partial_of(note, 250, 750);
    t.cm_out_2 = expected_successor(
        note,
        t.out2_cap,
        t.out2_expiry,
        t.delegate_holder_key,
        note.depth,
        t.out2_randomness,
    );
    t.run();
}

#[test(should_fail_with = "successor 1 commitment mismatch")]
fn test_delegate_full_must_rebind_to_delegate_key_rejected() {
    // The delegate key is a public-facing claim about WHO now holds the
    // mandate; the successor must actually be bound to it, not to some third
    // key of the prover's choosing. (Successor-1 binding is exercised on the
    // DELEGATE branch here, not only on the SPEND branch in the sibling
    // package.)
    let note = default_note();
    let mut t = delegate_full_of(note);
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        derive_holder_key(THIRD_PARTY_SK),
        note.depth + 1,
        t.out1_randomness,
    );
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: delegation rebinding and depth (§4.3-3, §6)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "delegation must rebind to a different holder key")]
fn test_delegate_full_self_delegation_rejected() {
    let note = default_note();
    let mut t = delegate_full_of(note);
    t.delegate_holder_key = note.holder_key;
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        note.holder_key,
        note.depth + 1,
        t.out1_randomness,
    );
    t.run();
}

#[test(should_fail_with = "delegation must rebind to a different holder key")]
fn test_delegate_partial_self_delegation_rejected() {
    let note = default_note();
    let mut t = delegate_partial_of(note, 250, 750);
    t.delegate_holder_key = note.holder_key;
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        note.holder_key,
        note.depth + 1,
        t.out1_randomness,
    );
    t.run();
}

#[test(should_fail_with = "delegation depth exceeds DEPTH_MAX")]
fn test_delegate_beyond_depth_max_rejected() {
    // in_depth already at DEPTH_MAX, so the successor would be DEPTH_MAX + 1.
    delegate_full_of(note_with(CAP, EXPIRY, DEPTH_MAX, HOLDER_SK)).run();
}

#[test(should_fail_with = "delegation depth exceeds DEPTH_MAX")]
fn test_delegate_partial_beyond_depth_max_rejected() {
    delegate_partial_of(note_with(CAP, EXPIRY, DEPTH_MAX, HOLDER_SK), 250, 750).run();
}

#[test(should_fail_with = "attempt to add with overflow")]
fn test_delegate_depth_u8_wrap_rejected() {
    // depth = 255: the CIRCUIT's checked u8 add must trap rather than wrap to
    // 0, which would reset the delegation chain and make the depth bound
    // meaningless (§4.3-3: "≤ 255 — no u8 wrap").
    //
    // Built BY HAND rather than through `delegate_full_of`, because that helper
    // computes `note.depth + 1` itself to build the expected successor — so it
    // would trap in the TEST before `main` was ever entered, and the test would
    // pass while proving nothing about the circuit. `cm_out_1` is therefore an
    // arbitrary non-zero value: the circuit cannot reach the commitment
    // comparison, and the assertion order (cap, rebind, non-zero, THEN depth)
    // is what this test also pins.
    let note = note_with(CAP, EXPIRY, 255, HOLDER_SK);
    let mut t = transition_for(note, KIND_DELEGATE_FULL);
    t.delegate_holder_key = derive_holder_key(DELEGATE_SK);
    t.out1_cap = note.remaining_cap;
    t.out1_expiry = note.expiry;
    t.cm_out_1 = 0x0dec0ded;
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: holder binding, membership, nullification (§3, §4.3-4)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "mandate note is not in the mandate state tree")]
fn test_wrong_holder_sk_rejected() {
    // holder_key is derived, never witnessed, so a wrong secret rebuilds a
    // different commitment and membership fails before anything else.
    let mut t = split_of(default_note(), 300, 700);
    t.holder_sk = HOLDER_SK + 1;
    t.run();
}

#[test(should_fail_with = "mandate note is not in the mandate state tree")]
fn test_wrong_mandate_root_rejected() {
    let mut t = split_of(default_note(), 300, 700);
    t.mandate_root = t.mandate_root + 1;
    t.run();
}

#[test(should_fail_with = "mandate nullifier mismatch")]
fn test_wrong_nullifier_public_input_rejected() {
    // Membership still holds; only the published nullifier is wrong. This is
    // the §4.4 serialization binding on its own.
    let mut t = split_of(default_note(), 300, 700);
    t.nf = t.nf + 1;
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: settlement-domain binding (§5 shared public inputs)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "settlement_context must be non-zero")]
fn test_zero_settlement_context_rejected() {
    let mut t = split_of(default_note(), 300, 700);
    t.settlement_context = 0;
    t.run();
}

#[test(should_fail_with = "mandate is not issued for this settlement domain")]
fn test_wrong_settlement_domain_rejected() {
    // The mandate was ISSUED for domain A (its committed `settlement_domain`,
    // and the witness honestly states it), but the transition is proven against
    // domain B. The AUTHORITY binding in `verify_input_mandate` rejects it: a
    // mandate cannot be transitioned on a domain it was not issued for. This is
    // what stops one authorization from being spent once per domain for N× the
    // cap — the nullifier folding is only replay hygiene layered on top.
    let mut t = split_of(default_note(), 300, 700);
    t.settlement_context = SETTLEMENT_CONTEXT + 1;
    t.run();
}

#[test(should_fail_with = "mandate note is not in the mandate state tree")]
fn test_cross_domain_replay_rejected() {
    // The complementary escape: a replay attacker moves to domain B AND relabels
    // the witnessed domain to B to slip past the authority assertion. But the
    // note committed in the tree carries domain A, so reconstructing it under
    // domain B yields a different commitment and membership fails. The domain is
    // bound into the COMMITMENT, so the mandate cannot be relabelled onto
    // another domain at all — either the domain assertion fires (honest witness)
    // or membership does (relabelled witness).
    let mut t = split_of(default_note(), 300, 700);
    t.settlement_context = SETTLEMENT_CONTEXT + 1;
    t.in_settlement_domain = SETTLEMENT_CONTEXT + 1;
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: reserved zero sentinels (§3 field discipline)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "mandate asset_id must be non-zero")]
fn test_zero_asset_id_rejected() {
    // A mandate minted over "asset 0" is indistinguishable from one whose asset
    // public is simply unset, which is exactly the confusion the sentinel
    // discipline exists to prevent.
    let mut note = default_note();
    note.asset_id = 0;
    split_of(note, 300, 700).run();
}

#[test(should_fail_with = "mandate policy_hash must be non-zero")]
fn test_zero_policy_hash_rejected() {
    let mut note = default_note();
    note.policy_hash = 0;
    split_of(note, 300, 700).run();
}

// -----------------------------------------------------------------------------
// Negative: revocation and temporal validity (§4.3-5, §4.3-6, §7.1)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "mandate root_id is revoked or the revocation path is invalid")]
fn test_revoked_root_id_rejected() {
    // Corrupting the full-id membership path must fail closed.
    let mut t = split_of(default_note(), 300, 700);
    t.revocation_siblings[0] = 12345;
    t.run();
}

#[test(should_fail_with = "unsupported revocation accumulator version")]
fn test_legacy_revocation_accumulator_version_rejected() {
    let mut t = split_of(default_note(), 300, 700);
    t.revocation_scheme = 1;
    t.run();
}

#[test(should_fail_with = "mandate expired")]
fn test_expired_mandate_rejected() {
    let mut t = split_of(default_note(), 300, 700);
    t.current_time = EXPIRY;
    t.run();
}

// =============================================================================
// Known-Answer Test
//
// Pins the public-input tuple of one canonical SPLIT end to end: nullifier,
// both successor commitments and the mandate state-tree root, over the fixture
// note (root_id = H(991, 13), settlement_domain 0x5e771e3c, asset 7, cap 1000,
// expiry 2000, policy 33, holder_sk 4242, randomness 555) split 300/700 with
// successor randomness 6001/6002 under settlement context 0x5e771e3c.
//
// This is a tripwire on the WHOLE §4.3 construction, not just on Poseidon2: a
// change to the commitment preimage order, a domain separator, the Merkle bit
// order, or the nullifier shape (including its settlement-context slot) moves
// these values. As with zkm_lib's KATs, do NOT re-bless by pasting a new value
// — a mismatch is a protocol break until proven otherwise. To re-capture after
// an audited change:
//   nargo test --show-output kat_
// Captured under nargo 1.0.0-beta.22 + poseidon v0.3.0.
// =============================================================================

#[test]
fn kat_split_public_inputs() {
    let t = split_of(default_note(), 300, 700);
    println(t.nf);
    println(t.cm_out_1);
    println(t.cm_out_2);
    println(t.mandate_root);
    println(t.revocation_root);
    println(t.revocation_scheme);

    // Same value as zkm_lib's kat_mandate_nullifier golden — the fixture note,
    // holder secret and settlement context are the same, so the two crates'
    // KATs cross-check each other.
    assert(
        t.nf == 0x116bfd5a40b551832ee1efb53eba914041fc22480f6c0e6623d095a847596ac1,
        "SPLIT nullifier KAT mismatch",
    );
    assert(
        t.cm_out_1 == 0x2abe1272a4b55a1bd2111e60b3a9490a57379ea80187d3639b1c0bb147ea5c17,
        "SPLIT successor 1 commitment KAT mismatch",
    );
    assert(
        t.cm_out_2 == 0x21f47c810eef024e4bd63503ba7ca7da35eb20bf848d734c1823854192984223,
        "SPLIT successor 2 commitment KAT mismatch",
    );
    assert(
        t.mandate_root == 0x2c7d0ca1d88bcd0071f0eb24173aede07c387f2e2e21f5640053982052b63237,
        "SPLIT mandate state-tree root KAT mismatch",
    );
    assert(
        t.revocation_root == 0x0ec9cf7fbcbffa41bc1b25e7569f1bbc85ee742cbe1c6c6f4c6af987b9773f55,
        "version-2 full-id exclusion accumulator root KAT mismatch",
    );
    assert(
        t.revocation_scheme == REVOCATION_ACCUMULATOR_FULL_ID_SPARSE_V2,
        "revocation accumulator version KAT mismatch",
    );

    // The pinned tuple must actually verify.
    t.run();
}

#[test(should_fail_with = "successor must differ from the consumed note")]
fn test_split_self_successor_rejected() {
    // A successor with the input's own cap, expiry, holder, depth AND
    // randomness IS the consumed note: re-inserting it would create a leaf
    // whose nullifier is already spent (permanently dead authority). The
    // shared helper rejects it before the commitment comparison runs.
    let note = default_note();
    let mut t = split_of(note, CAP, 0);
    t.out1_randomness = note.randomness;
    t.cm_out_1 = expected_successor(
        note,
        CAP,
        note.expiry,
        note.holder_key,
        note.depth,
        note.randomness,
    );
    t.run();
}

#[test(should_fail_with = "delegate holder key must be non-zero")]
fn test_delegate_full_zero_delegate_key_rejected() {
    // Zero is reserved (same discipline as asset_id / policy_hash / root_id):
    // authority bound to holder_key 0 is unspendable by anyone, so a
    // "delegation" to key 0 is a silent burn, not a rebind.
    let note = default_note();
    let mut t = delegate_full_of(note);
    t.delegate_holder_key = 0;
    t.run();
}

// =============================================================================
// Prover.toml emission — witness generation for the bb proving harness
//
// `nargo test` proves EXECUTION only (the ACVM). Some constraints bite only at
// real proof generation, so `scripts/prove-shape-classes.sh` drives a real
// `bb prove` + `bb verify` per transition SHAPE CLASS. Those proofs need a
// Prover.toml, and a ZKM witness cannot be written by hand: the sibling arrays
// are iterated Poseidon2 empty-subtree roots, and every root, commitment and
// nullifier in the vector has to be mutually consistent with them.
//
// So the witness is emitted HERE, from the very fixture helpers the test suite
// above already uses (`split_of`, `delegate_full_of`, ...). ONE SOURCE OF
// TRUTH: the transition that gets PROVED is built by the same code as the
// transition that gets TESTED, so a proof can never drift away from the
// statement the suite checks.
//
// The emitted format is deliberately quote-free `key=value` / `key[]=value`
// (a Noir f-string cannot contain an escaped `"`); `scripts/prover-toml.awk`
// turns the stream into TOML.
// =============================================================================

fn emit_prover_toml(t: Transition) {
    let kind = t.kind;
    let nf = t.nf;
    let cm_out_1 = t.cm_out_1;
    let cm_out_2 = t.cm_out_2;
    let mandate_root = t.mandate_root;
    let revocation_root = t.revocation_root;
    let revocation_scheme = t.revocation_scheme;
    let current_time = t.current_time;
    let settlement_context = t.settlement_context;
    println(f"kind={kind}");
    println(f"nf={nf}");
    println(f"cm_out_1={cm_out_1}");
    println(f"cm_out_2={cm_out_2}");
    println(f"mandate_root={mandate_root}");
    println(f"revocation_root={revocation_root}");
    println(f"revocation_scheme={revocation_scheme}");
    println(f"current_time={current_time}");
    println(f"settlement_context={settlement_context}");

    let in_root_id = t.in_root_id;
    let in_settlement_domain = t.in_settlement_domain;
    let in_asset_id = t.in_asset_id;
    let in_remaining_cap = t.in_remaining_cap;
    let in_expiry = t.in_expiry;
    let in_policy_hash = t.in_policy_hash;
    let in_depth = t.in_depth;
    let in_randomness = t.in_randomness;
    let holder_sk = t.holder_sk;
    let merkle_path_index = t.merkle_path_index;
    println(f"in_root_id={in_root_id}");
    println(f"in_settlement_domain={in_settlement_domain}");
    println(f"in_asset_id={in_asset_id}");
    println(f"in_remaining_cap={in_remaining_cap}");
    println(f"in_expiry={in_expiry}");
    println(f"in_policy_hash={in_policy_hash}");
    println(f"in_depth={in_depth}");
    println(f"in_randomness={in_randomness}");
    println(f"holder_sk={holder_sk}");
    println(f"merkle_path_index={merkle_path_index}");

    for i in 0..32 {
        let v = t.merkle_siblings[i];
        println(f"merkle_siblings[]={v}");
    }
    for i in 0..254 {
        let v = t.revocation_siblings[i];
        println(f"revocation_siblings[]={v}");
    }

    let out1_cap = t.out1_cap;
    let out1_expiry = t.out1_expiry;
    let out1_randomness = t.out1_randomness;
    let out2_cap = t.out2_cap;
    let out2_expiry = t.out2_expiry;
    let out2_randomness = t.out2_randomness;
    let delegate_holder_key = t.delegate_holder_key;
    println(f"out1_cap={out1_cap}");
    println(f"out1_expiry={out1_expiry}");
    println(f"out1_randomness={out1_randomness}");
    println(f"out2_cap={out2_cap}");
    println(f"out2_expiry={out2_expiry}");
    println(f"out2_randomness={out2_randomness}");
    println(f"delegate_holder_key={delegate_holder_key}");

    let policy_version = t.policy_version;
    let policy_max_per_spend = t.policy_max_per_spend;
    let policy_recipient_restricted = t.policy_recipient_restricted;
    let policy_recipient_set_root = t.policy_recipient_set_root;
    let policy_depth_limit = t.policy_depth_limit;
    let policy_blinding = t.policy_blinding;
    println(f"policy_version={policy_version}");
    println(f"policy_max_per_spend={policy_max_per_spend}");
    println(f"policy_recipient_restricted={policy_recipient_restricted}");
    println(f"policy_recipient_set_root={policy_recipient_set_root}");
    println(f"policy_depth_limit={policy_depth_limit}");
    println(f"policy_blinding={policy_blinding}");

    let out1_policy_hash = t.out1_policy_hash;
    let out2_policy_hash = t.out2_policy_hash;
    println(f"out1_policy_hash={out1_policy_hash}");
    println(f"out2_policy_hash={out2_policy_hash}");
    let v = t.out1_policy.version;
    println(f"out1_policy_version={v}");
    let v = t.out1_policy.max_per_spend;
    println(f"out1_policy_max_per_spend={v}");
    let v = t.out1_policy.recipient_restricted;
    println(f"out1_policy_recipient_restricted={v}");
    let v = t.out1_policy.recipient_set_root;
    println(f"out1_policy_recipient_set_root={v}");
    let v = t.out1_policy.depth_limit;
    println(f"out1_policy_depth_limit={v}");
    let v = t.out1_policy.policy_blinding;
    println(f"out1_policy_blinding={v}");
    let v = t.out2_policy.version;
    println(f"out2_policy_version={v}");
    let v = t.out2_policy.max_per_spend;
    println(f"out2_policy_max_per_spend={v}");
    let v = t.out2_policy.recipient_restricted;
    println(f"out2_policy_recipient_restricted={v}");
    let v = t.out2_policy.recipient_set_root;
    println(f"out2_policy_recipient_set_root={v}");
    let v = t.out2_policy.depth_limit;
    println(f"out2_policy_depth_limit={v}");
    let v = t.out2_policy.policy_blinding;
    println(f"out2_policy_blinding={v}");
}

#[test]
fn emit_toml_split() {
    emit_prover_toml(split_of(default_note(), 300, 700));
}

#[test]
fn emit_toml_split_at_depth_255() {
    emit_prover_toml(split_of(note_with(CAP, EXPIRY, 255, HOLDER_SK), 300, 700));
}

#[test]
fn emit_toml_retire() {
    emit_prover_toml(transition_for(default_note(), KIND_RETIRE));
}

#[test]
fn emit_toml_delegate_full() {
    emit_prover_toml(delegate_full_of(default_note()));
}

#[test]
fn emit_toml_delegate_partial() {
    emit_prover_toml(delegate_partial_of(default_note(), 250, 750));
}

#[test]
fn emit_toml_delegate_full_v2() {
    emit_prover_toml(
        delegate_full_with_policy(default_note(), policy_v2_carrier(3)),
    );
}

#[test]
fn emit_toml_rotate() {
    emit_prover_toml(rotate_of(default_note()));
}

#[test]
fn emit_toml_split_narrowed() {
    emit_prover_toml(narrowed_split_of(300, 700));
}

#[test]
fn emit_toml_split_slot2_narrowed() {
    emit_prover_toml(narrowed_split_slot2_of());
}

#[test]
fn emit_toml_rotate_narrowed() {
    emit_prover_toml(narrowed_rotate_of());
}

#[test]
fn emit_toml_delegate_partial_narrowed() {
    emit_prover_toml(narrowed_delegate_partial_of());
}

#[test]
fn test_delegate_partial_zero_retained_cap() {
    delegate_partial_of(default_note(), CAP, 0).run();
}

#[test]
fn test_delegate_partial_dust_retained_cap() {
    delegate_partial_of(default_note(), CAP - 1, 1).run();
}

#[test]
fn emit_toml_delegate_partial_zero_retained() {
    emit_prover_toml(delegate_partial_of(default_note(), CAP, 0));
}

#[test]
fn emit_toml_delegate_partial_dust_retained() {
    emit_prover_toml(delegate_partial_of(default_note(), CAP - 1, 1));
}
