// ZKM §5 SPEND-CONJOINED AUTHORIZATION PROOF.
//
// This IS the §5 spend-conjoined proof form.
//
// THE CONJUNCTION. §5 requires the authorization proof to conjoin, over shared
// public inputs, three statements. All three are here, in ONE circuit:
//
//   1. the §4.3 SPEND mandate transition — conservation, bounds, monotone
//      narrowing, membership + nullification, non-revocation, temporal
//      validity (the machinery is `zkm_lib`'s, shared with the mandate-only
//      VK so the input-side statement cannot drift between the two);
//   2. the ZKA value-spend leg — the consumed value note is proven a member of
//      the ZKA note tree, its nullifier is emitted, and the two output notes
//      conserve its value;
//   3. the policy predicate — ZKM Standard Policy v1 or v2
//      (`zkm_lib::assert_policy_permits_spend`), evaluated on this spend, with
//      the evaluated parameters proven to hash to the mandate's committed
//      `policy_hash`.
//
// REALIZATION: SHARED-PUBLIC-INPUT COMPOSITION, NOT RECURSION. §5 permits
// either ("via shared-public-input composition or recursive aggregation into
// `zka:bundle:v1`"). Composition is chosen: the legs share `amount`,
// `asset_id`, `settlement_context` and `current_time` as the
// SAME wires, so there is no cross-proof binding to get wrong, and §5's
// atomicity requirement becomes STRUCTURAL — one proof, one verification, one
// accept/reject. Recursive aggregation remains future work for targets that
// want a `zka:bundle:v1` envelope over an existing ZKA spend proof; it buys
// prover-side modularity, not a stronger statement.
//
// HOLDER UNIFICATION — ONE SECRET, BOTH LEGS. A single `holder_sk` witness
// carries the whole proof: the mandate's `holder_key` is
// `H(DOMAIN_ZKM_HOLDER_KEY, holder_sk)`, the consumed value note's recipient
// address is `derive_zka_address(holder_sk)`, and the ZKA nullifier key IS
// `holder_sk` (ZKA's spending-key convention). An agent's mandate AUTHORITY and
// its value CUSTODY are therefore provably the same key material — a mandate
// cannot be used to authorize the movement of someone else's notes, and a note
// cannot be moved under someone else's mandate.
//
// AMOUNT SEMANTICS. `amount` is the RECIPIENT-leg value — the value leaving
// the holder — and it is simultaneously the mandate's consumed authority and
// the policy's spend argument. The consumed value note is worth
// `amount + change_value`; the change returns to the holder's own address.
//
// AMOUNT PRIVACY. `amount` is a PRIVATE witness: the settlement layer inserts
// opaque ZKA note commitments, the policy evaluates it in-circuit, and the
// recipient verifies it by opening `zka_cm_recipient`. A separate `amount_cm`
// would duplicate that existing binding commitment without adding a privacy
// boundary. See docs/zkm_amount_commitment_decision.md for the decision record.
//
// RANGE SAFETY. The `u128` bound is independent of visibility: the policy
// ceiling comparison requires `Ord`, which an unbounded `Field` does not
// implement.
//
// SETTLEMENT OBLIGATIONS (§5 atomicity). A settlement layer that verifies a
// proof against this VK MUST then apply, ATOMICALLY — all five state effects or
// none.
//
// PRE-CONDITION (checked BEFORE any of the five effects). The layer MUST reject
// the proof unless it can place every claimed recent root in its OWN history:
//
//   0. `mandate_root` is a recent root in the target's OWN mandate state-tree
//      root history AND `zka_note_root` is a recent root in ZKA's value-note
//      tree root history for this settlement target (both recent-root windows),
//      AND `revocation_root` is recognized in the target's own accumulator-root
//      history — from which the layer DERIVES the epoch for the §7.2 staleness
//      window (there is no `revocation_epoch` public input; the root states the
//      epoch, not a prover-supplied label). A membership or non-membership proof
//      against a root the layer cannot place is a proof against a tree that is
//      not the target's, and MUST NOT be settled. Only once all three roots are
//      recognized are the five effects applied:
//
//   1. check-and-insert the MANDATE nullifier `nf` into the single ZKM mandate
//      nullifier set for `settlement_context`. That set is SHARED with
//      `zkm_mandate_transition`'s VK: `nf` binds only the consumed note and the
//      settlement context, not the proof form or the verification key, so
//      per-VK sets would let one mandate note be consumed once per key (§5).
//   2. check-and-insert `zka_nullifier` into ZKA's OWN value-note nullifier set
//      for this settlement target. Two sets, two roles: mandate authority and
//      value custody are nullified independently.
//   3. insert `cm_out_1` into the mandate state tree (§4.3-4).
//   4. insert `zka_cm_recipient` into the ZKA note tree.
//   5. insert `zka_cm_change` into the ZKA note tree.
//
// A partial application is a protocol violation in either direction: authority
// consumed without value moving, or value moved without authority consumed.
// Reorg semantics for all five follow the settlement target's ZKA finality
// policy (§4.3-4); ZKM defines no finality model of its own.
//
// PROVER OBLIGATIONS (recipient non-recoverability rests on these). The ZKA
// output notes are two-layer commitments whose only secret entropy is their
// randomness — `asset_cm` is derivable from the public asset and each note's
// `value` (`amount`, or `zka_in_value - amount`) is LOW-ENTROPY even though
// rev 7 made it private (real payment amounts are round numbers in a small
// range; privacy here rests on the blinding, never on the amount being hard to
// guess), and the recipient address, though private, is drawn from a bounded
// set under a restricted policy. So `recipient_randomness`,
// `change_randomness`, `out1_randomness` and the mandate's `policy_blinding`
// MUST each be sampled UNIFORMLY and INDEPENDENTLY per proof. An SDK MUST NOT
// derive them from spend parameters (amount, recipient, asset, a counter, or a
// key): a deterministic derivation makes the commitment openable by anyone who
// can guess the derivation and re-links notes an observer should not be able to
// correlate. The circuit adds cheap partial guards below (each randomness
// non-zero, and the two output randomnesses distinct), but those catch only the
// grossest failures — uniform independent sampling is the prover's obligation,
// not something the circuit can fully enforce.
//
// SCOPE OF POLICY ENFORCEMENT. The policy conjunction implemented here covers
// SPENDING only, and that division is now deliberate rather than pending.
// §6 makes both DELEGATE forms "subject to the mandate policy permitting
// delegation"; that check lives on the mandate-only VK
// (`zkm_mandate_transition`) and is ENFORCED there in-circuit as of rev 5 —
// v1 is permit-all by documented semantic, v2 asserts
// `depth(successor) <= depth_limit`. The §4.3-3 policy-NARROWING relation is
// likewise enforced on that VK as of rev 6 (`assert_policy_narrows`). THIS
// circuit deliberately enforces strict preservation instead: narrowing
// accompanies authority distribution (SPLIT / DELEGATE / ROTATE), never
// spending.
//
// The revocation accumulator is ZKM-OWNED normative surface: a revoked-set
// EXCLUSION tree, corrected in rev 5 from the earlier framing as a stand-in
// for ZKC-Core's accumulator — ZKC's is an issuer-maintained ACTIVE-SET
// membership tree, a polarity that cannot work for hidden self-issued
// principals (§7.1). The ZKM domain separators and `zkm/policy/v1` are
// ZKM-owned defined values, not entries awaiting KDC registration (§2 tag
// ownership, settled in rev 5; see the TAG OWNERSHIP block in `zkm_lib`). The
// MIRRORED ZKA constants are ZKA's published values, cross-checked against
// ZKA's own `zka_lib` by the KATs there.

use zkm_lib::{
    assert_policy_permits_spend, compute_merkle_root, compute_zka_asset_commitment,
    compute_zka_note_commitment, compute_zka_nullifier, derive_zka_address, derive_zka_spending_key,
    InputWitness, KIND_SPEND, NO_SUCCESSOR, StandardPolicyV2, successor_commitment,
    TransitionContext, verify_input_mandate,
};

fn main(
    // ---- §5 shared public inputs ----------------------------------------
    // §5: every proof MUST bind the transition kind, the emitted mandate
    // nullifier, each successor commitment, the mandate tree root, the
    // revocation accumulator root, `current_time` and the settlement context
    // (no epoch label — see below). The INPUT commitment is deliberately absent —
    // publishing it would link successor states (§4.6). The ZKA leg follows the
    // same discipline: the consumed value note appears publicly only as its
    // nullifier.
    //
    // DEDUP KEYS: `nf` is the canonical uniqueness key for the MANDATE set and
    // `zka_nullifier` for ZKA's — never the public tuple, and never a hash of
    // it. Output randomness is the prover's choice, so one consumption of one
    // note can be presented with different `cm_out_*`; only the nullifiers are
    // invariant across those presentations.
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
    // Versioned proof statement: only the full-identifier exclusion profile
    // is accepted by this verification key.
    revocation_scheme: pub u8,
    // The settlement target's own clock (§4.3-6). The verifier MUST substitute
    // it; ZKM defines no clock.
    current_time: pub u64,
    // Settlement-domain binding (§5). Asserted equal to the mandate note's
    // committed `settlement_domain` in `verify_input_mandate` (the AUTHORITY
    // binding that stops one mandate being spent once per domain for N× the cap)
    // AND folded into the mandate nullifier preimage as replay hygiene.
    settlement_context: pub Field,
    // NOTE (rev 7): `amount` was REMOVED from this vector and is now a private
    // witness (declared below with the ZKA leg). See AMOUNT PRIVACY in the
    // header. `asset_id` stays public: the verifier is being paid in that
    // asset, and asset-hiding is out of scope.
    asset_id_pub: pub Field,
    // NOTE (rev 5): `policy_hash_pub` was REMOVED from this vector. In the
    // merged single-circuit form the policy leg opens `in_policy_hash`
    // privately, so a public copy served no verifier function — and because
    // `policy_hash` is preserved across successors (§4.3-3), publishing it
    // was a lineage-stable cross-spend correlator, a §4.6 breach the blinding
    // alone does not close.
    // ---- ZKA leg publics -------------------------------------------------
    // A recent root of the ZKA value-note tree the consumed note is proven
    // against. Distinct from `mandate_root`: authority and value live in
    // separate trees, and this circuit is what binds a movement in one to a
    // transition in the other.
    zka_note_root: pub Field,
    zka_nullifier: pub Field,
    zka_cm_recipient: pub Field,
    zka_cm_change: pub Field,
    // ---- private: mandate opening + accumulator paths --------------------
    // `holder_key` is NOT witnessed: it is derived from `holder_sk` inside
    // `verify_input_mandate`, which is what binds the note to its holder — and,
    // here, to the owner of the value note as well.
    in_root_id: Field,
    // The settlement domain the mandate was ISSUED for (§5). `verify_input_mandate`
    // asserts it equals `settlement_context`, so a mandate cannot be spent on a
    // domain it was not issued for.
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
    // ---- private: ZKA value leg ------------------------------------------
    // The value leaving the holder. Shared by all three legs: it is the
    // mandate's consumed authority, the recipient note's value, and the
    // policy's spend argument. PRIVATE as of rev 7 — see AMOUNT PRIVACY in
    // the header. Its `u128` type is what range-bounds it; that is emitted by
    // the compiler for the typed witness and is independent of visibility
    // (measured: removing `pub` moved the ACIR opcode count by 0).
    amount: u128,
    zka_in_value: u128,
    zka_in_randomness: Field,
    zka_path_index: Field,
    zka_siblings: [Field; 32],
    change_randomness: Field,
    // The counterparty's ZKA address and the recipient note's blinding. The
    // address is private: a verifier learns that SOME permitted recipient was
    // paid, not who.
    recipient_address: Field,
    recipient_randomness: Field,
    // ---- private: policy opening -----------------------------------------
    // The opening of the mandate's committed `policy_hash`. Proving these hash
    // to `in_policy_hash` is §5's "a proof against any other policy MUST NOT
    // verify".
    policy_version: Field,
    policy_max_per_spend: u128,
    policy_recipient_restricted: Field,
    policy_recipient_set_root: Field,
    // v2 delegation depth limit; MUST be zero when `policy_version` is 1 (not
    // part of the v1 preimage — `assert_policy_opens` pins it). Not consulted
    // at spend time in either version.
    policy_depth_limit: u8,
    // High-entropy blinding of the policy hash (§4.6). Without it the published
    // `policy_hash` is dictionary-invertible and a cross-spend lineage
    // identifier; `assert_policy_permits_spend` refuses a zero blinding.
    policy_blinding: Field,
    recipient_set_path_index: Field,
    recipient_set_siblings: [Field; 16],
) {
    // =========================================================================
    // Leg 1 — the §4.3 SPEND mandate transition
    // =========================================================================

    // This VK proves exactly one kind. `kind` stays a public input so the §5
    // binding is identical in both proof forms and a settlement layer parses
    // one vector shape.
    assert(kind == KIND_SPEND, "this verification key proves SPEND only");

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

    // -- SPEND conservation (§4.3-1) and bounds (§4.3-2) -------------------
    // One successor: remaining_cap decremented by a positive settled amount.
    // A zero-amount proof would refresh the mandate and value note without
    // reducing the cap or moving value. Keep the amount private while
    // rejecting that degenerate spend in the circuit.
    assert(amount > 0, "spend amount must be positive");
    // u128 subtraction would trap on underflow, but the explicit bound is
    // §4.3-2's normative `a <= remaining_cap(M)` assertion.
    assert(amount <= in_remaining_cap, "spend amount exceeds remaining cap");
    assert(
        out1_cap == in_remaining_cap - amount,
        "SPEND successor cap must equal remaining cap minus amount",
    );

    // -- Conjunction publics ----------------------------------------------
    // The ZKA and policy legs below settle against these, so they must be the
    // mandate's own asset and policy. Unlike the superseded package, binding
    // them is no longer the END of the story: `asset_id_pub` now feeds a value
    // movement. (`policy_hash_pub` is gone — see the public-input note above.)
    assert(asset_id_pub == in_asset_id, "asset_id_pub must equal the mandate asset");

    // -- Successor shape ---------------------------------------------------
    // The non-zero check turns `NO_SUCCESSOR`'s probabilistic argument ("a
    // Poseidon2 image is never 0") into a constraint, so the empty-slot
    // sentinel cannot be smuggled into the live slot: a SPEND publishing
    // `cm_out_1 = 0` would consume the note and leave no successor, which is a
    // RETIRE wearing a SPEND's public vector.
    assert(cm_out_1 != NO_SUCCESSOR, "successor 1 commitment must be non-zero");
    assert(cm_out_2 == NO_SUCCESSOR, "SPEND must have no second successor");

    // Holder and depth are PRESERVED across a spend; rebinding requires a
    // DELEGATE transition, which this VK cannot express at all. The successor
    // inherits root_id / asset_id / policy_hash by construction (§4.3-3).
    assert(
        successor_commitment(
            input,
            cm_in,
            out1_cap,
            out1_expiry,
            input.holder_key,
            in_depth,
            out1_randomness,
        )
            == cm_out_1,
        "successor 1 commitment mismatch",
    );

    // =========================================================================
    // Leg 2 — the ZKA value spend
    //
    // The same `holder_sk` that just proved mandate authority is now the ZKA
    // spending key. Nothing rebinds between the legs: `holder_address` is
    // derived from it here, and `asset_cm` comes from the MANDATE's `asset_id`
    // (not from a free witness), so the value provably moves in the mandated
    // asset. An "asset substitution" — spending a note of some other asset
    // under this mandate — cannot be witnessed: it simply is not the note this
    // circuit reconstructs, and its membership proof fails.
    // =========================================================================

    let holder_address = derive_zka_address(holder_sk);
    let asset_cm = compute_zka_asset_commitment(in_asset_id);

    // -- Consumed value note: membership + nullification -------------------
    let cm_zka_in = compute_zka_note_commitment(
        asset_cm,
        zka_in_value as Field,
        holder_address,
        zka_in_randomness,
    );
    assert(
        compute_merkle_root(cm_zka_in, zka_path_index, zka_siblings) == zka_note_root,
        "zka value note is not in the zka note tree",
    );
    assert(zka_nullifier == compute_zka_nullifier(cm_zka_in, holder_sk), "zka nullifier mismatch");

    // -- Recipient discipline ----------------------------------------------
    // Zero is the reserved "field absent" sentinel throughout this protocol
    // (§3); a note committed to address 0 is spendable by nobody, so a
    // zero-recipient spend burns the value while consuming the mandate.
    assert(recipient_address != 0, "recipient address must be non-zero");
    // Reject the degenerate LITERAL self-spend (`recipient_address ==
    // holder_address`) as a hygiene tripwire: paying the exact address the
    // change already returns to is almost always a construction bug, and a
    // verifier reading such a proof would be told value moved to a counterparty
    // when it demonstrably did not.
    //
    // WHAT THIS DOES NOT CLAIM. It is NOT a guarantee that value left the
    // holder's control. Address ownership is unproven here — a holder who
    // controls a SECOND address can pay that address and defeat the tripwire
    // entirely. The assert catches the one literal self-address case cheaply;
    // it does not establish economic non-self-dealing.
    assert(recipient_address != holder_address, "spend recipient must differ from the holder");

    // -- Output randomness hygiene (§4.6; see PROVER OBLIGATIONS) -----------
    // Cheap partial guards on the entropy that recipient non-recoverability
    // rests on. A zero randomness collapses a note commitment to a
    // deterministic function of its public/low-entropy fields (openable by
    // guessing), and equal recipient/change randomness at equal value would
    // make the two outputs coincide. These catch the grossest failures only —
    // uniform, independent sampling is the prover's obligation, not enforceable
    // in-circuit.
    assert(recipient_randomness != 0, "recipient randomness must be non-zero");
    assert(change_randomness != 0, "change randomness must be non-zero");
    assert(
        recipient_randomness != change_randomness,
        "recipient and change randomness must differ",
    );

    // -- Value conservation -------------------------------------------------
    // `zka_in_value == amount + change_value`, realized as a subtraction so
    // there is exactly one witness for the change and no second equation to
    // satisfy. The bound is asserted FIRST: u128 subtraction would trap on
    // underflow anyway, but an explicit assertion is what makes the failure
    // legible (and is the same discipline §4.3-2 requires of the cap).
    assert(amount <= zka_in_value, "spend amount exceeds the value note");
    let change_value = zka_in_value - amount;

    // -- Output shape, before reconstruction --------------------------------
    // These guards are the value-leg analogue of the mandate's successor
    // discipline, and they are NOT redundant with the commitment equalities
    // below. Both outputs are checked against independently reconstructed
    // commitments, but a settlement layer inserts VALUES: two equal outputs are
    // one leaf, so an equal-value/equal-randomness pair would silently destroy
    // one note, and an output equal to the consumed note re-inserts a leaf
    // whose nullifier is already spent — permanently unspendable value.
    assert(zka_cm_recipient != 0, "zka recipient commitment must be non-zero");
    assert(zka_cm_change != 0, "zka change commitment must be non-zero");
    assert(zka_cm_recipient != zka_cm_change, "zka output commitments must be distinct");
    assert(
        zka_cm_recipient != cm_zka_in,
        "zka recipient output must differ from the consumed note",
    );
    assert(zka_cm_change != cm_zka_in, "zka change output must differ from the consumed note");

    // -- Output notes --------------------------------------------------------
    // `amount` to the counterparty, the remainder back to the holder's own
    // address. Both are built from the mandate's `asset_cm`, so neither leg can
    // change asset mid-spend.
    assert(
        zka_cm_recipient
            == compute_zka_note_commitment(
                asset_cm,
                amount as Field,
                recipient_address,
                recipient_randomness,
            ),
        "zka recipient note commitment mismatch",
    );
    assert(
        zka_cm_change
            == compute_zka_note_commitment(
                asset_cm,
                change_value as Field,
                holder_address,
                change_randomness,
            ),
        "zka change note commitment mismatch",
    );

    // =========================================================================
    // Leg 3 — the policy predicate (§5)
    //
    // Evaluated against `in_policy_hash` — the mandate's OWN committed
    // policy, bound privately through the mandate commitment (there is no
    // public policy input as of rev 5, §5). This is what makes "a proof
    // against any other policy MUST NOT verify" true rather than
    // aspirational: the predicate's parameters are re-hashed in-circuit and
    // compared to what the principal committed at issuance.
    // =========================================================================

    assert_policy_permits_spend(
        StandardPolicyV2 {
            version: policy_version,
            max_per_spend: policy_max_per_spend,
            recipient_restricted: policy_recipient_restricted,
            recipient_set_root: policy_recipient_set_root,
            depth_limit: policy_depth_limit,
            policy_blinding,
        },
        in_policy_hash,
        amount,
        recipient_address,
        recipient_set_path_index,
        recipient_set_siblings,
    );
}

// =============================================================================
// Tests
//
// Fixtures build BOTH single-leaf trees (the mandate note and the ZKA value
// note, each at index 0 under empty siblings), an all-empty revocation
// accumulator and a valid unrestricted policy, then drive `main` directly.
//
// Two layers, deliberately:
//   * `SpendCase` describes the WORLD (mandate fields, policy, value note,
//     recipient). Changing one knob re-derives everything that depends on it —
//     a different policy is a different `policy_hash`, hence a different
//     mandate commitment, hence a different tree root and nullifier. Tests that
//     probe protocol-level properties mutate a case.
//   * `Conjoined` mirrors `main`'s parameter list, so a test can tamper with a
//     single wire of an otherwise valid proof. Tests that probe binding
//     between public inputs and witnesses mutate a built `Conjoined`.
//
// Every negative therefore differs from a PASSING proof in exactly the property
// it is probing.
// =============================================================================

use zkm_lib::{
    compute_mandate_commitment, compute_mandate_nullifier, compute_mandate_root_id,
    compute_merkle_root_16, compute_policy_hash, compute_policy_hash_v2, compute_revocation_root,
    derive_holder_key, derive_holder_nullifier_secret, empty_merkle_siblings,
    empty_recipient_set_siblings, empty_revocation_siblings, KIND_SPLIT, MandateNote,
    POLICY_VERSION_V1, POLICY_VERSION_V2, REVOCATION_ACCUMULATOR_FULL_ID_SPARSE_V2,
    StandardPolicyV1,
};

global HOLDER_SK: Field = 4242;
global OTHER_SK: Field = 7373;
/// The counterparty being paid — and, in the restricted-policy fixtures, the
/// allowlisted member.
global COUNTERPARTY_SEED: Field = 8888;

fn counterparty_address() -> Field {
    derive_zka_address(derive_zka_spending_key(COUNTERPARTY_SEED))
}

/// A second allowlist member, so the restricted-policy set is a real two-member
/// tree rather than a single leaf.
global SECOND_MEMBER_SK: Field = 9999;
global PRINCIPAL_ISSUANCE_KEY: Field = 991;
global ISSUANCE_RANDOMNESS: Field = 13;
global ASSET_ID: Field = 7;
global IN_RANDOMNESS: Field = 555;
global OUT1_RANDOMNESS: Field = 6001;
global ZKA_IN_RANDOMNESS: Field = 7001;
global CHANGE_RANDOMNESS: Field = 7002;
global RECIPIENT_RANDOMNESS: Field = 7003;
global CAP: u128 = 1000;
global MAX_PER_SPEND: u128 = 600;
global ZKA_IN_VALUE: u128 = 900;
global AMOUNT: u128 = 400;
global EXPIRY: u64 = 2000;
global CURRENT_TIME: u64 = 1000;
/// Fixture policy blinding. A deployment samples this uniformly per mandate;
/// the fixed value here only has to be stable and non-zero.
global POLICY_BLINDING: Field = 0x9e2b_77a1;

/// Fixture settlement context. Deliberately the same value zkm_lib's KATs use,
/// so this package's mandate-nullifier golden and zkm_lib's are the same number
/// and cross-check each other.
global SETTLEMENT_CONTEXT: Field = 0x5e77_1e3c;

/// The world a proof is generated in. `build` derives every commitment, root
/// and nullifier from it.
struct SpendCase {
    note_cap: u128,
    note_expiry: u64,
    note_depth: u8,
    note_randomness: Field,
    /// The settlement domain the mandate note is issued for. Equal to
    /// `SETTLEMENT_CONTEXT` for every honest case; the wrong-domain test differs.
    note_settlement_domain: Field,
    holder_sk: Field,
    /// The MANDATE's asset. The circuit derives the ZKA asset commitment from
    /// this one, for both the consumed note and the outputs.
    asset_id: Field,
    policy: StandardPolicyV2,
    recipient_set_path_index: Field,
    recipient_set_siblings: [Field; 16],
    amount: u128,
    zka_in_value: u128,
    zka_in_randomness: Field,
    /// The asset the CONSUMED value note is actually denominated in. Equal to
    /// `asset_id` for every honest case; the substitution test differs.
    zka_in_asset_id: Field,
    /// The owner of the consumed value note. Equal to `holder_sk` for every
    /// honest case; the foreign-note test differs.
    zka_owner_sk: Field,
    recipient_address: Field,
}

/// `main`'s parameter list, so a test can tamper with one wire.
struct Conjoined {
    kind: u8,
    nf: Field,
    cm_out_1: Field,
    cm_out_2: Field,
    mandate_root: Field,
    revocation_root: Field,
    revocation_scheme: u8,
    current_time: u64,
    settlement_context: Field,
    /// PRIVATE as of rev 7 — kept in this struct's original position for
    /// readability, but passed to `main` in its new witness position below.
    amount: u128,
    asset_id_pub: Field,
    zka_note_root: Field,
    zka_nullifier: Field,
    zka_cm_recipient: Field,
    zka_cm_change: Field,
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
    zka_in_value: u128,
    zka_in_randomness: Field,
    zka_path_index: Field,
    zka_siblings: [Field; 32],
    change_randomness: Field,
    recipient_address: Field,
    recipient_randomness: Field,
    policy_version: Field,
    policy_max_per_spend: u128,
    policy_recipient_restricted: Field,
    policy_recipient_set_root: Field,
    // v2 delegation depth limit; MUST be zero when `policy_version` is 1 (not
    // part of the v1 preimage — `assert_policy_opens` pins it). Not consulted
    // at spend time in either version.
    policy_depth_limit: u8,
    policy_blinding: Field,
    recipient_set_path_index: Field,
    recipient_set_siblings: [Field; 16],
}

impl Conjoined {
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
            self.asset_id_pub,
            self.zka_note_root,
            self.zka_nullifier,
            self.zka_cm_recipient,
            self.zka_cm_change,
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
            self.amount,
            self.zka_in_value,
            self.zka_in_randomness,
            self.zka_path_index,
            self.zka_siblings,
            self.change_randomness,
            self.recipient_address,
            self.recipient_randomness,
            self.policy_version,
            self.policy_max_per_spend,
            self.policy_recipient_restricted,
            self.policy_recipient_set_root,
            self.policy_depth_limit,
            self.policy_blinding,
            self.recipient_set_path_index,
            self.recipient_set_siblings,
        );
    }
}

/// The fixture policy: v1, a per-spend ceiling of 600, no recipient
/// restriction. Note `MAX_PER_SPEND < CAP` — the ceiling and the cap are
/// independent bounds, and the tests exercise each separately.
fn unrestricted_policy() -> StandardPolicyV2 {
    StandardPolicyV2 {
        version: POLICY_VERSION_V1,
        max_per_spend: MAX_PER_SPEND,
        recipient_restricted: 0,
        recipient_set_root: 0,
        depth_limit: 0,
        policy_blinding: POLICY_BLINDING,
    }
}

/// Test-side version-dispatched policy hash (mirrors `assert_policy_opens`).
fn hash_of(p: StandardPolicyV2) -> Field {
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

fn default_case() -> SpendCase {
    SpendCase {
        note_cap: CAP,
        note_expiry: EXPIRY,
        note_depth: 0,
        note_randomness: IN_RANDOMNESS,
        note_settlement_domain: SETTLEMENT_CONTEXT,
        holder_sk: HOLDER_SK,
        asset_id: ASSET_ID,
        policy: unrestricted_policy(),
        recipient_set_path_index: 0,
        recipient_set_siblings: [0; 16],
        amount: AMOUNT,
        zka_in_value: ZKA_IN_VALUE,
        zka_in_randomness: ZKA_IN_RANDOMNESS,
        zka_in_asset_id: ASSET_ID,
        zka_owner_sk: HOLDER_SK,
        recipient_address: counterparty_address(),
    }
}

/// A restricted-policy world: a two-member allowlist (the counterparty at index
/// 0, a second member as its level-0 sibling) under an otherwise empty depth-16
/// tree.
fn restricted_case() -> SpendCase {
    let mut siblings = empty_recipient_set_siblings();
    siblings[0] = derive_zka_address(SECOND_MEMBER_SK);
    let member = counterparty_address();

    let mut case = default_case();
    case.policy = StandardPolicyV2 {
        version: POLICY_VERSION_V1,
        max_per_spend: MAX_PER_SPEND,
        recipient_restricted: 1,
        recipient_set_root: compute_merkle_root_16(member, 0, siblings),
        depth_limit: 0,
        policy_blinding: POLICY_BLINDING,
    };
    case.recipient_set_siblings = siblings;
    case
}

fn case_note(case: SpendCase, policy_hash: Field) -> MandateNote {
    MandateNote {
        root_id: compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS),
        settlement_domain: case.note_settlement_domain,
        asset_id: case.asset_id,
        remaining_cap: case.note_cap,
        expiry: case.note_expiry,
        policy_hash,
        holder_key: derive_holder_key(case.holder_sk),
        depth: case.note_depth,
        randomness: case.note_randomness,
    }
}

/// Independent (test-side) reconstruction of a mandate successor commitment. It
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

/// Independent (test-side) reconstruction of a ZKA note commitment from a plain
/// asset id.
fn expected_zka_note(asset_id: Field, value: u128, recipient: Field, randomness: Field) -> Field {
    compute_zka_note_commitment(
        compute_zka_asset_commitment(asset_id),
        value as Field,
        recipient,
        randomness,
    )
}

/// Build a complete conjoined proof from a case, committing the mandate to
/// `policy_hash` rather than to the case policy's own hash.
///
/// Only the reserved-sentinel test needs the override (no policy opening hashes
/// to 0, so a `policy_hash = 0` mandate cannot be expressed through the case).
fn build_with_policy_hash(case: SpendCase, policy_hash: Field) -> Conjoined {
    let merkle_siblings = empty_merkle_siblings();
    let revocation_siblings = empty_revocation_siblings();

    // -- mandate leg --------------------------------------------------------
    let note = case_note(case, policy_hash);
    let cm_in = compute_mandate_commitment(note);
    // Deliberately tolerant: an over-spend case has no honest successor cap, so
    // the fixture publishes a consistent successor at cap 0 and the circuit is
    // expected to reject on the §4.3-2 bound, not on a commitment mismatch.
    let out1_cap = if case.note_cap >= case.amount {
        case.note_cap - case.amount
    } else {
        0
    };

    // -- ZKA leg ------------------------------------------------------------
    let holder_address = derive_zka_address(case.holder_sk);
    let cm_zka_in = expected_zka_note(
        case.zka_in_asset_id,
        case.zka_in_value,
        derive_zka_address(case.zka_owner_sk),
        case.zka_in_randomness,
    );
    // Same tolerance on the value leg: a conservation-violating case has no
    // honest change value, and the circuit must reject on the conservation
    // bound rather than on the change commitment.
    let change_value = if case.zka_in_value >= case.amount {
        case.zka_in_value - case.amount
    } else {
        0
    };

    Conjoined {
        kind: KIND_SPEND,
        nf: compute_mandate_nullifier(
            derive_holder_nullifier_secret(case.holder_sk),
            cm_in,
            SETTLEMENT_CONTEXT,
        ),
        cm_out_1: expected_successor(
            note,
            out1_cap,
            note.expiry,
            note.holder_key,
            note.depth,
            OUT1_RANDOMNESS,
        ),
        cm_out_2: 0,
        mandate_root: compute_merkle_root(cm_in, 0, merkle_siblings),
        revocation_root: compute_revocation_root(0, note.root_id, revocation_siblings),
        revocation_scheme: REVOCATION_ACCUMULATOR_FULL_ID_SPARSE_V2,
        current_time: CURRENT_TIME,
        settlement_context: SETTLEMENT_CONTEXT,
        amount: case.amount,
        asset_id_pub: case.asset_id,
        // The ZKA note tree is a SEPARATE depth-32 tree holding the consumed
        // value note as its only leaf.
        zka_note_root: compute_merkle_root(cm_zka_in, 0, merkle_siblings),
        zka_nullifier: compute_zka_nullifier(cm_zka_in, case.zka_owner_sk),
        // Outputs are denominated in the MANDATE's asset — what the circuit
        // reconstructs — so an asset-substituted INPUT fails on membership
        // rather than on an output commitment.
        zka_cm_recipient: expected_zka_note(
            case.asset_id,
            case.amount,
            case.recipient_address,
            RECIPIENT_RANDOMNESS,
        ),
        zka_cm_change: expected_zka_note(
            case.asset_id,
            change_value,
            holder_address,
            CHANGE_RANDOMNESS,
        ),
        in_root_id: note.root_id,
        in_settlement_domain: note.settlement_domain,
        in_asset_id: note.asset_id,
        in_remaining_cap: note.remaining_cap,
        in_expiry: note.expiry,
        in_policy_hash: note.policy_hash,
        in_depth: note.depth,
        in_randomness: note.randomness,
        holder_sk: case.holder_sk,
        merkle_path_index: 0,
        merkle_siblings,
        revocation_siblings,
        out1_cap,
        out1_expiry: note.expiry,
        out1_randomness: OUT1_RANDOMNESS,
        zka_in_value: case.zka_in_value,
        zka_in_randomness: case.zka_in_randomness,
        zka_path_index: 0,
        zka_siblings: merkle_siblings,
        change_randomness: CHANGE_RANDOMNESS,
        recipient_address: case.recipient_address,
        recipient_randomness: RECIPIENT_RANDOMNESS,
        policy_version: case.policy.version,
        policy_max_per_spend: case.policy.max_per_spend,
        policy_recipient_restricted: case.policy.recipient_restricted,
        policy_recipient_set_root: case.policy.recipient_set_root,
        policy_depth_limit: case.policy.depth_limit,
        policy_blinding: case.policy.policy_blinding,
        recipient_set_path_index: case.recipient_set_path_index,
        recipient_set_siblings: case.recipient_set_siblings,
    }
}

fn build(case: SpendCase) -> Conjoined {
    build_with_policy_hash(case, hash_of(case.policy))
}

// -----------------------------------------------------------------------------
// Positive: the conjunction itself
// -----------------------------------------------------------------------------

#[test]
fn test_conjoined_spend_with_change() {
    // The canonical case: 400 of a 900-value note leaves the holder under a
    // 1000-cap mandate, 500 comes back as change, all three legs satisfied.
    build(default_case()).run();
}

#[test]
fn test_full_note_spend_change_zero() {
    // The consumed note is spent entirely: `change_value = 0`. The change note
    // still exists (a zero-value note under fresh randomness) — the circuit
    // does not special-case it away, because an absent output would make the
    // settlement layer's insert set depend on a witness.
    let mut case = default_case();
    case.zka_in_value = 500;
    case.amount = 500;
    let mut t = build(case);
    let holder_address = derive_zka_address(HOLDER_SK);
    assert(
        t.zka_cm_recipient
            == expected_zka_note(ASSET_ID, 500, case.recipient_address, RECIPIENT_RANDOMNESS),
    );
    assert(t.zka_cm_change == expected_zka_note(ASSET_ID, 0, holder_address, CHANGE_RANDOMNESS));
    assert(t.zka_cm_change != 0);
    assert(t.zka_cm_change != t.zka_cm_recipient);
    assert(t.change_randomness != t.zka_in_randomness);
    let first_change = t.zka_cm_change;
    // A second, fresh opening is a distinct zero-value commitment; the fixed
    // change output remains present and must still reconstruct in the circuit.
    t.change_randomness = CHANGE_RANDOMNESS + 2;
    t.zka_cm_change = expected_zka_note(ASSET_ID, 0, holder_address, t.change_randomness);
    assert(t.zka_cm_change != first_change);
    t.run();
}

#[test]
fn test_spend_amount_one() {
    let mut case = default_case();
    case.amount = 1;
    let t = build(case);
    assert(t.out1_cap == CAP - 1);
    assert(
        t.zka_cm_recipient
            == expected_zka_note(ASSET_ID, 1, case.recipient_address, RECIPIENT_RANDOMNESS),
    );
    assert(
        t.zka_cm_change
            == expected_zka_note(
                ASSET_ID,
                ZKA_IN_VALUE - 1,
                derive_zka_address(HOLDER_SK),
                CHANGE_RANDOMNESS,
            ),
    );
    t.run();
}

#[test]
fn test_amount_at_policy_max_boundary() {
    // `amount == max_per_spend` is permitted; the ceiling is inclusive.
    let mut case = default_case();
    case.amount = MAX_PER_SPEND;
    build(case).run();
}

#[test]
fn test_spend_exact_remaining_cap() {
    // Spending the whole remaining cap is legal; the successor is a live note
    // with cap 0, not a retirement (it can still be RETIREd or SPLIT by the
    // mandate-only VK).
    let mut case = default_case();
    case.note_cap = 400;
    case.amount = 400;
    build(case).run();
}

#[test]
fn test_restricted_policy_permits_member_recipient() {
    // The recipient is proven a member of the policy's depth-16 allowlist —
    // without revealing WHICH member, or the set's other entries.
    build(restricted_case()).run();
}

#[test(should_fail_with = "unrestricted policy must carry a zero allowlist path index")]
fn test_unrestricted_policy_rejects_nonzero_allowlist_index() {
    // An unrestricted policy MUST carry a canonical (zero) dummy witness,
    // because a junk one is a free unconstrained witness the prover controls.
    //
    // It is NOT because proving would otherwise reject it: measured against
    // nargo 1.0.0-beta.25 + bb 5.0.0, with this assertion
    // removed the junk index executes, proves AND verifies. See the doc comment
    // on `zkm_lib::assert_policy_permits_spend`.
    let mut case = default_case();
    case.recipient_set_path_index = 1048576;
    build(case).run();
}

#[test(should_fail_with = "unrestricted policy must carry zero allowlist siblings")]
fn test_unrestricted_policy_rejects_nonzero_allowlist_siblings() {
    let mut case = default_case();
    case.recipient_set_siblings = [12345; 16];
    build(case).run();
}

#[test(should_fail_with = "spend amount must be positive")]
fn test_spend_zero_amount_rejected() {
    // Conservation alone admits a mandate and value-note refresh with no
    // cap consumed and a zero-value recipient note.
    let mut case = default_case();
    case.amount = 0;
    build(case).run();
}

#[test(should_fail_with = "spend amount must be positive")]
fn test_zero_value_input_and_zero_amount_rejected() {
    let mut case = default_case();
    case.zka_in_value = 0;
    case.amount = 0;
    build(case).run();
}

#[test]
fn test_successor_may_narrow_expiry() {
    // §4.3-3 bounds expiry from above only; narrowing is allowed.
    let case = default_case();
    let note = case_note(case, hash_of(case.policy));
    let mut t = build(case);
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
fn test_spend_at_max_depth_is_provable() {
    // A deeply delegated mandate is still spendable: SPEND preserves depth and
    // performs no depth arithmetic, so `depth = 255` — the value at which a
    // DELEGATE would trap — must not make an ordinary spend unprovable.
    let mut case = default_case();
    case.note_depth = 255;
    build(case).run();
}

#[test]
fn test_conjoined_chain_two_steps() {
    // Spend, then spend again from the successor mandate AND the change note.
    // Both trees are re-rooted around the single new leaf each step produces,
    // which is what the settlement layer's atomic five-effect application
    // yields for one-note trees.
    let case1 = default_case();
    let step1 = build(case1);
    step1.run();

    let mut case2 = default_case();
    // The mandate successor of step 1: cap 1000 - 400, fresh randomness.
    case2.note_cap = CAP - AMOUNT;
    case2.note_randomness = OUT1_RANDOMNESS;
    // The change note of step 1: value 900 - 400, under the change randomness.
    case2.zka_in_value = ZKA_IN_VALUE - AMOUNT;
    case2.zka_in_randomness = CHANGE_RANDOMNESS;
    // Spend the change note in full, within both the successor cap and the
    // per-spend ceiling.
    case2.amount = 500;

    let step2 = build(case2);
    // The step-2 world must be exactly the state step 1 published, not a
    // lookalike: same mandate successor commitment, same value-note commitment.
    assert(
        compute_mandate_commitment(case_note(case2, hash_of(case2.policy))) == step1.cm_out_1,
        "step 2 must consume step 1's mandate successor",
    );
    assert(
        expected_zka_note(
            ASSET_ID,
            case2.zka_in_value,
            derive_zka_address(HOLDER_SK),
            CHANGE_RANDOMNESS,
        )
            == step1.zka_cm_change,
        "step 2 must consume step 1's change note",
    );
    step2.run();

    // Authority strictly decreased (1000 -> 600 -> 100) and both nullifier sets
    // see two distinct entries, so neither leg was replayed.
    assert(step2.out1_cap == 100);
    assert(step1.nf != step2.nf);
    assert(step1.zka_nullifier != step2.zka_nullifier);
}

// -----------------------------------------------------------------------------
// Negative: proof-form separation (§5)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "this verification key proves SPEND only")]
fn test_non_spend_kind_rejected() {
    // The mirror image of `zkm_mandate_transition`'s SPEND rejection: neither
    // VK admits the other's kinds, so the two public-input layouts can never be
    // confused for one another.
    let mut t = build(default_case());
    t.kind = KIND_SPLIT;
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: mandate conservation and bounds (§4.3-1, §4.3-2)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "spend amount exceeds remaining cap")]
fn test_overspend_rejected() {
    let mut case = default_case();
    case.amount = CAP + 1;
    build(case).run();
}

#[test(should_fail_with = "SPEND successor cap must equal remaining cap minus amount")]
fn test_spend_successor_cap_inflation_rejected() {
    // Within the cap bound, but the successor keeps more than it should.
    let case = default_case();
    let note = case_note(case, hash_of(case.policy));
    let mut t = build(case);
    t.out1_cap = 900;
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

// -----------------------------------------------------------------------------
// Negative: mandate successor shape
// -----------------------------------------------------------------------------

#[test(should_fail_with = "successor 1 commitment must be non-zero")]
fn test_zero_successor_rejected() {
    // A SPEND with no successor is a RETIRE in disguise: the cap would be
    // destroyed while the public vector still claims `amount` was settled.
    let mut t = build(default_case());
    t.cm_out_1 = 0;
    t.run();
}

#[test(should_fail_with = "SPEND must have no second successor")]
fn test_nonzero_cm_out_2_rejected() {
    let mut t = build(default_case());
    t.cm_out_2 = 99;
    t.run();
}

#[test(should_fail_with = "successor 1 commitment mismatch")]
fn test_consumed_mandate_as_successor_rejected() {
    // Even at a positive amount, publishing the consumed mandate note as the
    // successor fails reconstruction because its cap was not decremented.
    let case = default_case();
    let note = case_note(case, hash_of(case.policy));
    let mut t = build(case);
    t.out1_randomness = note.randomness;
    t.cm_out_1 = expected_successor(
        note,
        note.remaining_cap,
        note.expiry,
        note.holder_key,
        note.depth,
        note.randomness,
    );
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: monotone narrowing and inheritance (§4.3-3)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "successor expiry must not extend the input expiry")]
fn test_successor_expiry_extension_rejected() {
    let case = default_case();
    let note = case_note(case, hash_of(case.policy));
    let mut t = build(case);
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
    let case = default_case();
    let note = case_note(case, hash_of(case.policy));
    let mut forged = note;
    forged.asset_id = ASSET_ID + 1;
    let mut t = build(case);
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

#[test(should_fail_with = "successor 1 commitment mismatch")]
fn test_spend_holder_rebind_rejected() {
    // SPEND preserves the holder; rebinding requires DELEGATE, which is not
    // expressible on this VK at all.
    let case = default_case();
    let note = case_note(case, hash_of(case.policy));
    let mut t = build(case);
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        derive_holder_key(OTHER_SK),
        note.depth,
        t.out1_randomness,
    );
    t.run();
}

#[test(should_fail_with = "successor 1 commitment mismatch")]
fn test_spend_depth_reset_rejected() {
    // Depth is preserved by SPEND. A successor at depth 0 would launder a
    // delegated mandate back into a freshly-issued-looking one and reset the
    // §6 delegation budget.
    let mut case = default_case();
    case.note_depth = 3;
    let note = case_note(case, hash_of(case.policy));
    let mut t = build(case);
    t.cm_out_1 = expected_successor(
        note,
        t.out1_cap,
        t.out1_expiry,
        note.holder_key,
        0,
        t.out1_randomness,
    );
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: conjunction publics (§5)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "asset_id_pub must equal the mandate asset")]
fn test_wrong_asset_id_pub_rejected() {
    let mut t = build(default_case());
    t.asset_id_pub = ASSET_ID + 1;
    t.run();
}

#[test]
fn test_spend_under_v2_policy() {
    // A v2 mandate spends exactly like a v1 one: depth_limit is a DELEGATION
    // parameter and is not consulted here.
    let mut case = default_case();
    case.policy.version = POLICY_VERSION_V2;
    case.policy.depth_limit = 3;
    build(case).run();
}

#[test(should_fail_with = "policy opening mismatch")]
fn test_v2_spend_with_forged_policy_carrier_rejected() {
    let mut case = default_case();
    case.policy.version = POLICY_VERSION_V2;
    case.policy.depth_limit = 3;
    case.amount = 700;
    case.zka_in_value = 900;
    let mut t = build(case);
    t.policy_max_per_spend = 1_000_000;
    t.run();
}

#[test(should_fail_with = "v1 policy must carry a zero depth_limit witness")]
fn test_v1_spend_with_nonzero_depth_limit_witness_rejected() {
    let mut t = build(default_case());
    t.policy_depth_limit = 1;
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: holder binding, membership, nullification (§3, §4.3-4)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "mandate note is not in the mandate state tree")]
fn test_wrong_holder_sk_rejected() {
    // holder_key is derived, never witnessed, so a wrong secret rebuilds a
    // different mandate commitment and membership fails before anything else —
    // including before the ZKA leg, where the same secret would also fail to
    // open the value note.
    let mut t = build(default_case());
    t.holder_sk = HOLDER_SK + 1;
    t.run();
}

#[test(should_fail_with = "mandate note is not in the mandate state tree")]
fn test_wrong_mandate_root_rejected() {
    let mut t = build(default_case());
    t.mandate_root = t.mandate_root + 1;
    t.run();
}

#[test(should_fail_with = "mandate nullifier mismatch")]
fn test_wrong_nullifier_public_input_rejected() {
    let mut t = build(default_case());
    t.nf = t.nf + 1;
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: settlement-domain binding (§5 shared public inputs)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "settlement_context must be non-zero")]
fn test_zero_settlement_context_rejected() {
    let mut t = build(default_case());
    t.settlement_context = 0;
    t.run();
}

#[test(should_fail_with = "mandate is not issued for this settlement domain")]
fn test_wrong_settlement_domain_rejected() {
    // The mandate was ISSUED for domain A (its committed `settlement_domain`,
    // honestly witnessed) but the spend is proven against domain B. The
    // AUTHORITY binding rejects it: without it one mandate is witnessable — and
    // its cap spent, its value moved — once per settlement domain that shares
    // the mandate tree. This is the primary cross-domain-multiplication defence;
    // the nullifier folding is only replay hygiene layered on top.
    let mut t = build(default_case());
    t.settlement_context = SETTLEMENT_CONTEXT + 1;
    t.run();
}

#[test(should_fail_with = "mandate note is not in the mandate state tree")]
fn test_cross_domain_replay_rejected() {
    // The complementary escape: a replay attacker moves to domain B AND relabels
    // the witnessed domain to B to slip past the authority assertion. But the
    // note committed in the tree carries domain A, so reconstructing it under
    // domain B is a different commitment and membership fails. The domain is
    // bound into the COMMITMENT, so the mandate cannot be relabelled onto
    // another domain at all.
    let mut t = build(default_case());
    t.settlement_context = SETTLEMENT_CONTEXT + 1;
    t.in_settlement_domain = SETTLEMENT_CONTEXT + 1;
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: reserved zero sentinels (§3 field discipline)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "mandate asset_id must be non-zero")]
fn test_zero_asset_id_rejected() {
    // With `asset_id = 0` the SPEND form is genuinely ambiguous:
    // `asset_id_pub == in_asset_id` and "asset_id_pub is the unset sentinel"
    // would hold at the same time.
    let mut case = default_case();
    case.asset_id = 0;
    case.zka_in_asset_id = 0;
    build(case).run();
}

#[test(should_fail_with = "mandate policy_hash must be non-zero")]
fn test_zero_policy_hash_rejected() {
    // No policy opening hashes to 0, so this mandate could never have been
    // issued honestly — but the circuit refuses it explicitly rather than
    // relying on that.
    build_with_policy_hash(default_case(), 0).run();
}

// -----------------------------------------------------------------------------
// Negative: revocation and temporal validity (§4.3-5, §4.3-6, §7.1)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "mandate root_id is revoked or the revocation path is invalid")]
fn test_revoked_root_id_rejected() {
    let mut t = build(default_case());
    t.revocation_siblings[0] = 12345;
    t.run();
}

#[test(should_fail_with = "unsupported revocation accumulator version")]
fn test_legacy_revocation_accumulator_version_rejected() {
    let mut t = build(default_case());
    t.revocation_scheme = 1;
    t.run();
}

#[test(should_fail_with = "mandate expired")]
fn test_expired_mandate_rejected() {
    let mut t = build(default_case());
    t.current_time = EXPIRY;
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: the ZKA value leg
// -----------------------------------------------------------------------------

#[test(should_fail_with = "spend amount exceeds the value note")]
fn test_value_conservation_violation_rejected() {
    // The mandate has cap for it and the policy permits it, but the note being
    // spent is not worth it: `amount > zka_in_value` would mint value out of
    // nothing (or, with a wrapping subtraction, an enormous change note).
    let mut case = default_case();
    case.zka_in_value = 100;
    build(case).run();
}

#[test(should_fail_with = "zka value note is not in the zka note tree")]
fn test_foreign_zka_note_rejected() {
    // A note owned by another key. The circuit reconstructs the consumed note
    // at `derive_zka_address(holder_sk)`, so a note addressed to anyone else is
    // simply not the leaf it looks for — a mandate cannot authorize the
    // movement of a stranger's value.
    let mut case = default_case();
    case.zka_owner_sk = OTHER_SK;
    build(case).run();
}

#[test(should_fail_with = "zka value note is not in the zka note tree")]
fn test_zka_asset_substitution_rejected() {
    // A note of a DIFFERENT asset than the mandate authorizes. `asset_cm` comes
    // from the mandate's own `asset_id`, so this is unwitnessable: the value
    // provably moves in the mandated asset or not at all.
    let mut case = default_case();
    case.zka_in_asset_id = ASSET_ID + 1;
    build(case).run();
}

#[test(should_fail_with = "zka value note is not in the zka note tree")]
fn test_wrong_zka_note_root_rejected() {
    let mut t = build(default_case());
    t.zka_note_root = t.zka_note_root + 1;
    t.run();
}

#[test(should_fail_with = "zka nullifier mismatch")]
fn test_wrong_zka_nullifier_public_rejected() {
    // The published ZKA nullifier is what the settlement layer serializes value
    // spends on; a free choice of it would let one note be spent repeatedly.
    let mut t = build(default_case());
    t.zka_nullifier = t.zka_nullifier + 1;
    t.run();
}

#[test(should_fail_with = "recipient address must be non-zero")]
fn test_zero_recipient_rejected() {
    let mut case = default_case();
    case.recipient_address = 0;
    build(case).run();
}

#[test(should_fail_with = "spend recipient must differ from the holder")]
fn test_self_spend_rejected() {
    // Paying oneself consumes mandate authority for no transfer.
    let mut case = default_case();
    case.recipient_address = derive_zka_address(HOLDER_SK);
    build(case).run();
}

#[test(should_fail_with = "zka recipient commitment must be non-zero")]
fn test_zero_zka_recipient_commitment_rejected() {
    let mut t = build(default_case());
    t.zka_cm_recipient = 0;
    t.run();
}

#[test(should_fail_with = "zka change commitment must be non-zero")]
fn test_zero_zka_change_commitment_rejected() {
    let mut t = build(default_case());
    t.zka_cm_change = 0;
    t.run();
}

#[test(should_fail_with = "zka output commitments must be distinct")]
fn test_identical_zka_outputs_rejected() {
    // Two equal outputs are ONE leaf to the settlement layer: half the value
    // would be destroyed while conservation held on paper.
    let mut t = build(default_case());
    t.zka_cm_change = t.zka_cm_recipient;
    t.run();
}

#[test(should_fail_with = "zka change output must differ from the consumed note")]
fn test_zka_output_equal_to_consumed_note_rejected() {
    // Re-inserting the consumed note as its own change re-creates a leaf whose
    // nullifier is already spent: permanently unspendable value.
    let mut t = build(default_case());
    t.zka_cm_change = expected_zka_note(
        ASSET_ID,
        ZKA_IN_VALUE,
        derive_zka_address(HOLDER_SK),
        ZKA_IN_RANDOMNESS,
    );
    t.run();
}

#[test(should_fail_with = "zka recipient output must differ from the consumed note")]
fn test_zka_recipient_output_equal_to_consumed_note_rejected() {
    // The recipient-side twin of the guard above: the consumed note re-published
    // as the RECIPIENT output re-inserts a leaf whose nullifier is already
    // spent. Both output slots carry the same distinct-from-consumed guard, and
    // only exercising the change slot left the recipient comparison untested.
    let mut t = build(default_case());
    t.zka_cm_recipient = expected_zka_note(
        ASSET_ID,
        ZKA_IN_VALUE,
        derive_zka_address(HOLDER_SK),
        ZKA_IN_RANDOMNESS,
    );
    t.run();
}

#[test(should_fail_with = "zka recipient note commitment mismatch")]
fn test_forged_zka_cm_recipient_rejected() {
    // The published recipient note must be worth exactly `amount` and be
    // addressed to the recipient the policy was evaluated against; a free
    // choice of it would decouple the settled value from the authorized one.
    let mut t = build(default_case());
    t.zka_cm_recipient = expected_zka_note(
        ASSET_ID,
        AMOUNT + 1,
        counterparty_address(),
        RECIPIENT_RANDOMNESS,
    );
    t.run();
}

#[test(should_fail_with = "zka change note commitment mismatch")]
fn test_forged_zka_cm_change_rejected() {
    // Inflating the change is how a prover would keep value it did not have.
    let mut t = build(default_case());
    t.zka_cm_change = expected_zka_note(
        ASSET_ID,
        ZKA_IN_VALUE,
        derive_zka_address(HOLDER_SK),
        CHANGE_RANDOMNESS,
    );
    t.run();
}

// -----------------------------------------------------------------------------
// Negative: the policy predicate (§5)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "policy opening mismatch")]
fn test_policy_opening_mismatch_rejected() {
    // The heart of §5's "a proof against any other policy MUST NOT verify": the
    // prover evaluates a permissive policy of its own choosing while the
    // mandate committed to a stricter one.
    let mut t = build(default_case());
    t.policy_max_per_spend = 1_000_000;
    t.run();
}

#[test(should_fail_with = "unsupported policy version")]
fn test_unsupported_policy_version_rejected() {
    // The version check fires before any opening is attempted: an unknown
    // schema is refused, never reinterpreted under a known version's
    // semantics.
    let mut case = default_case();
    case.policy.version = 3;
    build(case).run();
}

#[test(should_fail_with = "spend exceeds policy max_per_spend")]
fn test_amount_exceeds_policy_max_rejected() {
    // Within the mandate's remaining cap (1000) but over the policy's per-spend
    // ceiling (600) — the two bounds are independent, and this is the one the
    // superseded package could not enforce at all.
    let mut case = default_case();
    case.amount = MAX_PER_SPEND + 100;
    build(case).run();
}

#[test(should_fail_with = "recipient_restricted must be boolean")]
fn test_non_boolean_recipient_restriction_rejected() {
    // A selector of 2 would take neither branch: the allowlist would go
    // unenforced under a policy_hash the principal signed believing it
    // restricted.
    let mut case = restricted_case();
    case.policy.recipient_restricted = 2;
    build(case).run();
}

#[test(should_fail_with = "restricted policy must carry a non-zero recipient set root")]
fn test_restricted_policy_zero_set_root_rejected() {
    let mut case = default_case();
    case.policy.recipient_restricted = 1;
    build(case).run();
}

#[test(should_fail_with = "recipient not in the policy recipient set")]
fn test_restricted_policy_non_member_rejected() {
    // Everything else about this spend is valid; the counterparty is simply not
    // on the allowlist the mandate committed to.
    let mut case = restricted_case();
    case.recipient_address = derive_zka_address(OTHER_SK);
    build(case).run();
}

#[test]
fn test_restricted_policy_permits_member_at_index_1() {
    // The whole existing restricted-policy suite proves membership at path_index
    // 0. A leaf at index 0 is always the LEFT child at every level, so an
    // all-index-0 suite never exercises the RIGHT-child branch of
    // `compute_merkle_root_16` — a bit-order reversal there (folding index bits
    // MSB-first instead of LSB-first, or swapping the left/right selector) would
    // pass every index-0 test yet corrupt every non-zero position. This pins a
    // member at path_index 1 (the RIGHT child at level 0), so that branch is
    // constraint-bearing. The allowlist: `member` at index 1, with the node at
    // index 0 as its level-0 sibling, under an otherwise empty depth-16 tree.
    let member = counterparty_address();
    let mut siblings = empty_recipient_set_siblings();
    siblings[0] = derive_zka_address(SECOND_MEMBER_SK);
    let root = compute_merkle_root_16(member, 1, siblings);

    let mut case = default_case();
    case.policy = StandardPolicyV2 {
        version: POLICY_VERSION_V1,
        max_per_spend: MAX_PER_SPEND,
        recipient_restricted: 1,
        recipient_set_root: root,
        depth_limit: 0,
        policy_blinding: POLICY_BLINDING,
    };
    case.recipient_set_path_index = 1;
    case.recipient_set_siblings = siblings;
    case.recipient_address = member;
    build(case).run();
}

#[test(should_fail_with = "Field failed to decompose into specified 16 limbs")]
fn test_restricted_policy_rejects_out_of_range_set_index() {
    // Under a RESTRICTED policy the membership branch is constraint-bearing, and
    // `compute_merkle_root_16` decomposes `recipient_set_path_index` into 16
    // bits. An index at or above 2^16 is not a position in a depth-16 tree; the
    // decomposition traps rather than silently truncating the index (which would
    // let a prover claim a position outside the committed set). Pins that trap —
    // and its exact runtime message — for the restricted branch.
    let mut case = restricted_case();
    case.recipient_set_path_index = 65536; // 2^16, one past the last valid leaf
    build(case).run();
}

// -----------------------------------------------------------------------------
// Negative: policy blinding (§4.6, F4)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "policy blinding must be non-zero")]
fn test_zero_policy_blinding_rejected() {
    // A mandate whose policy commits to a ZERO blinding: the opening is
    // hash-consistent (the mandate's policy_hash is computed with blinding 0),
    // so the §5 opening check passes, but the predicate refuses it — an
    // unblinded policy hash is dictionary-invertible and a cross-spend lineage
    // identifier (§4.6).
    let mut case = default_case();
    case.policy.policy_blinding = 0;
    build(case).run();
}

// -----------------------------------------------------------------------------
// Negative: output-randomness hygiene (§4.6, F5)
// -----------------------------------------------------------------------------

#[test(should_fail_with = "recipient randomness must be non-zero")]
fn test_zero_recipient_randomness_rejected() {
    // Recipient non-recoverability rests on the recipient note's randomness
    // being the commitment's only secret entropy; a zero randomness makes it a
    // deterministic function of public/low-entropy fields, openable by guessing.
    let mut t = build(default_case());
    t.recipient_randomness = 0;
    t.run();
}

#[test(should_fail_with = "change randomness must be non-zero")]
fn test_zero_change_randomness_rejected() {
    let mut t = build(default_case());
    t.change_randomness = 0;
    t.run();
}

#[test(should_fail_with = "recipient and change randomness must differ")]
fn test_equal_output_randomness_rejected() {
    // Distinct messages MUST carry distinct randomness: equal randomness across
    // the two outputs is the kind of correlated sampling the PROVER OBLIGATIONS
    // block forbids, and at equal value it would collapse the two commitments.
    let mut t = build(default_case());
    t.recipient_randomness = t.change_randomness;
    t.run();
}

// =============================================================================
// Known-Answer Test
//
// Pins the WHOLE §5 public tuple of one canonical conjoined spend: both
// nullifiers, both tree roots, the mandate successor, both ZKA output
// commitments and the policy hash, over the fixture world (mandate root_id =
// H(991, 13), settlement_domain 0x5e771e3c, asset 7, cap 1000, expiry 2000,
// holder_sk 4242, randomness 555; value note 900 at randomness 7001; spend 400
// to the KDC address of entity seed 8888 with recipient randomness 7003 and change
// randomness 7002; policy v1 / max_per_spend 600 / unrestricted / blinding
// 0x9e2b77a1; settlement context 0x5e771e3c).
//
// This is a tripwire on the entire construction — commitment preimage orders
// (including the mandate commitment's `settlement_domain` slot and the policy
// preimage's `policy_blinding` slot), every domain separator, both Merkle bit
// orders, the nullifier shapes (including the mandate nullifier's
// settlement-context slot), and the ZKA two-layer note construction.
//
// TWO OF THESE VALUES ARE CROSS-CHECKED IN `zkm_lib` and must not be re-blessed
// in isolation: `zka_nullifier` equals `kat_zka_nullifier` (the consumed value
// note IS that KAT's note — asset 7, value 900, owner sk 4242, randomness
// 7001), and the fixture policy hash equals `kat_policy_hash_v1_unrestricted`
// (checked below via `hash_of` — no longer a public input as of rev 5). Both
// therefore also inherit that KAT's cross-repository check against ZKA's own
// `zka_lib`. `revocation_root` is the version-2 empty full-id exclusion root.
//
// The fixture commits to an openable policy (§5) with `compute_policy_hash(...)`.
// The `zkm_lib::kat_mandate_nullifier` fixture uses a stand-in `policy_hash = 33`.
// These policy hashes yield different mandate commitments and nullifiers.
//
// As with every KAT in this workspace, do NOT re-bless by pasting a new value —
// a mismatch is a protocol break until proven otherwise. To re-capture after an
// audited change:
//   nargo test --show-output kat_
// Captured under nargo 1.0.0-beta.22 + poseidon v0.3.0.
// =============================================================================

#[test]
fn kat_conjoined_public_inputs() {
    let t = build(default_case());
    println(t.nf);
    println(t.cm_out_1);
    println(t.mandate_root);
    println(t.revocation_root);
    println(t.revocation_scheme);
    let fixture_policy_hash = hash_of(default_case().policy);
    println(fixture_policy_hash);
    println(t.zka_note_root);
    println(t.zka_nullifier);
    println(t.zka_cm_recipient);
    println(t.zka_cm_change);

    // -- mandate leg --------------------------------------------------------
    assert(
        t.nf == 0x08baf96e623fdfcda647a9919dce6bd34134561705598bb2dbbdf839a27d7eec,
        "conjoined mandate nullifier KAT mismatch",
    );
    assert(
        t.cm_out_1 == 0x174fb29393ab14248c16ff2a981f4eb739eed9138b44c0e9f57728e73789b942,
        "conjoined mandate successor commitment KAT mismatch",
    );
    assert(
        t.mandate_root == 0x073c003cc29873b29985ebb4a8e0f7bacf2021990cbed369c6c0aaf75e112980,
        "conjoined mandate state-tree root KAT mismatch",
    );
    assert(
        t.revocation_root == 0x0ec9cf7fbcbffa41bc1b25e7569f1bbc85ee742cbe1c6c6f4c6af987b9773f55,
        "version-2 full-id exclusion accumulator root KAT mismatch",
    );
    assert(
        t.revocation_scheme == REVOCATION_ACCUMULATOR_FULL_ID_SPARSE_V2,
        "revocation accumulator version KAT mismatch",
    );

    // -- policy leg ---------------------------------------------------------
    assert(
        fixture_policy_hash == 0x2b487390249e8dc9619250a062297e450b984d2bdd5f2c0277edbf1f6e5dd32f,
        "conjoined policy hash KAT mismatch",
    );

    // -- ZKA value leg ------------------------------------------------------
    assert(
        t.zka_note_root == 0x002e132102c77c0097c77a6d798be9668f7c0a3249de5f4b1e13430f81440a56,
        "zka note-tree root KAT mismatch",
    );
    assert(
        t.zka_nullifier == 0x2c0540439a25670b0c6441614febeb452185856f121eabc87c0197e4f470f8c4,
        "zka nullifier KAT mismatch",
    );
    assert(
        t.zka_cm_recipient == 0x2d720b87b17436a59885d6e1c7c409941eae3ab13e544b7b08c158ce497fac94,
        "zka recipient note commitment KAT mismatch",
    );
    assert(
        t.zka_cm_change == 0x09f692147183dd8a1f6d85017286971bf50376d6d348a19a6a1b74f5b8d6a901,
        "zka change note commitment KAT mismatch",
    );

    // The pinned tuple must actually verify.
    t.run();
}

// =============================================================================
// Prover.toml emission — witness generation for the bb proving harness.
// See the sibling comment in zkm_mandate_transition for the rationale: the
// witness that gets PROVED is built by the same fixture helpers as the witness
// that gets TESTED, so the two cannot drift.
// =============================================================================

fn emit_prover_toml(c: Conjoined) {
    let kind = c.kind;
    let nf = c.nf;
    let cm_out_1 = c.cm_out_1;
    let cm_out_2 = c.cm_out_2;
    let mandate_root = c.mandate_root;
    let revocation_root = c.revocation_root;
    let revocation_scheme = c.revocation_scheme;
    let current_time = c.current_time;
    let settlement_context = c.settlement_context;
    let asset_id_pub = c.asset_id_pub;

    let zka_note_root = c.zka_note_root;
    let zka_nullifier = c.zka_nullifier;
    let zka_cm_recipient = c.zka_cm_recipient;
    let zka_cm_change = c.zka_cm_change;
    println(f"kind={kind}");
    println(f"nf={nf}");
    println(f"cm_out_1={cm_out_1}");
    println(f"cm_out_2={cm_out_2}");
    println(f"mandate_root={mandate_root}");
    println(f"revocation_root={revocation_root}");
    println(f"revocation_scheme={revocation_scheme}");
    println(f"current_time={current_time}");
    println(f"settlement_context={settlement_context}");
    println(f"asset_id_pub={asset_id_pub}");
    println(f"zka_note_root={zka_note_root}");
    println(f"zka_nullifier={zka_nullifier}");
    println(f"zka_cm_recipient={zka_cm_recipient}");
    println(f"zka_cm_change={zka_cm_change}");

    let in_root_id = c.in_root_id;
    let in_settlement_domain = c.in_settlement_domain;
    let in_asset_id = c.in_asset_id;
    let in_remaining_cap = c.in_remaining_cap;
    let in_expiry = c.in_expiry;
    let in_policy_hash = c.in_policy_hash;
    let in_depth = c.in_depth;
    let in_randomness = c.in_randomness;
    let holder_sk = c.holder_sk;
    let merkle_path_index = c.merkle_path_index;
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
        let v = c.merkle_siblings[i];
        println(f"merkle_siblings[]={v}");
    }
    for i in 0..254 {
        let v = c.revocation_siblings[i];
        println(f"revocation_siblings[]={v}");
    }

    let out1_cap = c.out1_cap;
    let out1_expiry = c.out1_expiry;
    let out1_randomness = c.out1_randomness;
    // PRIVATE as of rev 7 — emitted with the ZKA value-leg witnesses, not with
    // the publics above.
    let amount = c.amount;
    let zka_in_value = c.zka_in_value;
    let zka_in_randomness = c.zka_in_randomness;
    let zka_path_index = c.zka_path_index;
    println(f"out1_cap={out1_cap}");
    println(f"out1_expiry={out1_expiry}");
    println(f"out1_randomness={out1_randomness}");
    println(f"amount={amount}");
    println(f"zka_in_value={zka_in_value}");
    println(f"zka_in_randomness={zka_in_randomness}");
    println(f"zka_path_index={zka_path_index}");

    for i in 0..32 {
        let v = c.zka_siblings[i];
        println(f"zka_siblings[]={v}");
    }

    let change_randomness = c.change_randomness;
    let recipient_address = c.recipient_address;
    let recipient_randomness = c.recipient_randomness;
    let policy_version = c.policy_version;
    let policy_max_per_spend = c.policy_max_per_spend;
    let policy_recipient_restricted = c.policy_recipient_restricted;
    let policy_recipient_set_root = c.policy_recipient_set_root;
    let policy_depth_limit = c.policy_depth_limit;
    let policy_blinding = c.policy_blinding;
    let recipient_set_path_index = c.recipient_set_path_index;
    println(f"change_randomness={change_randomness}");
    println(f"recipient_address={recipient_address}");
    println(f"recipient_randomness={recipient_randomness}");
    println(f"policy_version={policy_version}");
    println(f"policy_max_per_spend={policy_max_per_spend}");
    println(f"policy_recipient_restricted={policy_recipient_restricted}");
    println(f"policy_recipient_set_root={policy_recipient_set_root}");
    println(f"policy_depth_limit={policy_depth_limit}");
    println(f"policy_blinding={policy_blinding}");
    println(f"recipient_set_path_index={recipient_set_path_index}");

    for i in 0..16 {
        let v = c.recipient_set_siblings[i];
        println(f"recipient_set_siblings[]={v}");
    }
}

#[test]
fn emit_toml_spend_unrestricted() {
    emit_prover_toml(build(default_case()));
}

#[test]
fn emit_toml_spend_v2() {
    let mut case = default_case();
    case.policy.version = POLICY_VERSION_V2;
    case.policy.depth_limit = 3;
    emit_prover_toml(build(case));
}

#[test]
fn emit_toml_spend_restricted() {
    emit_prover_toml(build(restricted_case()));
}

#[test]
fn emit_toml_spend_amount_one() {
    let mut case = default_case();
    case.amount = 1;
    emit_prover_toml(build(case));
}

#[test]
fn emit_toml_spend_full_note() {
    let mut case = default_case();
    case.zka_in_value = 500;
    case.amount = 500;
    emit_prover_toml(build(case));
}

#[test]
fn emit_toml_spend_zero_amount() {
    let mut case = default_case();
    case.amount = 0;
    emit_prover_toml(build(case));
}

#[test]
fn emit_toml_spend_zero_input() {
    let mut case = default_case();
    case.zka_in_value = 0;
    case.amount = 0;
    emit_prover_toml(build(case));
}
