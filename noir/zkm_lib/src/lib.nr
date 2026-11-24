// zkm_lib — shared cryptographic primitives and constraint machinery for ZKM
// circuits.
//
// Poseidon2 wrappers mirror zka_lib in ZKA.dev exactly (same dependency pin,
// same call shape), so ZKM mandate commitments hash identically across the
// ZK family. If ZKM's shared surface with ZKA/ZKC grows, extract the common
// module KDC-style instead of letting the copies drift.
//
// Beyond the wrappers this crate carries the §3 mandate artifact (commitment,
// nullifier, root_id, holder-key derivations), the two accumulator gadgets the
// §4.3 transition circuits need (the depth-32 mandate state tree and the
// depth-254 version-2 full-identifier revocation tree), and the §4.3 constraint machinery that is
// COMMON to every transition kind: holder binding, input-note reconstruction +
// membership, nullification, non-revocation, temporal validity and successor
// construction. The two bin packages — `zkm_mandate_transition` (§5
// mandate-only form, kinds 1–5) and `zkm_spend_conjoined` (the §5
// spend-conjoined form) — each add only their per-kind conservation and shape
// constraints on top, so the shared statement cannot drift between the two
// verification keys.
//
// This crate also carries the two surfaces the §5 CONJUNCTION needs and the
// mandate-only form does not: the mirrored ZKA value-note primitives and the
// ZKM Standard Policy v1 predicate. They live here rather than in
// `zkm_spend_conjoined` for the same reason as everything else in this file —
// a primitive with exactly one caller today is still the surface a second
// proof form (or a recursive `zka:bundle:v1` aggregation) will have to match
// bit for bit.
//
// The Merkle gadgets use the same Poseidon2 child-order convention as zka_lib;
// the revocation path additionally uses canonical BN254 limb decomposition.

use poseidon::poseidon2::Poseidon2;

// =============================================================================
// Domain Separators (Blake2b512-derived, canonical)
//
// Each constant = Blake2b512("ZKA-Domain-" || tag) mod BN254.Fr, interpreting
// the 64-byte digest as a LITTLE-ENDIAN integer — the exact convention of
// `src/zka-crypto/src/hash/bn254_domain.rs::domain_separator_bn254()` in
// ZKA.dev, cross-checked against the published DOMAIN_ZKA_SPENDING and
// DOMAIN_ZKA_NULLIFIER values before these were derived.
//
// TAG OWNERSHIP. Per KDC §A.4's tag-collision rule a
// referencing specification owns its own additional domain tags, so there is
// no central registration step to wait on: every `zkm/*` tag here is ZKM-OWNED
// and these are the DEFINED values, not placeholders awaiting confirmation.
// The standing obligation is collision-avoidance rather than registration —
// a new tag MUST be checked against the AFP-KDC v1.0.3 domain registry and
// against ZKA/ZKC operational tags before being added here. The KATs below
// make a silent change to any of them loud.
// =============================================================================

pub global DOMAIN_ZKM_MANDATE_COMMITMENT: Field =
    0x2b9b00feea6c9acfdfbd933453a7be3e4980badd8beb7848e28992009b74f67c;
pub global DOMAIN_ZKM_MANDATE_NULLIFIER: Field =
    0x01a0ffaffcb4824255c8db4d91656683e68cae424489fb79d76f7083fedfe053;
pub global DOMAIN_ZKM_MANDATE_NULLIFIER_KEY: Field =
    0x13434dd24dcadc2621268e80ba4628bc0d9f8154e5f272a99de4257c9ee9eafd;
pub global DOMAIN_ZKM_MANDATE_ROOT_ID: Field =
    0x0e8b2c7f9831b5cbaaddbe7b8a98cb3d6f0e570b825df5a0ed18ff82b6a29295;
pub global DOMAIN_ZKM_HOLDER_KEY: Field =
    0x12106df0c6acc17eab4e42f1f0509aeaeeaacd580cbee77327869a0fffe0ab52;
/// §3 principal issuance-key derivation. Not consumed by any bin
/// circuit — `zkm_issuance` takes the key as a witness, however derived —
/// but defined and KAT-guarded here so the §2 tag table has no undelivered
/// entries.
pub global DOMAIN_ZKM_ISSUANCE_KEY: Field =
    0x13ea79880b4f13adef0c45c92fbf65b495034c93646ac078cb076bff4afa8998;
/// §5 control-attestation lineage tag — consumed by
/// `zkm_control_attestation` via `compute_control_attestation_tag`.
pub global DOMAIN_ZKM_CONTROL_ATTESTATION: Field =
    0x2ada2ea2f52b310f53244b1b43a4227881a39cbb648f74aa7ad202588ae76301;
/// §5 disclosure-binding derivation. Like `DOMAIN_ZKM_ISSUANCE_KEY`
/// this is not an in-circuit assertion: `zkm_control_attestation` takes
/// `disclosure_binding` as an opaque public field. §5 now REQUIRES the
/// recipient to recompute it from the canonical envelope projection,
/// audience and recipient nonce; the circuit cannot check that digest. It is
/// defined and KAT-guarded here so the §2 tag table has no undelivered entries
/// and so two independent SDKs derive the same binding.
pub global DOMAIN_ZKM_DISCLOSURE_BINDING: Field =
    0x0b5325387de003d1f3d1d3c85995e287af94e7bc9a3463bc93b60605a345ec9d;
/// Binding of one verified ZKC proof to one ZKM interaction. The proof bytes
/// stay outside the circuit; their canonical digest and the registry-pinned VK
/// hash are folded into this binding.
pub global DOMAIN_ZKM_ZKC_COMPOSITION: Field =
    0x15d0455dcc699fff3399d8dcbfaf8934ca251d42b00a15425ec5d9ddf8c6606c;
/// Exact-context derivations for credential-bound issuance and spend.
pub global DOMAIN_ZKM_ZKC_ISSUANCE_CONTEXT: Field =
    0x2d558de9eeb08e860ef0fa89499b327f0a3ecb922295b2380642b066334d8e4a;
pub global DOMAIN_ZKM_ZKC_SPEND_CONTEXT: Field =
    0x187257a1677344507d757d1b9e16c6d6418cc8000257de995dd3ede77d4abbf6;

// ZKC v0.4.1 / AFP-KDC v1.0.2 constants, mirrored byte-for-byte. These are
// ZKC's published values, not ZKM-owned tags.
pub global DOMAIN_ZKC_CREDENTIAL: Field =
    0x3010b194aeae94550e7a48d065d9dc931108c2d15136704bf4ad78eae07f0e26;
pub global DOMAIN_ZKC_BINDING: Field =
    0x12b8b6de2c8fc6b63102155d15c31799845a1f360ab0df6266284bde48e3a93f;
pub global DOMAIN_ZKC_PRESENTATION_SCOPE: Field =
    0x2f7a94a38bb647d343fc7abc74b6466fe1eb566d71c185cc9537b7e768c466ae;

/// Numeric profile encodings used only inside the ZKM composition statement.
/// The ZKC envelope continues to carry the normative string discriminator.
pub global ZKC_PROFILE_ANONYMOUS: u8 = 0;
pub global ZKC_PROFILE_SCOPED: u8 = 1;
pub global ZKC_PROFILE_LINKABLE: u8 = 2;

/// Mandate state tree depth (§4.2). Matches ZKA's value-note tree depth so a
/// settlement layer can run one tree implementation for both.
pub global MANDATE_TREE_DEPTH: u32 = 32;

/// Version 2 addresses an exclusion leaf with every bit of the canonical
/// BN254 field representative, so two distinct root identifiers cannot share a
/// slot. The 254-bit depth is consensus-visible.
pub global REVOCATION_TREE_DEPTH: u32 = 254;
pub global REVOCATION_ACCUMULATOR_FULL_ID_SPARSE_V2: u8 = 2;

/// PROVISIONAL deployment delegation-depth bound (§4.3-3, §6).
///
/// This is a VERIFICATION-KEY CONSTANT, not a public input. §4.3-3 requires a
/// DELEGATE transition to assert `depth(successor) ≤ depth_max` against a
/// *deployment-disclosed* bound; a public input cannot discharge that
/// obligation, because the prover chooses public inputs and would simply
/// disclose whatever bound its own chain needs (the assertion becomes vacuous).
/// Baking the bound into the circuit means the deployment discloses it by
/// shipping the verification key (§4.3-3 / §6), and every verifier of that VK
/// enforces the same bound. CHANGING THIS VALUE IS A VERIFICATION-KEY CHANGE:
/// it forks the circuit, invalidates existing proofs, and MUST go through
/// whatever VK-governance the deployment runs.
///
/// 16 is provisional pending the §6 depth-bound registry.
pub global DEPTH_MAX: u8 = 16;

// =============================================================================
// Transition Kinds (§4.2, §6)
//
// Shared across both bin packages so the wire encoding of `kind` is identical
// whichever verification key a settlement layer is checking. `kind` is a §5
// public input in BOTH proof forms — §5 requires every proof to bind the
// transition kind — so the package split is NOT a privacy decision (the kind is
// public either way). It is a DEPLOYMENT-SAFETY decision: see the header of
// `zkm_spend_conjoined`.
// =============================================================================

pub global KIND_SPEND: u8 = 0;
pub global KIND_SPLIT: u8 = 1;
pub global KIND_RETIRE: u8 = 2;
pub global KIND_DELEGATE_FULL: u8 = 3;
pub global KIND_DELEGATE_PARTIAL: u8 = 4;
/// §6 cross-holder handoff: rebind to a new key of the SAME holder at the
/// SAME depth. Rotation is housekeeping, not delegation — it spends no depth
/// budget and is not gated by the policy's delegation permission; what it
/// shares with DELEGATE is the rebind hazard, so the §5 companion possession
/// proof is REQUIRED for it.
pub global KIND_ROTATE: u8 = 5;
pub global KIND_MAX: u8 = 5;

/// Sentinel for an unused successor slot. A real successor commitment is a
/// Poseidon2 image, so 0 is not a value an honest prover can produce — but the
/// circuits assert live successors are non-zero anyway rather than resting on
/// that probabilistic argument.
pub global NO_SUCCESSOR: Field = 0;

// =============================================================================
// Poseidon2 Hash Wrappers
// =============================================================================

/// Hash 2 field elements with Poseidon2
pub fn poseidon2(a: Field, b: Field) -> Field {
    Poseidon2::hash([a, b], 2)
}

/// Hash 3 field elements with Poseidon2
pub fn poseidon3(a: Field, b: Field, c: Field) -> Field {
    Poseidon2::hash([a, b, c], 3)
}

/// Hash 4 field elements with Poseidon2
pub fn poseidon4(a: Field, b: Field, c: Field, d: Field) -> Field {
    Poseidon2::hash([a, b, c, d], 4)
}

/// Fixed-width wrapper for the seven-element ZKC composition preimage.
pub fn poseidon7(a: Field, b: Field, c: Field, d: Field, e: Field, f: Field, g: Field) -> Field {
    Poseidon2::hash([a, b, c, d, e, f, g], 7)
}

// =============================================================================
// ZKC same-subject composition
// =============================================================================

/// KDC A.6: `cbk = H("zkc/credential", entity_seed)`.
pub fn derive_zkc_credential_binding_key(entity_seed: Field) -> Field {
    poseidon2(DOMAIN_ZKC_CREDENTIAL, entity_seed)
}

/// KDC A.6: `holderCommitment = H("zkc/binding", cbk)`.
pub fn derive_zkc_holder_commitment(entity_seed: Field) -> Field {
    poseidon2(
        DOMAIN_ZKC_BINDING,
        derive_zkc_credential_binding_key(entity_seed),
    )
}

/// ZKC v0.4 scoped presentation handle.
pub fn derive_zkc_presentation_pseudonym(entity_seed: Field, scope_id: Field) -> Field {
    assert(scope_id != 0, "scoped ZKC presentation requires a non-zero scope");
    poseidon3(
        DOMAIN_ZKC_PRESENTATION_SCOPE,
        derive_zkc_credential_binding_key(entity_seed),
        scope_id,
    )
}

/// Return the handle that a separately verified ZKC proof must expose for a
/// subject-composition companion. Anonymous v0.4 proofs deliberately expose no
/// holder-derived handle, so they cannot use this path: they require a single
/// predicate-specific circuit sharing `entity_seed` as a private wire.
pub fn derive_zkc_composable_subject_handle(
    entity_seed: Field,
    profile: u8,
    scope_id: Field,
) -> Field {
    if profile == ZKC_PROFILE_SCOPED {
        derive_zkc_presentation_pseudonym(entity_seed, scope_id)
    } else {
        assert(
            profile == ZKC_PROFILE_LINKABLE,
            "anonymous or unknown ZKC profile cannot use handle composition",
        );
        assert(scope_id == 0, "linkable ZKC presentation must not carry a scope");
        derive_zkc_holder_commitment(entity_seed)
    }
}

/// KDC entity-seed derivation of the ZKM principal issuance authority.
pub fn derive_zkm_issuance_key(entity_seed: Field) -> Field {
    poseidon2(DOMAIN_ZKM_ISSUANCE_KEY, entity_seed)
}

pub fn compute_zkc_issuance_context(cm: Field, settlement_context: Field) -> Field {
    poseidon3(DOMAIN_ZKM_ZKC_ISSUANCE_CONTEXT, cm, settlement_context)
}

pub fn compute_zkc_spend_context(
    nf: Field,
    zka_cm_recipient: Field,
    settlement_context: Field,
) -> Field {
    poseidon4(
        DOMAIN_ZKM_ZKC_SPEND_CONTEXT,
        nf,
        zka_cm_recipient,
        settlement_context,
    )
}

/// Bind the exact verified ZKC proof, registry-selected VK, active profile and
/// subject handle to the exact ZKM issuance/spend interaction context.
pub fn compute_zkc_composition_binding(
    zkc_vk_hash: Field,
    zkc_proof_digest: Field,
    proof_context: Field,
    profile: u8,
    subject_handle: Field,
    scope_id: Field,
) -> Field {
    poseidon7(
        DOMAIN_ZKM_ZKC_COMPOSITION,
        zkc_vk_hash,
        zkc_proof_digest,
        proof_context,
        profile as Field,
        subject_handle,
        scope_id,
    )
}

// =============================================================================
// The Mandate Artifact (spec §3)
//
// A mandate exists on the wire and in state only as `cm`; this struct is the
// opening, known to the holder. Field ORDER is normative — it is the hash
// preimage order of `compute_mandate_commitment`.
// =============================================================================

pub struct MandateNote {
    /// Stable identifier of the original issuance; preserved across every
    /// successor and sub-mandate, and the revocation anchor (§7.1).
    pub root_id: Field,
    /// Settlement-domain binding, committed IN THE AUTHORITY itself (§5). A
    /// mandate is issued FOR a specific settlement domain; a transition proof is
    /// only valid where `settlement_domain == ctx.settlement_context`
    /// (`verify_input_mandate`). Successors inherit it by construction, so the
    /// binding follows the whole delegation subtree. This is the AUTHORITY-level
    /// defence that stops one mandate from being witnessable — and its cap
    /// spent — on N settlement domains for N× the cap; the nullifier-preimage
    /// folding is replay hygiene layered on top, not the primary binding.
    pub settlement_domain: Field,
    /// ZKA registry asset encoding.
    pub asset_id: Field,
    /// Remaining spend authority in the asset's atomic units.
    pub remaining_cap: u128,
    /// Settlement-layer timestamp bound; MUST NOT extend across successors.
    pub expiry: u64,
    /// Hash of the versioned, published policy predicate + parameters.
    pub policy_hash: Field,
    /// The agent key authorized to consume this mandate; rebound on delegation.
    pub holder_key: Field,
    /// Delegation depth; 0 at issuance, +1 per delegation (§6).
    pub depth: u8,
    /// Commitment blinding. Fresh per successor state.
    pub randomness: Field,
}

/// `cm = H_{zkm/mandate_commitment/v1}(root_id, settlement_domain, asset_id,
/// remaining_cap, expiry, policy_hash, holder_key, depth, randomness)` (§3).
///
/// The domain separator occupies preimage slot 0, so a mandate commitment can
/// never collide with a ZKA note commitment over the same Poseidon2 instance.
/// `settlement_domain` is preimage slot 2 (right after `root_id`): binding the
/// settlement domain into the COMMITMENT — not merely into the nullifier — is
/// what makes a mandate un-witnessable on a domain it was not issued for (§5).
pub fn compute_mandate_commitment(note: MandateNote) -> Field {
    Poseidon2::hash(
        [
            DOMAIN_ZKM_MANDATE_COMMITMENT,
            note.root_id,
            note.settlement_domain,
            note.asset_id,
            note.remaining_cap as Field,
            note.expiry as Field,
            note.policy_hash,
            note.holder_key,
            note.depth as Field,
            note.randomness,
        ],
        10,
    )
}

/// `root_id = H_{zkm/mandate_root_id/v1}(principal_issuance_key,
/// issuance_randomness)` — fields in exactly that order (§3).
///
/// Hiding the principal is the point: `root_id` is public-ish (it is what the
/// revocation accumulator indexes) but reveals nothing about the issuance key
/// without `issuance_randomness`.
pub fn compute_mandate_root_id(principal_issuance_key: Field, issuance_randomness: Field) -> Field {
    poseidon3(
        DOMAIN_ZKM_MANDATE_ROOT_ID,
        principal_issuance_key,
        issuance_randomness,
    )
}

/// `lineage_tag = H_{zkm/control_attestation/v1}(root_id, settlement_context,
/// disclosure_binding)` — the §5 control-attestation public value (rev 7).
///
/// WHY A TAG AND NOT `root_id` ITSELF. A control attestation proves "I hold the
/// issuance authority behind this lineage" to a disclosure recipient. The
/// obvious way to prove that is a `zkm_revocation_auth` proof — but its public
/// vector IS the statement that authorizes revocation insertion, so handing one
/// to an auditor hands them the power to kill the lineage. Publishing this tag
/// instead of `root_id` makes the attestation VK **structurally incapable of
/// authorizing a revocation**: a settlement layer inserting into the §7.1
/// exclusion accumulator needs a public `root_id` to know what to insert, and
/// this vector does not contain one. That is the same species of argument §5
/// makes for the mandate-only VK carrying no ZKA value leg — the safety
/// property is an ABSENCE, checkable by reading the public-input count, not a
/// rule someone must remember to apply.
///
/// The recipient already knows `root_id` (the note openings in the disclosure
/// envelope contain it), `settlement_context` and `disclosure_binding` (both
/// envelope metadata), so it recomputes this tag and compares. Folding the
/// binding in makes the tag per-envelope: the same lineage attested to two
/// audiences produces two unequal tags, so a tag is not a cross-envelope
/// correlator.
///
/// WHY `settlement_context` IS IN THE PREIMAGE (added post-rev-7). It was
/// originally a bare public input of the circuit — asserted non-zero and
/// otherwise unconstrained, the same "§5 hygiene" shape `zkm_revocation_auth`
/// uses. That was sound but semantically incomplete, and the incompleteness
/// landed somewhere that mattered: §5's disclosure self-verification rule
/// tells a recipient to recompute this tag and compare, so with the context
/// outside the preimage the recipient's own check could not detect an
/// attestation presented against the wrong settlement domain. The proof binds
/// the public vector, so no forgery was possible either way — but "the
/// recipient must additionally remember to compare `settlement_context`
/// against the envelope's `metadata.context`" is exactly the kind of rule this
/// statement was designed not to need. In the preimage, the tag identifies
/// (lineage, domain, envelope) and one equality check covers all three.
pub fn compute_control_attestation_tag(
    root_id: Field,
    settlement_context: Field,
    disclosure_binding: Field,
) -> Field {
    poseidon4(
        DOMAIN_ZKM_CONTROL_ATTESTATION,
        root_id,
        settlement_context,
        disclosure_binding,
    )
}

// =============================================================================
// Holder Key Derivation (§3)
//
// holder_sk -> holder_key              = H(DOMAIN_ZKM_HOLDER_KEY, holder_sk)
// holder_sk -> holder_nullifier_secret = H(DOMAIN_ZKM_MANDATE_NULLIFIER_KEY, holder_sk)
//
// Both descend from the SAME private key. §3 requires every transition proof to
// prove the nullifier-secret derivation: without it a holder could emit
// distinct nullifiers for one `cm` under different secrets and defeat the spend
// serialization of §4.4.
// =============================================================================

/// Derive the mandate `holder_key` from the holder's private key.
pub fn derive_holder_key(holder_sk: Field) -> Field {
    poseidon2(DOMAIN_ZKM_HOLDER_KEY, holder_sk)
}

/// Derive the `holder_nullifier_secret` from the holder's private key.
pub fn derive_holder_nullifier_secret(holder_sk: Field) -> Field {
    poseidon2(DOMAIN_ZKM_MANDATE_NULLIFIER_KEY, holder_sk)
}

/// `nf = H_{zkm/mandate_nullifier/v1}(holder_nullifier_secret, cm,
/// settlement_context)` (§3), mirroring ZKA's note-nullifier shape so
/// settlement layers can enforce uniqueness with machinery they already run.
///
/// THREAT MODEL — WHAT STOPS CROSS-DOMAIN MULTIPLICATION IS THE AUTHORITY
/// BINDING, NOT THIS FOLDING. The primary defence against one mandate being
/// spent on N settlement domains for N× the cap is `settlement_domain` inside
/// the mandate COMMITMENT (`MandateNote`/`compute_mandate_commitment`), asserted
/// equal to `ctx.settlement_context` in `verify_input_mandate`: a mandate simply
/// cannot be witnessed on a domain it was not issued for, so the extra copies
/// never exist to be nullified. Folding `settlement_context` into this nullifier
/// preimage is REPLAY HYGIENE on top of that: with per-domain nullifier sets a
/// bare (unfolded) nullifier would repeat verbatim across domains, so folding
/// makes the emitted `nf` domain-separated and un-cross-postable. It is a second
/// layer, deliberately not the load-bearing one — because a nullifier binding
/// alone (with disjoint per-domain sets) would let a mandate be consumed once
/// per domain, which is exactly the cap-multiplication the AUTHORITY binding
/// prevents. Folding into the PREIMAGE (rather than merely asserting a public
/// input is non-zero) keeps this hygiene layer unremovable: the constraint
/// cannot be optimized away, because the nullifier public input is a function of
/// it. This mirrors zka_lib's `compute_context(epoch, chain_id, application_id)`
/// hygiene, and `settlement_context` is expected to be exactly such a value.
pub fn compute_mandate_nullifier(
    holder_nullifier_secret: Field,
    commitment: Field,
    settlement_context: Field,
) -> Field {
    Poseidon2::hash(
        [DOMAIN_ZKM_MANDATE_NULLIFIER, holder_nullifier_secret, commitment, settlement_context],
        4,
    )
}

// =============================================================================
// Mandate State Tree (§4.2) — depth-32 Merkle membership
//
// Copied from zka_lib::compute_merkle_root, bit order included. std::merkle was
// removed in beta.21, so the fold is explicit.
// =============================================================================

/// Compute a depth-32 Merkle root by folding `leaf` with `siblings`, selecting
/// child order from the bits of `path_index`. Poseidon2 for internal nodes.
pub fn compute_merkle_root(leaf: Field, path_index: Field, siblings: [Field; 32]) -> Field {
    // beta.20+: `to_be_bits::<N>()` returns `[bool; N]`, so no `as bool` cast
    // is needed on the elements below (it returned `[u1; N]` on older nargo).
    let index_bits: [bool; 32] = path_index.to_be_bits();
    let mut current = leaf;
    for i in 0..32 {
        let is_right = index_bits[31 - i];
        let l = if is_right { siblings[i] } else { current };
        let r = if is_right { current } else { siblings[i] };
        current = poseidon2(l, r);
    }
    current
}

// =============================================================================
// Revocation Accumulator (§7.1) — version 2 full-identifier exclusion tree
//
// Every revoked `root_id` is inserted as the value of the leaf addressed by
// all 254 bits of its canonical BN254 representative. An active lineage proves
// that its exact leaf is zero. This preserves ZKM's privacy-friendly exclusion
// polarity while making the address function injective over valid root ids.
//
// Version 1 used a depth-128 exclusion tree indexed by `low_128_bits(root_id)`.
// Its constant-zero non-membership leaf allowed two distinct identifiers to
// co-revoke when their low halves collided. Version 2 deliberately changes the
// leaf encoding, witness shape, public statement, and verification keys.
// =============================================================================

/// Prove that the exact full-identifier exclusion leaf is still empty.
pub fn assert_root_id_not_revoked(revocation_root: Field, root_id: Field, siblings: [Field; 254]) {
    assert(root_id != 0, "root_id must be non-zero");
    assert(
        compute_revocation_root(0, root_id, siblings) == revocation_root,
        "mandate root_id is revoked or the revocation path is invalid",
    );
}

/// Fold a leaf along the canonical 254-bit root-id path, least-significant bit
/// first. `bn254::decompose` supplies the unique canonical (lo, hi) limbs, so the
/// path never rests on a full-width `to_*_bits` (noir/scripts/check-field-canonicity.sh).
pub fn compute_revocation_root(leaf: Field, root_id: Field, siblings: [Field; 254]) -> Field {
    let (lo, hi) = std::field::bn254::decompose(root_id);
    let lo_bits: [bool; 128] = lo.to_be_bits();
    let hi_bits: [bool; 128] = hi.to_be_bits();
    let mut current = leaf;
    for i in 0..128 {
        let is_right = lo_bits[127 - i];
        let left = if is_right { siblings[i] } else { current };
        let right = if is_right { current } else { siblings[i] };
        current = poseidon2(left, right);
    }
    for i in 0..126 {
        let is_right = hi_bits[127 - i];
        let left = if is_right { siblings[128 + i] } else { current };
        let right = if is_right { current } else { siblings[128 + i] };
        current = poseidon2(left, right);
    }
    current
}

// =============================================================================
// Shared §4.3 Transition Machinery
//
// Everything below is common to EVERY transition kind and to BOTH proof forms,
// so it lives here rather than in either bin package: a divergence between the
// two verification keys on the input-side statement would be a protocol split
// that no test in a single package could see.
// =============================================================================

/// The public context a transition is proven against.
pub struct TransitionContext {
    /// Recent mandate state-tree root the input note is proven against (§4.3-4).
    pub mandate_root: Field,
    /// Revocation accumulator root the full-id non-membership proof is against (§4.3-5).
    ///
    /// NO EPOCH LABEL ACCOMPANIES IT. An earlier draft carried a prover-supplied
    /// `revocation_epoch` beside this root; it was removed because it was a
    /// wholly free public input — unconstrained and unconstrainable in-circuit,
    /// so a stale root could be published under a fresh epoch label, making the
    /// "stated epoch" a lie-vector. The epoch is NOT the prover's to state: the
    /// verifier MUST recognize `revocation_root` in its OWN accumulator-root
    /// history, DERIVE the root's epoch from that history, and apply the §7.2
    /// staleness window to the derived epoch — rejecting any root it cannot
    /// place. The root, not a prover-supplied label, states the epoch. A
    /// verifier that accepts a `revocation_root` it cannot locate in its own
    /// history accepts arbitrarily stale non-revocation proofs.
    pub revocation_root: Field,
    /// Public accumulator statement version. Legacy version-1 roots and
    /// witnesses are structurally incompatible and fail closed here.
    pub revocation_scheme: u8,
    /// Target-validated expiry upper bound (§4.3-6).
    ///
    /// The target authenticates now and window W, requiring now <= current_time
    /// and current_time - now <= W. This is not a lower-bound not_before clock;
    /// supporting both bounds requires a separately versioned interval artifact.
    pub current_time: u64,
    /// Settlement-domain binding (§5). Asserted equal to the mandate note's
    /// committed `settlement_domain` in `verify_input_mandate` — the AUTHORITY
    /// binding that stops cross-domain cap multiplication — AND folded into the
    /// nullifier preimage (see `compute_mandate_nullifier`) as replay hygiene.
    /// Expected to be a `compute_context(epoch, chain_id, application_id)`-style
    /// value.
    pub settlement_context: Field,
}

/// The private opening of the input mandate note plus its accumulator paths.
///
/// `holder_key` is deliberately ABSENT: it is derived from `holder_sk` inside
/// `verify_input_mandate`, never witnessed, which is what binds the note to a
/// prover who actually holds the key.
pub struct InputWitness {
    pub root_id: Field,
    /// The settlement domain the mandate was issued for. Asserted equal to
    /// `ctx.settlement_context` in `verify_input_mandate` (§5).
    pub settlement_domain: Field,
    pub asset_id: Field,
    pub remaining_cap: u128,
    pub expiry: u64,
    pub policy_hash: Field,
    pub depth: u8,
    pub randomness: Field,
    pub holder_sk: Field,
    pub merkle_path_index: Field,
    pub merkle_siblings: [Field; 32],
    pub revocation_siblings: [Field; 254],
}

/// Prove the input side of a §4.3 transition and return the reconstructed input
/// note (whose `holder_key` is the DERIVED one) together with its commitment
/// `cm_in`, which callers MUST thread into `successor_commitment` so successors
/// provably differ from the consumed note.
///
/// Enforces, in order: the zero-sentinel discipline, holder binding (§3),
/// membership at `mandate_root` (§4.3-4), the emitted nullifier (§4.3-4,
/// §4.4), non-revocation of `root_id` (§4.3-5) and temporal validity (§4.3-6).
///
/// ZERO IS RESERVED. `asset_id` and `policy_hash` are rejected at 0 because 0
/// is the "field absent" sentinel this protocol uses in its public vectors: a
/// mandate issued with `asset_id = 0` or `policy_hash = 0` would be
/// indistinguishable from an unset field to any layer that inspects those
/// publics, and in the SPEND form it would let `asset_id_pub == in_asset_id`
/// and `asset_id_pub == 0` hold simultaneously. Issuance MUST NOT mint such a
/// mandate; the circuit refuses to transition one. (`root_id != 0` is enforced
/// separately by `assert_root_id_not_revoked`, where it defends the
/// accumulator's own empty-leaf sentinel.)
pub fn verify_input_mandate(
    ctx: TransitionContext,
    w: InputWitness,
    nf: Field,
) -> (MandateNote, Field) {
    // -- Settlement-domain binding (§5) -----------------------------------
    // The AUTHORITY binding: the mandate note commits to the settlement domain
    // it was issued for, and that committed domain MUST equal the domain this
    // transition is being proven against. Without it, a single mandate note is
    // witnessable on every settlement domain that shares the mandate tree, and
    // with per-domain nullifier sets each domain consumes the cap once — one
    // authorization multiplied N-fold. The nullifier-preimage folding below is
    // replay hygiene on top of this, not a substitute for it (a nullifier
    // binding alone still admits one consumption PER domain).
    assert(ctx.settlement_context != 0, "settlement_context must be non-zero");
    assert(
        w.settlement_domain == ctx.settlement_context,
        "mandate is not issued for this settlement domain",
    );

    // -- Reserved-sentinel discipline -------------------------------------
    assert(w.asset_id != 0, "mandate asset_id must be non-zero");
    assert(w.policy_hash != 0, "mandate policy_hash must be non-zero");

    // -- Holder binding (§3) ----------------------------------------------
    // Both secrets descend from one private key, and the input note is
    // reconstructed with the DERIVED holder_key. A prover who does not hold
    // `holder_sk` cannot produce a note that is in the tree, and a prover who
    // does cannot emit a nullifier under any other secret (§4.4).
    let holder_key = derive_holder_key(w.holder_sk);
    let hns = derive_holder_nullifier_secret(w.holder_sk);

    let input = MandateNote {
        root_id: w.root_id,
        settlement_domain: w.settlement_domain,
        asset_id: w.asset_id,
        remaining_cap: w.remaining_cap,
        expiry: w.expiry,
        policy_hash: w.policy_hash,
        holder_key,
        depth: w.depth,
        randomness: w.randomness,
    };
    let cm_in = compute_mandate_commitment(input);

    // -- Membership + nullification (§4.3-4) ------------------------------
    assert(
        compute_merkle_root(cm_in, w.merkle_path_index, w.merkle_siblings) == ctx.mandate_root,
        "mandate note is not in the mandate state tree",
    );
    assert(
        nf == compute_mandate_nullifier(hns, cm_in, ctx.settlement_context),
        "mandate nullifier mismatch",
    );

    // -- Non-revocation (§4.3-5) ------------------------------------------
    // Successors preserve root_id, so this one check covers the whole
    // delegation subtree (§7.1).
    assert(
        ctx.revocation_scheme == REVOCATION_ACCUMULATOR_FULL_ID_SPARSE_V2,
        "unsupported revocation accumulator version",
    );
    assert_root_id_not_revoked(ctx.revocation_root, w.root_id, w.revocation_siblings);

    // -- Temporal validity (§4.3-6) ---------------------------------------
    assert(ctx.current_time < w.expiry, "mandate expired");

    (input, cm_in)
}

/// Build a successor commitment with an explicit successor `policy_hash`.
/// The mandate-only VK uses this form for §4.3-3 policy narrowing; this helper
/// builds the commitment, while callers with a changed policy hash MUST prove
/// the §5 relation with `assert_policy_narrows` over both policy openings.
///
/// `root_id`, `settlement_domain` and `asset_id` are inherited from `input` by
/// construction, so the prover cannot switch the issuance or asset binding.
/// `expiry` is witnessed and bounded above by the input expiry.
///
/// `cm_in` is the consumed note's commitment (from `verify_input_mandate`).
/// A successor identical to the consumed note (same fields, reused
/// randomness) would re-insert a leaf whose nullifier is already spent —
/// permanently unspendable authority — so it is rejected here, in the shared
/// helper, where no proof form can forget the check.
pub fn successor_commitment_with_policy(
    input: MandateNote,
    cm_in: Field,
    remaining_cap: u128,
    expiry: u64,
    holder_key: Field,
    depth: u8,
    randomness: Field,
    policy_hash: Field,
) -> Field {
    assert(expiry <= input.expiry, "successor expiry must not extend the input expiry");
    let cm = compute_mandate_commitment(
        MandateNote {
            root_id: input.root_id,
            settlement_domain: input.settlement_domain,
            asset_id: input.asset_id,
            remaining_cap,
            expiry,
            policy_hash,
            holder_key,
            depth,
            randomness,
        },
    );
    assert(cm != cm_in, "successor must differ from the consumed note");
    cm
}

/// Preservation form of `successor_commitment_with_policy`: the successor
/// inherits the input's `policy_hash`. The spend-conjoined VK uses only this
/// form, so it cannot silently switch policies while spending.
pub fn successor_commitment(
    input: MandateNote,
    cm_in: Field,
    remaining_cap: u128,
    expiry: u64,
    holder_key: Field,
    depth: u8,
    randomness: Field,
) -> Field {
    successor_commitment_with_policy(
        input,
        cm_in,
        remaining_cap,
        expiry,
        holder_key,
        depth,
        randomness,
        input.policy_hash,
    )
}

/// Depth of a delegated successor: `depth + 1`, bounded by the
/// VK-baked `DEPTH_MAX` (§4.3-3, §6).
///
/// The u8 addition is checked, so `depth = 255` traps on overflow rather than
/// wrapping to 0 — the spec's "≤ 255 — no u8 wrap" requirement is enforced by
/// the type. `DEPTH_MAX` is a constant, not a witness or a public input, so the
/// bound cannot be raised by the party constructing the proof.
pub fn delegated_depth(in_depth: u8) -> u8 {
    let out_depth = in_depth + 1;
    assert(out_depth <= DEPTH_MAX, "delegation depth exceeds DEPTH_MAX");
    out_depth
}

// =============================================================================
// Mirrored ZKA Value-Note Primitives (§5 conjunction)
//
// The §5 spend-conjoined proof form (`zkm_spend_conjoined`) has to evaluate the
// ZKA spend statement in the SAME circuit as the §4.3 mandate transition, so
// ZKA's value-note primitives are needed here. Everything in this section is a
// verbatim mirror of `noir/zka_lib/src/lib.nr` in the ZKA.dev repository
// — same formulas, same argument order, same Poseidon2 pin — and is therefore
// HASH-IDENTICAL to ZKA by construction, not by coincidence:
//
//   zka_lib::compute_note_commitment   -> compute_zka_note_commitment
//   zka_lib::compute_nullifier         -> compute_zka_nullifier
//   zka_lib::derive_address            -> derive_zka_address
//   zka_lib::compute_asset_commitment  -> compute_zka_asset_commitment
//
// WHY MIRROR RATHER THAN DEPEND. §1.1's "reuse by reference" is a NORMATIVE
// discipline about the protocol surface — ZKM does not redefine ZKA's note
// machinery, it uses ZKA's — but nargo has no cross-repository dependency that
// would let this workspace import `zka_lib` from ZKA.dev without vendoring it.
// The mirror is the mechanical realization of that discipline, and the KATs
// below are what keep it honest: each golden is the value ZKA's own circuits
// produce, so a drift in either repository is a test failure here rather than a
// silent cross-repo hash break that would only surface as an unspendable note.
// If this shared surface grows further, extract a common module KDC-style
// instead of letting the copies multiply.
//
// The six constants are ZKA's PUBLISHED domain separators (tags `zka/spending`,
// `zka/viewing`, `zka/proof`, `zka/address`, `zka/nullifier`, `zka/asset`), copied
// verbatim from zka_lib and KAT-asserted below. These are already-deployed values in ZKA — as of
// rev 7 the ZKM tags at the top of this file are equally non-provisional
// (§2 tag ownership), so the two sets differ in ORIGIN, not in status: those
// are ZKM-owned, these are ZKA's and must never be redefined here. A mismatch
// is a cross-repo hash break: ZKM would nullify notes ZKA cannot see and commit
// notes ZKA cannot spend.
// =============================================================================

pub global DOMAIN_ZKA_SPENDING: Field =
    0x14046af3b2a955bb4c450d1b53ffc2798acc3c2924c3519cf923146b775acc67;
pub global DOMAIN_ZKA_VIEWING: Field =
    0x041a8f7dfa88f8b20fd899a83e0bce075c65856e12e7706113f0b326a9b13eff;
pub global DOMAIN_ZKA_PROOF: Field =
    0x193befdd9db847abcc0c6412a4044f4ce9b378786241eab30fbb50b9faaad2d7;
pub global DOMAIN_ZKA_ADDRESS: Field =
    0x001b916d980f2edf145af8615825a58890f9ff48dc7c0fa92ed14fe0cd5e5fb8;
pub global DOMAIN_ZKA_NULLIFIER: Field =
    0x2e03b47965736082429061ee83eba139ece5ee1c8f30983b4d5a54ac8e18c1eb;
pub global DOMAIN_ZKA_ASSET: Field =
    0x078574d1857e778c075008cf155293bda6a75e7146a12a32692271782baf7d30;

/// ZKA value-note commitment — the canonical two-layer construction:
///   inner      = H(asset_commitment, value, recipient)
///   commitment = H(inner, randomness)
///
/// NOTE THE ABSENT DOMAIN SLOT. Unlike every ZKM hash in this file, a ZKA note
/// commitment carries no domain separator in slot 0; the separation comes from
/// `asset_commitment`, which is itself domain-tagged. That is zka_lib's
/// convention and it is reproduced exactly — adding a slot here would produce
/// commitments ZKA's tree does not recognize.
pub fn compute_zka_note_commitment(
    asset_commitment: Field,
    value: Field,
    recipient: Field,
    randomness: Field,
) -> Field {
    let inner = poseidon3(asset_commitment, value, recipient);
    poseidon2(inner, randomness)
}

/// ZKA value-note nullifier — two-step:
///   intermediate = H(DOMAIN_ZKA_NULLIFIER, commitment)
///   nullifier    = H(intermediate, spending_key)
///
/// The ZKA spending key IS the nullifier key (no separate derivation), which is
/// what lets the conjoined circuit use one `holder_sk` for both legs: the same
/// secret that derives the mandate's `holder_key` spends the value note.
pub fn compute_zka_nullifier(commitment: Field, spending_key: Field) -> Field {
    let intermediate = poseidon2(DOMAIN_ZKA_NULLIFIER, commitment);
    poseidon2(intermediate, spending_key)
}

/// ZKA spending key from the KDC-reduced master seed.
pub fn derive_zka_spending_key(master_seed: Field) -> Field {
    poseidon2(DOMAIN_ZKA_SPENDING, master_seed)
}

/// ZKA viewing key from a spending key.
pub fn derive_zka_viewing_key(spending_key: Field) -> Field {
    poseidon2(DOMAIN_ZKA_VIEWING, spending_key)
}

/// ZKA proof-authorizing key from a spending key.
pub fn derive_zka_proof_key(spending_key: Field) -> Field {
    poseidon2(DOMAIN_ZKA_PROOF, spending_key)
}

/// ZKA address from a spending key, retaining the existing API's input semantics.
pub fn derive_zka_address(spending_key: Field) -> Field {
    poseidon2(DOMAIN_ZKA_ADDRESS, derive_zka_viewing_key(spending_key))
}

/// ZKA asset commitment from a registry asset id (§3's `asset_id`).
pub fn compute_zka_asset_commitment(asset_id: Field) -> Field {
    poseidon2(DOMAIN_ZKA_ASSET, asset_id)
}

// =============================================================================
// ZKM Standard Policy v1 (§5 policy predicate)
//
// §5 requires the authorization proof to evaluate the policy predicate and to
// establish that "the policy circuit and parameters actually evaluated hash to
// the `policy_hash` committed in `M` — a proof against any other policy MUST
// NOT verify". A `policy_hash` with no predicate behind it discharges neither
// half of that: this section is the first CONCRETE policy schema, so the
// obligation becomes real rather than aspirational.
//
// The schema is deliberately small — a per-spend ceiling and an optional
// recipient allowlist — because its purpose is to make the CONJUNCTION real,
// not to be an expressive policy language. Richer predicates are future
// versions; `version` is in the hash preimage precisely so a v2 schema cannot
// be replayed against a v1 commitment (and vice versa).
//
// SAFEGUARD 4 (§1.2). This predicate is published, inspectable, versioned Noir
// source, as every ZKM policy predicate MUST be. An SDK MUST refuse by default
// to prove against a policy predicate the agent cannot inspect; a mandate whose
// `policy_hash` opens to no published predicate is exactly such a case.
// =============================================================================

/// ZKM-owned tag `zkm/policy/v1` (§2 tag ownership, settled in rev 5).
/// Derived with the same convention as the ZKM tags at the top of this file:
/// `Blake2b512("ZKA-Domain-" || tag) mod BN254.Fr`, little-endian reduction.
pub global DOMAIN_ZKM_POLICY: Field =
    0x21924384b009ec6f6d4fa4058a6282081978d6e026ee2ac3d720470ab2e0ba06;

/// Standard Policy schema versions. A mandate committing to any OTHER version
/// is refused rather than evaluated under either schema's semantics.
///
/// V1 SEMANTIC FOR DELEGATION (normative, §5): a v1 policy carries no
/// delegation parameter and PERMITS delegation, bounded only by the VK-baked
/// `DEPTH_MAX`. A principal that wants per-mandate delegation control issues
/// under v2, whose `depth_limit` gates it (0 = no delegation at all).
pub global POLICY_VERSION_V1: Field = 1;
pub global POLICY_VERSION_V2: Field = 2;

/// Depth of the policy recipient-allowlist Merkle tree. Deliberately shallower
/// than the state trees: an allowlist is a policy-scale set (≤ 65 536 entries),
/// not a chain-scale one, and every restricted spend pays for the depth.
pub global RECIPIENT_SET_DEPTH: u32 = 16;

/// The opening of a `policy_hash` under ZKM Standard Policy v1.
///
/// Field ORDER is normative — it is the preimage order of
/// `compute_policy_hash`.
pub struct StandardPolicyV1 {
    /// Schema version; MUST be `POLICY_VERSION_V1` for this predicate.
    pub version: Field,
    /// Per-spend ceiling in the asset's atomic units. Independent of the
    /// mandate's `remaining_cap`: the cap bounds TOTAL authority, this bounds
    /// each individual spend.
    pub max_per_spend: u128,
    /// Boolean (asserted): 1 restricts spends to `recipient_set_root`'s
    /// members, 0 permits any recipient.
    pub recipient_restricted: Field,
    /// Depth-16 Merkle root over permitted recipient ZKA addresses. Meaningful
    /// only when `recipient_restricted == 1`.
    pub recipient_set_root: Field,
    /// Per-mandate blinding of the policy hash. Every OTHER field of this schema
    /// is low-entropy — `version` is a small constant, `recipient_restricted` is
    /// a bit, `max_per_spend` ranges over a dictionary an observer can
    /// enumerate, and an unrestricted policy's `recipient_set_root` is 0 — so a
    /// `policy_hash` published in the clear is BOTH brute-forceable back to its
    /// parameters (a small dictionary recovers `max_per_spend`) AND a stable
    /// per-policy lineage identifier that links every spend of one mandate
    /// (§4.6 breach). A fresh, high-entropy `policy_blinding` in the preimage
    /// closes both: the hash reveals nothing about the parameters and is not a
    /// cross-spend correlator. MUST be non-zero (a zero blinding is the
    /// unblinded footgun) and sampled uniformly per mandate.
    pub policy_blinding: Field,
}

/// `policy_hash = H_{zkm/policy/v1}(version, max_per_spend,
/// recipient_restricted, recipient_set_root, policy_blinding)`.
///
/// The domain separator occupies preimage slot 0, so a policy hash can never
/// collide with a mandate commitment or a ZKA note over the same Poseidon2
/// instance. EVERY parameter is in the preimage — that is what makes §5's "a
/// proof against any other policy MUST NOT verify" hold for a parameterized
/// schema: changing `max_per_spend` or the allowlist root is a different
/// `policy_hash`, hence a different mandate. `policy_blinding` is the LAST
/// preimage slot: the low-entropy parameters alone would make the published
/// hash both dictionary-invertible and a cross-spend lineage identifier, so the
/// blinding is what actually hides them (see `StandardPolicyV1`).
pub fn compute_policy_hash(policy: StandardPolicyV1) -> Field {
    Poseidon2::hash(
        [
            DOMAIN_ZKM_POLICY,
            policy.version,
            policy.max_per_spend as Field,
            policy.recipient_restricted,
            policy.recipient_set_root,
            policy.policy_blinding,
        ],
        6,
    )
}

/// The opening of a `policy_hash` under ZKM Standard Policy v2 (§5): v1 plus a
/// per-mandate delegation depth limit.
///
/// Field ORDER is normative — it is the preimage order of
/// `compute_policy_hash_v2`. `depth_limit` sits BEFORE the blinding so the
/// blinding stays the last preimage slot in every schema version.
///
/// This struct is also the version-agnostic CARRIER for the versioned
/// predicates below: a v1 opening rides in it with `depth_limit == 0`
/// (asserted, so the extra slot can never be a free scratch witness).
pub struct StandardPolicyV2 {
    /// Schema version; `POLICY_VERSION_V1` or `POLICY_VERSION_V2` for the
    /// versioned predicates below.
    pub version: Field,
    pub max_per_spend: u128,
    pub recipient_restricted: Field,
    pub recipient_set_root: Field,
    /// Per-mandate delegation depth ceiling (§6): a DELEGATE transition's
    /// successor depth MUST be <= `depth_limit`. 0 forbids delegation
    /// entirely (a delegated successor's depth is always >= 1). Independent
    /// of the VK-baked `DEPTH_MAX`, which still applies: the effective bound
    /// is the tighter of the two. Meaningful only under v2.
    pub depth_limit: u8,
    /// Per-mandate blinding — same §4.6 role and same MUST-be-non-zero rule
    /// as v1's (see `StandardPolicyV1.policy_blinding`).
    pub policy_blinding: Field,
}

/// `policy_hash = H_{zkm/policy/v1}(version, max_per_spend,
/// recipient_restricted, recipient_set_root, depth_limit, policy_blinding)`.
///
/// SEVEN preimage slots against v1's six: the two schemas can never collide
/// even before the `version` field is compared, because the Poseidon2 sponge
/// is length-domain-separated. Same `zkm/policy/v1` domain tag — the tag names
/// the POLICY HASH construction; `version` (in the preimage) names the schema.
pub fn compute_policy_hash_v2(policy: StandardPolicyV2) -> Field {
    Poseidon2::hash(
        [
            DOMAIN_ZKM_POLICY,
            policy.version,
            policy.max_per_spend as Field,
            policy.recipient_restricted,
            policy.recipient_set_root,
            policy.depth_limit as Field,
            policy.policy_blinding,
        ],
        7,
    )
}

/// Open a policy carrier against a committed `policy_hash` under whichever
/// schema version it declares. The ONE place version dispatch happens: both
/// bin circuits call this, so "a proof against any other policy MUST NOT
/// verify" (§5) has a single implementation.
///
/// For v1 the carrier's `depth_limit` slot MUST be zero — it is not part of
/// the v1 preimage, so without the assertion it would be a free,
/// unconstrained scratch witness (house rule: no meaningless malleable
/// witnesses).
pub fn assert_policy_opens(policy: StandardPolicyV2, committed_policy_hash: Field) {
    // A zero blinding is the unblinded footgun in every schema version (§4.6).
    assert(policy.policy_blinding != 0, "policy blinding must be non-zero");
    assert(
        (policy.version == POLICY_VERSION_V1) | (policy.version == POLICY_VERSION_V2),
        "unsupported policy version",
    );
    if policy.version == POLICY_VERSION_V1 {
        assert(policy.depth_limit == 0, "v1 policy must carry a zero depth_limit witness");
        let v1 = StandardPolicyV1 {
            version: policy.version,
            max_per_spend: policy.max_per_spend,
            recipient_restricted: policy.recipient_restricted,
            recipient_set_root: policy.recipient_set_root,
            policy_blinding: policy.policy_blinding,
        };
        assert(compute_policy_hash(v1) == committed_policy_hash, "policy opening mismatch");
    } else {
        assert(compute_policy_hash_v2(policy) == committed_policy_hash, "policy opening mismatch");
    }
}

/// §6 delegation gate: open the mandate's committed policy and assert it
/// permits a delegation whose successor lands at `successor_depth`.
///
/// v1: permitted unconditionally (the documented v1 semantic — see
/// `POLICY_VERSION_V1`); the VK-baked `DEPTH_MAX` is still enforced by
/// `delegated_depth`. v2: `successor_depth <= depth_limit`, so
/// `depth_limit = 0` forbids delegation outright.
pub fn assert_policy_permits_delegation(
    policy: StandardPolicyV2,
    committed_policy_hash: Field,
    successor_depth: u8,
) {
    assert_policy_opens(policy, committed_policy_hash);
    if policy.version == POLICY_VERSION_V2 {
        assert(successor_depth <= policy.depth_limit, "delegation exceeds the policy depth limit");
    }
}

/// §5 narrowing registry v1, in-circuit: assert that `to` narrows `from`.
///
/// Both carriers MUST already be opened against their committed hashes by
/// the caller (`assert_policy_opens`) — this function asserts only the
/// RELATION. Registry v1 rules, in order: no schema downgrade (v2 -> v1
/// would widen delegation); the per-spend ceiling may only tighten; the
/// recipient restriction is monotone (0 -> 1 only) and a restricted target
/// keeps the SAME set root (set shrinking needs subset proofs, deliberately
/// excluded from registry v1); the v2 depth limit may only tighten; and the
/// narrowed policy carries FRESH blinding (reuse would link the two policies
/// if either opening is ever disclosed).
pub fn assert_policy_narrows(from: StandardPolicyV2, to: StandardPolicyV2) {
    assert(
        !((from.version == POLICY_VERSION_V2) & (to.version == POLICY_VERSION_V1)),
        "narrowing may not downgrade the policy schema version",
    );
    assert(to.max_per_spend <= from.max_per_spend, "narrowing may not raise max_per_spend");
    // Booleanity of both selectors is asserted HERE because
    // `assert_policy_opens` does not: a non-boolean selector would dodge the
    // monotonicity relation below.
    assert(
        from.recipient_restricted * (from.recipient_restricted - 1) == 0,
        "recipient_restricted must be boolean",
    );
    assert(
        to.recipient_restricted * (to.recipient_restricted - 1) == 0,
        "recipient_restricted must be boolean",
    );
    assert(
        from.recipient_restricted * (from.recipient_restricted - to.recipient_restricted) == 0,
        "narrowing may not lift a recipient restriction",
    );
    if to.recipient_restricted == 1 {
        assert(
            to.recipient_set_root != 0,
            "restricted policy must carry a non-zero recipient set root",
        );
        if from.recipient_restricted == 1 {
            assert(
                to.recipient_set_root == from.recipient_set_root,
                "narrowing may not change a restricted recipient set",
            );
        }
    }
    if (from.version == POLICY_VERSION_V2) & (to.version == POLICY_VERSION_V2) {
        assert(to.depth_limit <= from.depth_limit, "narrowing may not raise the depth limit");
    }
    assert(to.policy_blinding != from.policy_blinding, "narrowed policy must carry fresh blinding");
}

/// Depth-16 Merkle root for the policy recipient set. Identical fold to
/// `compute_merkle_root` (same child-order convention, same Poseidon2 internal
/// nodes), at a different height — so allowlist witnesses are built by the same
/// tooling as state-tree witnesses.
///
/// `path_index` is implicitly range-checked to 16 bits by the decomposition
/// below: an index at or above 2^16 is not a position in this tree and traps.
pub fn compute_merkle_root_16(leaf: Field, path_index: Field, siblings: [Field; 16]) -> Field {
    let index_bits: [bool; 16] = path_index.to_be_bits();
    let mut current = leaf;
    for i in 0..16 {
        let is_right = index_bits[15 - i];
        let l = if is_right { siblings[i] } else { current };
        let r = if is_right { current } else { siblings[i] };
        current = poseidon2(l, r);
    }
    current
}

/// Evaluate ZKM Standard Policy (v1 or v2) against a spend, and prove the
/// evaluated parameters are the ones the mandate committed to (§5). The
/// carrier is `StandardPolicyV2`; a v1 opening rides in it with
/// `depth_limit == 0` (asserted in `assert_policy_opens`).
///
/// The FIRST assertion is the one §5 actually demands: the policy opening must
/// hash to the mandate's `policy_hash`. Without it the remaining checks are
/// theatre — a prover would simply supply a permissive policy. With it, the
/// predicate evaluated is provably the predicate the principal authorized.
///
/// The MEMBERSHIP constraint is borne only when restricted, and so — MEASURED,
/// not assumed — is the depth-16 fold's `to_be_bits::<16>()` range check on the
/// path index. It is NOT emitted unconditionally: with the assertion below
/// removed, an unrestricted policy carrying a 2^20 path index executes, PROVES
/// and VERIFIES under nargo 1.0.0-beta.25 + bb 5.0.0. The
/// control holds in the other direction: with the branch TAKEN (restricted),
/// the same index traps during execution. So the decomposition is predicated
/// along with the rest of the branch.
///
/// The assertion below therefore stays for the reason that DOES hold: it denies
/// the prover a free, unconstrained scratch witness and removes the malleability
/// of a meaningless one. Do NOT weaken it on the theory that proof generation
/// would catch an out-of-range dummy index — it does not. The mandate — not the
/// prover — chooses the branch, because `recipient_restricted` is inside the
/// hashed preimage.
pub fn assert_policy_permits_spend(
    policy: StandardPolicyV2,
    committed_policy_hash: Field,
    amount: u128,
    recipient_address: Field,
    recipient_set_path_index: Field,
    recipient_set_siblings: [Field; 16],
) {
    // -- §5: the evaluated policy IS the committed policy -------------------
    // Version-dispatched opening (v1 or v2 — the SPEND semantics of the two
    // schemas are identical; v2's `depth_limit` is a DELEGATION parameter and
    // is not consulted here). Includes blinding well-formedness and version
    // admissibility.
    assert_policy_opens(policy, committed_policy_hash);

    // -- Per-spend ceiling ---------------------------------------------------
    assert(amount <= policy.max_per_spend, "spend exceeds policy max_per_spend");

    // -- Booleanity of the branch selector -----------------------------------
    // A non-boolean selector would take neither branch: `recipient_restricted =
    // 2` would sail past a bare `if == 1` with the allowlist unenforced, while
    // still hashing to a policy_hash the principal signed believing it
    // restricted. The algebraic form is used rather than `== 0 | == 1` so the
    // constraint is a single degree-2 relation.
    assert(
        policy.recipient_restricted * (policy.recipient_restricted - 1) == 0,
        "recipient_restricted must be boolean",
    );

    // -- Recipient allowlist (restricted policies only) ----------------------
    if policy.recipient_restricted == 1 {
        // An empty/absent root would otherwise let a restricted policy be
        // satisfied by a path that folds to 0 — restriction in name only.
        assert(
            policy.recipient_set_root != 0,
            "restricted policy must carry a non-zero recipient set root",
        );
        assert(
            compute_merkle_root_16(
                recipient_address,
                recipient_set_path_index,
                recipient_set_siblings,
            )
                == policy.recipient_set_root,
            "recipient not in the policy recipient set",
        );
    } else {
        // Unrestricted: force the dummy witness to canonical zero. This does
        // NOT make the depth-16 range check unconditional -- see this
        // function's doc comment above for the measured claim about what
        // proving time does and does not catch. What it DOES do: it denies
        // the prover a free, unconstrained scratch witness and removes the
        // malleability of a meaningless one.
        assert(
            recipient_set_path_index == 0,
            "unrestricted policy must carry a zero allowlist path index",
        );
        for i in 0..RECIPIENT_SET_DEPTH {
            assert(
                recipient_set_siblings[i] == 0,
                "unrestricted policy must carry zero allowlist siblings",
            );
        }
    }
}

// =============================================================================
// Witness-Construction Helpers
//
// Not used by any circuit: exported so deployments (and both packages' tests)
// build accumulator witnesses with the exact construction the gadgets verify,
// rather than re-deriving the empty-subtree ladder per call site.
// =============================================================================

/// Sibling path of an all-empty depth-32 mandate state tree (level `d`'s
/// sibling is the empty subtree root at level `d`), so a note at index 0 is the
/// tree's only leaf.
pub fn empty_merkle_siblings() -> [Field; 32] {
    let mut siblings = [0; 32];
    let mut empty: Field = 0;
    for depth in 0..32 {
        siblings[depth] = empty;
        empty = poseidon2(empty, empty);
    }
    siblings
}

/// Sibling path of an all-empty depth-16 policy recipient set, so a single
/// allowlisted address at index 0 is the set's only member.
pub fn empty_recipient_set_siblings() -> [Field; 16] {
    let mut siblings = [0; 16];
    let mut empty: Field = 0;
    for depth in 0..16 {
        siblings[depth] = empty;
        empty = poseidon2(empty, empty);
    }
    siblings
}

/// Sibling path of an all-empty depth-254 revocation accumulator.
pub fn empty_revocation_siblings() -> [Field; 254] {
    let mut siblings = [0; 254];
    let mut empty: Field = 0;
    for depth in 0..254 {
        siblings[depth] = empty;
        empty = poseidon2(empty, empty);
    }
    siblings
}

// =============================================================================
// Behavioural Tests
// =============================================================================

#[test]
fn test_domain_separators_all_unique() {
    let domains = [
        DOMAIN_ZKM_MANDATE_COMMITMENT,
        DOMAIN_ZKM_MANDATE_NULLIFIER,
        DOMAIN_ZKM_MANDATE_NULLIFIER_KEY,
        DOMAIN_ZKM_MANDATE_ROOT_ID,
        DOMAIN_ZKM_HOLDER_KEY,
        DOMAIN_ZKM_ISSUANCE_KEY,
        DOMAIN_ZKM_CONTROL_ATTESTATION,
        DOMAIN_ZKM_DISCLOSURE_BINDING,
        DOMAIN_ZKM_ZKC_COMPOSITION,
        DOMAIN_ZKM_ZKC_ISSUANCE_CONTEXT,
        DOMAIN_ZKM_ZKC_SPEND_CONTEXT,
    ];
    for i in 0..11 {
        for j in (i + 1)..11 {
            assert(domains[i] != domains[j], "Domain separators must be unique");
        }
    }
}

#[test]
fn test_domain_separators_nonzero() {
    assert(DOMAIN_ZKM_MANDATE_COMMITMENT != 0, "mandate commitment domain must be nonzero");
    assert(DOMAIN_ZKM_MANDATE_NULLIFIER != 0, "mandate nullifier domain must be nonzero");
    assert(DOMAIN_ZKM_MANDATE_NULLIFIER_KEY != 0, "nullifier key domain must be nonzero");
    assert(DOMAIN_ZKM_MANDATE_ROOT_ID != 0, "root_id domain must be nonzero");
    assert(DOMAIN_ZKM_HOLDER_KEY != 0, "holder key domain must be nonzero");
    assert(DOMAIN_ZKM_ISSUANCE_KEY != 0, "issuance key domain must be nonzero");
    assert(DOMAIN_ZKM_CONTROL_ATTESTATION != 0, "control attestation domain must be nonzero");
    assert(DOMAIN_ZKM_DISCLOSURE_BINDING != 0, "disclosure binding domain must be nonzero");
    assert(DOMAIN_ZKM_ZKC_COMPOSITION != 0, "ZKC composition domain must be nonzero");
    assert(DOMAIN_ZKM_ZKC_ISSUANCE_CONTEXT != 0, "ZKC issuance context domain must be nonzero");
    assert(DOMAIN_ZKM_ZKC_SPEND_CONTEXT != 0, "ZKC spend context domain must be nonzero");
}

#[test]
fn test_transition_kinds_are_distinct_and_bounded() {
    let kinds = [
        KIND_SPEND,
        KIND_SPLIT,
        KIND_RETIRE,
        KIND_DELEGATE_FULL,
        KIND_DELEGATE_PARTIAL,
        KIND_ROTATE,
    ];
    for i in 0..6 {
        assert(kinds[i] <= KIND_MAX, "every kind must be within KIND_MAX");
        for j in (i + 1)..6 {
            assert(kinds[i] != kinds[j], "transition kinds must be distinct");
        }
    }
}

fn sample_note() -> MandateNote {
    MandateNote {
        root_id: 11,
        settlement_domain: 88,
        asset_id: 7,
        remaining_cap: 1000,
        expiry: 2000,
        policy_hash: 33,
        holder_key: 44,
        depth: 0,
        randomness: 555,
    }
}

#[test]
fn test_mandate_commitment_deterministic() {
    assert(
        compute_mandate_commitment(sample_note()) == compute_mandate_commitment(sample_note()),
        "Mandate commitment must be deterministic",
    );
}

#[test]
fn test_mandate_commitment_binds_every_field() {
    let base = compute_mandate_commitment(sample_note());

    let mut n = sample_note();
    n.root_id = 12;
    assert(compute_mandate_commitment(n) != base, "root_id must bind");

    n = sample_note();
    n.settlement_domain = 89;
    assert(compute_mandate_commitment(n) != base, "settlement_domain must bind");

    n = sample_note();
    n.asset_id = 8;
    assert(compute_mandate_commitment(n) != base, "asset_id must bind");

    n = sample_note();
    n.remaining_cap = 999;
    assert(compute_mandate_commitment(n) != base, "remaining_cap must bind");

    n = sample_note();
    n.expiry = 1999;
    assert(compute_mandate_commitment(n) != base, "expiry must bind");

    n = sample_note();
    n.policy_hash = 34;
    assert(compute_mandate_commitment(n) != base, "policy_hash must bind");

    n = sample_note();
    n.holder_key = 45;
    assert(compute_mandate_commitment(n) != base, "holder_key must bind");

    n = sample_note();
    n.depth = 1;
    assert(compute_mandate_commitment(n) != base, "depth must bind");

    n = sample_note();
    n.randomness = 556;
    assert(compute_mandate_commitment(n) != base, "randomness must bind");
}

#[test]
fn test_holder_key_hierarchy_all_distinct() {
    let sk: Field = 42;
    let hk = derive_holder_key(sk);
    let hns = derive_holder_nullifier_secret(sk);
    assert(sk != hk, "sk != holder_key");
    assert(sk != hns, "sk != holder_nullifier_secret");
    assert(hk != hns, "holder_key != holder_nullifier_secret");
}

#[test]
fn test_holder_derivations_separate_keys() {
    assert(derive_holder_key(42) != derive_holder_key(43), "distinct sk => distinct holder_key");
    assert(
        derive_holder_nullifier_secret(42) != derive_holder_nullifier_secret(43),
        "distinct sk => distinct nullifier secret",
    );
}

#[test]
fn test_mandate_nullifier_binds_secret_commitment_and_context() {
    let base = compute_mandate_nullifier(7, 9, 5);
    assert(compute_mandate_nullifier(8, 9, 5) != base, "nullifier must bind the secret");
    assert(compute_mandate_nullifier(7, 10, 5) != base, "nullifier must bind the commitment");
    // The cross-domain replay defence: the SAME note under a different
    // settlement context is a DIFFERENT nullifier, so a transition proven for
    // one target does not carry to another.
    assert(
        compute_mandate_nullifier(7, 9, 6) != base,
        "nullifier must bind the settlement context",
    );
    assert(compute_mandate_nullifier(0, 0, 0) != 0, "domain separation keeps nf nonzero");
}

#[test]
fn test_root_id_binds_issuance_inputs() {
    let base = compute_mandate_root_id(991, 13);
    assert(compute_mandate_root_id(992, 13) != base, "issuance key must bind");
    assert(compute_mandate_root_id(991, 14) != base, "issuance randomness must bind");
    // Argument order is normative: swapping the two must not collide.
    assert(compute_mandate_root_id(13, 991) != base, "argument order is normative");
}

#[test]
fn test_merkle_root_child_order_matters() {
    let mut siblings = [0; 32];
    siblings[0] = 7;
    assert(
        compute_merkle_root(42, 1, siblings) != compute_merkle_root(42, 0, siblings),
        "Child order must affect the root (left vs right placement)",
    );
    assert(
        compute_merkle_root(42, 0, siblings) != compute_merkle_root(43, 0, siblings),
        "Different leaves must produce different roots",
    );
}

#[test]
fn test_empty_revocation_tree_accepts_full_root_id_path() {
    let siblings = empty_revocation_siblings();
    let root_id: Field = 0x2a3f00000000000000000000000000ff;
    let root = compute_revocation_root(0, root_id, siblings);
    assert_root_id_not_revoked(root, root_id, siblings);
}

// Cross-language KAT shared with `scripts/migrate-revocation-v2.py`: one
// revoked full identifier exercises the leaf encoding, LSB-first path order,
// and every level of the depth-254 fold (the empty-root KAT cannot distinguish
// path conventions).
#[test]
fn kat_revocation_root_v2_single_root_id_7() {
    let siblings = empty_revocation_siblings();
    assert(
        compute_revocation_root(7, 7, siblings)
            == 0x2d034b66ce121eb3eb86ae45a4c959a68c77c01d71f3f43bbe205fe3ddbd588b,
        "version-2 single-revocation root KAT mismatch",
    );
}

#[test(should_fail_with = "root_id must be non-zero")]
fn test_zero_root_id_rejected() {
    let siblings = empty_revocation_siblings();
    let root = compute_revocation_root(0, 1, siblings);
    assert_root_id_not_revoked(root, 0, siblings);
}

#[test(should_fail_with = "mandate root_id is revoked or the revocation path is invalid")]
fn test_revoked_root_id_rejected() {
    let siblings = empty_revocation_siblings();
    let root = compute_revocation_root(1, 1, siblings);
    assert_root_id_not_revoked(root, 1, siblings);
}

#[test]
fn test_low_128_collision_does_not_co_revoke() {
    let low: Field = 7;
    let high_collision: Field = 0x0000000000000000000000000000000100000000000000000000000000000007;
    let empty = empty_revocation_siblings();
    let root_after_low_revocation = compute_revocation_root(low, low, empty);
    let mut high_siblings = empty;
    let mut low_subtree = low;
    let (low_limb, _high_limb) = std::field::bn254::decompose(low);
    let low_bits: [bool; 128] = low_limb.to_be_bits();
    for i in 0..128 {
        let is_right = low_bits[127 - i];
        let left = if is_right { empty[i] } else { low_subtree };
        let right = if is_right { low_subtree } else { empty[i] };
        low_subtree = poseidon2(left, right);
    }
    high_siblings[128] = low_subtree;

    // Version 1 mapped both values to slot 7. Version 2 diverges at bit 128,
    // so the high identifier still proves an empty exact leaf.
    assert_root_id_not_revoked(root_after_low_revocation, high_collision, high_siblings);
    assert(low != high_collision, "collision fixture identifiers must differ");
}

#[test]
fn test_delegated_depth_increments_up_to_the_bound() {
    assert(delegated_depth(0) == 1, "depth must increment by one");
    assert(delegated_depth(DEPTH_MAX - 1) == DEPTH_MAX, "DEPTH_MAX - 1 is the last legal input");
}

#[test(should_fail_with = "delegation depth exceeds DEPTH_MAX")]
fn test_delegated_depth_rejects_the_bound_itself() {
    let _ = delegated_depth(DEPTH_MAX);
}

// -----------------------------------------------------------------------------
// Mirrored ZKA value-note primitives
// -----------------------------------------------------------------------------

#[test]
fn test_all_domain_separators_unique_across_families() {
    // ZKM's own tags, ZKA's mirrored tags and the policy tag share one
    // Poseidon2 instance, so a collision anywhere in this set would let one
    // family's preimage masquerade as another's.
    let domains = [
        DOMAIN_ZKM_MANDATE_COMMITMENT,
        DOMAIN_ZKM_MANDATE_NULLIFIER,
        DOMAIN_ZKM_MANDATE_NULLIFIER_KEY,
        DOMAIN_ZKM_MANDATE_ROOT_ID,
        DOMAIN_ZKM_HOLDER_KEY,
        DOMAIN_ZKM_POLICY,
        DOMAIN_ZKA_SPENDING,
        DOMAIN_ZKA_VIEWING,
        DOMAIN_ZKA_PROOF,
        DOMAIN_ZKA_ADDRESS,
        DOMAIN_ZKA_NULLIFIER,
        DOMAIN_ZKA_ASSET,
        DOMAIN_ZKC_CREDENTIAL,
        DOMAIN_ZKC_BINDING,
        DOMAIN_ZKC_PRESENTATION_SCOPE,
        DOMAIN_ZKM_ZKC_COMPOSITION,
        DOMAIN_ZKM_ZKC_ISSUANCE_CONTEXT,
        DOMAIN_ZKM_ZKC_SPEND_CONTEXT,
    ];
    for i in 0..16 {
        assert(domains[i] != 0, "no domain separator may be zero");
        for j in (i + 1)..16 {
            assert(domains[i] != domains[j], "domain separators must be unique");
        }
    }
}

#[test]
fn test_zka_note_commitment_binds_every_field() {
    let asset = compute_zka_asset_commitment(7);
    let base = compute_zka_note_commitment(asset, 100, 9, 555);
    assert(
        compute_zka_note_commitment(compute_zka_asset_commitment(8), 100, 9, 555) != base,
        "asset must bind",
    );
    assert(compute_zka_note_commitment(asset, 101, 9, 555) != base, "value must bind");
    assert(compute_zka_note_commitment(asset, 100, 10, 555) != base, "recipient must bind");
    assert(compute_zka_note_commitment(asset, 100, 9, 556) != base, "randomness must bind");
}

#[test]
fn test_zka_nullifier_binds_commitment_and_key() {
    let base = compute_zka_nullifier(9, 4242);
    assert(compute_zka_nullifier(10, 4242) != base, "nullifier must bind the commitment");
    assert(compute_zka_nullifier(9, 4243) != base, "nullifier must bind the spending key");
    // Two notes spent by one key must not collide, and one note under two keys
    // must not either — both are how a value note gets double-spent.
    assert(compute_zka_nullifier(0, 0) != 0, "domain separation keeps the nullifier nonzero");
}

#[test]
fn test_zka_address_derivation_separates_keys() {
    let sk: Field = 4242;
    let addr = derive_zka_address(sk);
    assert(addr != sk, "address must not be the spending key");
    assert(derive_zka_address(4243) != addr, "distinct sk => distinct address");
    // The ZKA address and the ZKM holder key descend from the SAME secret in
    // the conjoined circuit, so they must be distinct values — otherwise a
    // mandate holder key would be usable as a ZKA address.
    assert(derive_holder_key(sk) != addr, "holder_key and zka address must differ");
}

#[test]
fn test_zka_asset_commitment_separates_assets() {
    assert(
        compute_zka_asset_commitment(7) != compute_zka_asset_commitment(8),
        "distinct asset ids must commit distinctly",
    );
    assert(compute_zka_asset_commitment(0) != 0, "asset commitment of 0 is not 0");
}

// -----------------------------------------------------------------------------
// ZKM Standard Policy (v1 + v2)
// -----------------------------------------------------------------------------

global KAT_POLICY_BLINDING: Field = 0x9e2b_77a1;

/// Tests build the version-agnostic CARRIER; v1 rides with depth_limit 0.
fn unrestricted_policy(max_per_spend: u128) -> StandardPolicyV2 {
    StandardPolicyV2 {
        version: POLICY_VERSION_V1,
        max_per_spend,
        recipient_restricted: 0,
        recipient_set_root: 0,
        depth_limit: 0,
        policy_blinding: KAT_POLICY_BLINDING,
    }
}

fn unrestricted_policy_v2(max_per_spend: u128, depth_limit: u8) -> StandardPolicyV2 {
    StandardPolicyV2 {
        version: POLICY_VERSION_V2,
        max_per_spend,
        recipient_restricted: 0,
        recipient_set_root: 0,
        depth_limit,
        policy_blinding: KAT_POLICY_BLINDING,
    }
}

fn v1_view(p: StandardPolicyV2) -> StandardPolicyV1 {
    StandardPolicyV1 {
        version: p.version,
        max_per_spend: p.max_per_spend,
        recipient_restricted: p.recipient_restricted,
        recipient_set_root: p.recipient_set_root,
        policy_blinding: p.policy_blinding,
    }
}

/// Version-dispatched hash, mirroring `assert_policy_opens`.
fn hash_of(p: StandardPolicyV2) -> Field {
    if p.version == POLICY_VERSION_V1 {
        compute_policy_hash(v1_view(p))
    } else {
        compute_policy_hash_v2(p)
    }
}

/// A restricted policy over a two-member allowlist: `member` at index 0 with
/// `other_member` as its level-0 sibling, under an otherwise empty tree.
fn restricted_policy(
    max_per_spend: u128,
    member: Field,
    other_member: Field,
) -> (StandardPolicyV2, [Field; 16]) {
    let mut siblings = empty_recipient_set_siblings();
    siblings[0] = other_member;
    let root = compute_merkle_root_16(member, 0, siblings);
    (
        StandardPolicyV2 {
            version: POLICY_VERSION_V1,
            max_per_spend,
            recipient_restricted: 1,
            recipient_set_root: root,
            depth_limit: 0,
            policy_blinding: KAT_POLICY_BLINDING,
        }, siblings,
    )
}

#[test]
fn test_policy_hash_binds_every_parameter() {
    let base = compute_policy_hash(v1_view(unrestricted_policy(500)));
    let mut p = unrestricted_policy(500);
    p.version = 2;
    assert(compute_policy_hash(v1_view(p)) != base, "version must bind");
    assert(
        compute_policy_hash(v1_view(unrestricted_policy(501))) != base,
        "max_per_spend must bind",
    );
    p = unrestricted_policy(500);
    p.recipient_restricted = 1;
    assert(compute_policy_hash(v1_view(p)) != base, "recipient_restricted must bind");
    p = unrestricted_policy(500);
    p.recipient_set_root = 77;
    assert(compute_policy_hash(v1_view(p)) != base, "recipient_set_root must bind");
    p = unrestricted_policy(500);
    p.policy_blinding = KAT_POLICY_BLINDING + 1;
    assert(compute_policy_hash(v1_view(p)) != base, "policy_blinding must bind");
}

#[test]
fn test_policy_hash_v2_binds_depth_limit_and_separates_from_v1() {
    let v2_base = compute_policy_hash_v2(unrestricted_policy_v2(500, 3));
    assert(
        compute_policy_hash_v2(unrestricted_policy_v2(500, 4)) != v2_base,
        "depth_limit must bind",
    );
    // Length-domain separation: even a v2 preimage that agrees with a v1
    // preimage on every shared slot hashes differently (7 sponge slots vs 6).
    assert(
        compute_policy_hash(v1_view(unrestricted_policy(500))) != v2_base,
        "v1 and v2 hashes must never collide",
    );
}

#[test]
fn test_policy_v2_opens_and_permits_spend() {
    let p = unrestricted_policy_v2(500, 3);
    assert_policy_permits_spend(p, hash_of(p), 500, 123, 0, [0; 16]);
}

#[test(should_fail_with = "v1 policy must carry a zero depth_limit witness")]
fn test_v1_carrier_nonzero_depth_limit_rejected() {
    let mut p = unrestricted_policy(500);
    p.depth_limit = 1;
    assert_policy_opens(p, compute_policy_hash(v1_view(p)));
}

#[test]
fn test_delegation_gate_v1_permits() {
    let p = unrestricted_policy(500);
    // v1 carries no delegation parameter: permitted at any successor depth
    // (DEPTH_MAX is enforced elsewhere, by `delegated_depth`).
    assert_policy_permits_delegation(p, hash_of(p), 255);
}

#[test]
fn test_delegation_gate_v2_boundary() {
    let p = unrestricted_policy_v2(500, 3);
    assert_policy_permits_delegation(p, hash_of(p), 3);
}

#[test(should_fail_with = "delegation exceeds the policy depth limit")]
fn test_delegation_gate_v2_exceeded() {
    let p = unrestricted_policy_v2(500, 3);
    assert_policy_permits_delegation(p, hash_of(p), 4);
}

#[test(should_fail_with = "delegation exceeds the policy depth limit")]
fn test_delegation_gate_v2_zero_limit_forbids() {
    let p = unrestricted_policy_v2(500, 0);
    assert_policy_permits_delegation(p, hash_of(p), 1);
}

// ---- §5 narrowing registry v1 (assert_policy_narrows rule tests) ----------

fn fresh(mut p: StandardPolicyV2) -> StandardPolicyV2 {
    // A narrowed policy must re-blind (§5).
    p.policy_blinding = KAT_POLICY_BLINDING + 99;
    p
}

#[test]
fn test_narrows_v1_ceiling_tightens() {
    assert_policy_narrows(unrestricted_policy(500), fresh(unrestricted_policy(400)));
}

#[test]
fn test_narrows_v1_to_v2_any_depth_limit() {
    assert_policy_narrows(
        unrestricted_policy(500),
        fresh(unrestricted_policy_v2(500, 7)),
    );
}

#[test]
fn test_narrows_v2_depth_limit_boundary() {
    assert_policy_narrows(
        unrestricted_policy_v2(500, 3),
        fresh(unrestricted_policy_v2(500, 3)),
    );
}

#[test]
fn test_narrows_may_add_restriction() {
    let mut to = fresh(unrestricted_policy(500));
    to.recipient_restricted = 1;
    to.recipient_set_root = 77;
    assert_policy_narrows(unrestricted_policy(500), to);
}

#[test(should_fail_with = "narrowing may not downgrade the policy schema version")]
fn test_narrows_v2_to_v1_rejected() {
    assert_policy_narrows(
        unrestricted_policy_v2(500, 3),
        fresh(unrestricted_policy(400)),
    );
}

#[test(should_fail_with = "narrowing may not raise max_per_spend")]
fn test_narrows_raised_ceiling_rejected() {
    assert_policy_narrows(unrestricted_policy(500), fresh(unrestricted_policy(501)));
}

#[test(should_fail_with = "narrowing may not lift a recipient restriction")]
fn test_narrows_lifted_restriction_rejected() {
    let mut from = unrestricted_policy(500);
    from.recipient_restricted = 1;
    from.recipient_set_root = 77;
    assert_policy_narrows(from, fresh(unrestricted_policy(400)));
}

#[test(should_fail_with = "recipient_restricted must be boolean")]
fn test_narrows_non_boolean_target_rejected() {
    let mut to = fresh(unrestricted_policy(400));
    to.recipient_restricted = 2;
    assert_policy_narrows(unrestricted_policy(500), to);
}

#[test(should_fail_with = "restricted policy must carry a non-zero recipient set root")]
fn test_narrows_restricted_target_zero_root_rejected() {
    let mut to = fresh(unrestricted_policy(400));
    to.recipient_restricted = 1;
    assert_policy_narrows(unrestricted_policy(500), to);
}

#[test(should_fail_with = "narrowing may not change a restricted recipient set")]
fn test_narrows_changed_root_rejected() {
    let mut from = unrestricted_policy(500);
    from.recipient_restricted = 1;
    from.recipient_set_root = 77;
    let mut to = fresh(unrestricted_policy(400));
    to.recipient_restricted = 1;
    to.recipient_set_root = 78;
    assert_policy_narrows(from, to);
}

#[test(should_fail_with = "narrowing may not raise the depth limit")]
fn test_narrows_raised_depth_limit_rejected() {
    assert_policy_narrows(
        unrestricted_policy_v2(500, 3),
        fresh(unrestricted_policy_v2(500, 4)),
    );
}

#[test(should_fail_with = "narrowed policy must carry fresh blinding")]
fn test_narrows_reused_blinding_rejected() {
    assert_policy_narrows(unrestricted_policy(500), unrestricted_policy(400));
}

#[test(should_fail_with = "policy blinding must be non-zero")]
fn test_policy_zero_blinding_rejected() {
    // A zero blinding reverts the policy hash to a pure function of its
    // low-entropy parameters (dictionary-invertible, a cross-spend correlator).
    // The predicate refuses it even though the opening is hash-consistent.
    let mut p = unrestricted_policy(500);
    p.policy_blinding = 0;
    assert_policy_permits_spend(p, hash_of(p), 400, 123, 0, [0; 16]);
}

#[test]
fn test_policy_permits_unrestricted_spend() {
    let p = unrestricted_policy(500);
    // An unrestricted policy carries a CANONICAL (zero) dummy allowlist witness;
    // the membership branch does not constrain the recipient, but the witness
    // itself must be zero (see below).
    assert_policy_permits_spend(p, hash_of(p), 500, 123, 0, [0; 16]);
}

#[test(should_fail_with = "unrestricted policy must carry a zero allowlist path index")]
fn test_unrestricted_policy_nonzero_index_rejected() {
    // An unrestricted policy MUST carry a zero dummy index: a junk one is a
    // free, unconstrained scratch witness the prover controls. It is NOT true
    // that proof generation would otherwise reject it — see the measurement in
    // `assert_policy_permits_spend`'s doc comment. Enforced regardless of the
    // (off) membership branch.
    let p = unrestricted_policy(500);
    assert_policy_permits_spend(p, hash_of(p), 500, 123, 1048576, [0; 16]);
}

#[test]
fn test_policy_permits_restricted_member() {
    let member = derive_zka_address(8888);
    let (p, siblings) = restricted_policy(500, member, derive_zka_address(9999));
    assert_policy_permits_spend(p, hash_of(p), 400, member, 0, siblings);
}

#[test(should_fail_with = "policy opening mismatch")]
fn test_policy_opening_mismatch_rejected() {
    // The parameters actually evaluated are not the ones the mandate committed
    // to: the §5 "proof against any other policy MUST NOT verify" check.
    let committed = hash_of(unrestricted_policy(500));
    assert_policy_permits_spend(
        unrestricted_policy(100_000),
        committed,
        400,
        123,
        0,
        [0; 16],
    );
}

#[test(should_fail_with = "policy opening mismatch")]
fn test_policy_v2_opening_mismatch_rejected() {
    let committed = hash_of(unrestricted_policy_v2(500, 3));
    assert_policy_permits_spend(
        unrestricted_policy_v2(100_000, 255),
        committed,
        400,
        123,
        0,
        [0; 16],
    );
}

#[test(should_fail_with = "unsupported policy version")]
fn test_policy_unsupported_version_rejected() {
    let mut p = unrestricted_policy(500);
    p.version = 3;
    // The version check fires before any opening is attempted: an unknown
    // schema is refused, not reinterpreted under either known version.
    assert_policy_permits_spend(p, hash_of(p), 400, 123, 0, [0; 16]);
}

#[test(should_fail_with = "spend exceeds policy max_per_spend")]
fn test_policy_max_per_spend_enforced() {
    let p = unrestricted_policy(500);
    assert_policy_permits_spend(p, hash_of(p), 501, 123, 0, [0; 16]);
}

#[test(should_fail_with = "recipient_restricted must be boolean")]
fn test_policy_non_boolean_restriction_rejected() {
    let mut p = unrestricted_policy(500);
    p.recipient_restricted = 2;
    p.recipient_set_root = 77;
    assert_policy_permits_spend(p, hash_of(p), 400, 123, 0, [0; 16]);
}

#[test(should_fail_with = "restricted policy must carry a non-zero recipient set root")]
fn test_policy_restricted_with_zero_root_rejected() {
    let mut p = unrestricted_policy(500);
    p.recipient_restricted = 1;
    assert_policy_permits_spend(p, hash_of(p), 400, 123, 0, [0; 16]);
}

#[test(should_fail_with = "recipient not in the policy recipient set")]
fn test_policy_non_member_recipient_rejected() {
    let member = derive_zka_address(8888);
    let (p, siblings) = restricted_policy(500, member, derive_zka_address(9999));
    let stranger = derive_zka_address(1234);
    assert_policy_permits_spend(p, hash_of(p), 400, stranger, 0, siblings);
}

#[test]
fn test_merkle_root_16_child_order_matters() {
    let mut siblings = [0; 16];
    siblings[0] = 7;
    assert(
        compute_merkle_root_16(42, 1, siblings) != compute_merkle_root_16(42, 0, siblings),
        "child order must affect the root",
    );
    assert(
        compute_merkle_root_16(42, 0, siblings) != compute_merkle_root_16(43, 0, siblings),
        "different leaves must produce different roots",
    );
    // Depth is part of the construction: the same leaf at depth 16 and depth 32
    // must not fold to the same root.
    assert(
        compute_merkle_root_16(0, 0, empty_recipient_set_siblings())
            != compute_merkle_root(0, 0, empty_merkle_siblings()),
        "depth-16 and depth-32 empty roots must differ",
    );
}

// =============================================================================
// Known-Answer Tests (KATs)
//
// Poseidon2 goldens are identical to zka_lib's (same poseidon pin, same
// parameterization), captured under nargo 1.0.0-beta.21 + poseidon v0.3.0 and
// verified unchanged under nargo 1.0.0-beta.25. The ZKM-specific goldens below
// were captured under nargo 1.0.0-beta.22 + poseidon v0.3.0. A mismatch means
// the Poseidon2 parameterization or a domain separator changed — treat it as a
// protocol break and investigate the dependency/toolchain before re-blessing.
// To re-bless after an audited change: nargo test --show-output kat_  (read the
// printed Field values). Never paste a new value in to make a test pass.
// =============================================================================

#[test]
fn kat_afp_kdc_v102_raw_sponge_p0_empty() {
    assert(
        Poseidon2::hash([], 0)
            == 0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e,
        "AFP-KDC v1.0.2 P0 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p1_one() {
    assert(
        Poseidon2::hash([1], 1)
            == 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373,
        "AFP-KDC v1.0.2 P1 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p2_two() {
    assert(
        Poseidon2::hash([1, 2], 2)
            == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
        "AFP-KDC v1.0.2 P2 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p3_three() {
    assert(
        Poseidon2::hash([1, 2, 3], 3)
            == 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
        "AFP-KDC v1.0.2 P3 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p4_four() {
    assert(
        Poseidon2::hash([1, 2, 3, 4], 4)
            == 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9,
        "AFP-KDC v1.0.2 P4 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p6_six() {
    assert(
        Poseidon2::hash([1, 2, 3, 4, 5, 6], 6)
            == 0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a,
        "AFP-KDC v1.0.2 P6 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p7_seven() {
    assert(
        Poseidon2::hash([1, 2, 3, 4, 5, 6, 7], 7)
            == 0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238,
        "AFP-KDC v1.0.2 P7 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_poseidon2_of_1_2() {
    assert(
        poseidon2(1, 2) == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
        "poseidon2(1,2) KAT mismatch: Poseidon2 parameterization changed",
    );
}

#[test]
fn kat_poseidon3_of_1_2_3() {
    assert(
        poseidon3(1, 2, 3) == 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
        "poseidon3(1,2,3) KAT mismatch: Poseidon2 parameterization changed",
    );
}

#[test]
fn kat_poseidon4_of_1_2_3_4() {
    assert(
        poseidon4(1, 2, 3, 4) == 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9,
        "poseidon4(1,2,3,4) KAT mismatch: Poseidon2 parameterization changed",
    );
}

#[test]
fn kat_zkc_holder_commitment_from_seed_42() {
    let cbk = derive_zkc_credential_binding_key(42);
    assert(
        cbk == 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105,
        "ZKC cbk KAT mismatch",
    );
    assert(
        derive_zkc_holder_commitment(42)
            == 0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf,
        "ZKC holder commitment KAT mismatch",
    );
}

#[test]
fn kat_poseidon7_of_1_to_7() {
    assert(
        poseidon7(1, 2, 3, 4, 5, 6, 7)
            == 0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238,
        "poseidon7(1..7) KAT mismatch: Poseidon2 parameterization changed",
    );
}

#[test]
fn kat_zkc_composition_outputs() {
    assert(
        DOMAIN_ZKC_PRESENTATION_SCOPE
            == 0x2f7a94a38bb647d343fc7abc74b6466fe1eb566d71c185cc9537b7e768c466ae,
        "DOMAIN_ZKC_PRESENTATION_SCOPE KAT mismatch",
    );
    assert(
        DOMAIN_ZKM_ZKC_COMPOSITION
            == 0x15d0455dcc699fff3399d8dcbfaf8934ca251d42b00a15425ec5d9ddf8c6606c,
        "DOMAIN_ZKM_ZKC_COMPOSITION KAT mismatch",
    );
    assert(
        DOMAIN_ZKM_ZKC_ISSUANCE_CONTEXT
            == 0x2d558de9eeb08e860ef0fa89499b327f0a3ecb922295b2380642b066334d8e4a,
        "DOMAIN_ZKM_ZKC_ISSUANCE_CONTEXT KAT mismatch",
    );
    assert(
        DOMAIN_ZKM_ZKC_SPEND_CONTEXT
            == 0x187257a1677344507d757d1b9e16c6d6418cc8000257de995dd3ede77d4abbf6,
        "DOMAIN_ZKM_ZKC_SPEND_CONTEXT KAT mismatch",
    );

    let subject_handle = derive_zkc_presentation_pseudonym(42, 7);
    assert(
        subject_handle == 0x02af556638a0909bdfbda62d1c6302c6d6d6a69a312cf4a97e2e431a9636d71e,
        "scoped ZKC subject handle KAT mismatch",
    );

    assert(
        compute_zkc_issuance_context(101, 202)
            == 0x154cfeb5e6ccf23eca767445224b599288cb5eb1961704fbba38e68dd74d12e2,
        "ZKC issuance context KAT mismatch",
    );

    let spend_context = compute_zkc_spend_context(303, 404, 202);
    assert(
        spend_context == 0x26d9ead47c903813f2f40ee3bb1ac7c182a5d8d8745498067aef149c53844509,
        "ZKC spend context KAT mismatch",
    );
    assert(
        compute_zkc_composition_binding(
            505,
            606,
            spend_context,
            ZKC_PROFILE_SCOPED,
            subject_handle,
            7,
        )
            == 0x03faf4334373e856bae12bbaa2e78023ad3e9d2f5a3d899a15e70f1b42d1c0ad,
        "ZKC composition binding KAT mismatch",
    );
}

#[test(should_fail_with = "anonymous or unknown ZKC profile cannot use handle composition")]
fn test_anonymous_zkc_handle_composition_rejected() {
    let _ = derive_zkc_composable_subject_handle(42, ZKC_PROFILE_ANONYMOUS, 0);
}

#[test]
fn test_scoped_and_linkable_zkc_handles_are_profile_separated() {
    let scoped = derive_zkc_composable_subject_handle(42, ZKC_PROFILE_SCOPED, 7);
    let linkable = derive_zkc_composable_subject_handle(42, ZKC_PROFILE_LINKABLE, 0);
    assert(scoped != linkable, "profile handles must differ");
    assert(scoped != derive_zkc_composable_subject_handle(42, ZKC_PROFILE_SCOPED, 8));
}

// KAT: ZKM domain separators. Each is
// Blake2b512("ZKA-Domain-" || tag) mod BN254.Fr with the digest read
// little-endian (see the module header); tags are the §2 KDC names. Pinning
// them here means an edit to a constant is a test failure, not a silent
// protocol fork.
#[test]
fn kat_zkm_domain_separators() {
    // tag = "zkm/mandate_commitment/v1"
    assert(
        DOMAIN_ZKM_MANDATE_COMMITMENT
            == 0x2b9b00feea6c9acfdfbd933453a7be3e4980badd8beb7848e28992009b74f67c,
        "DOMAIN_ZKM_MANDATE_COMMITMENT KAT mismatch",
    );
    // tag = "zkm/mandate_nullifier/v1"
    assert(
        DOMAIN_ZKM_MANDATE_NULLIFIER
            == 0x01a0ffaffcb4824255c8db4d91656683e68cae424489fb79d76f7083fedfe053,
        "DOMAIN_ZKM_MANDATE_NULLIFIER KAT mismatch",
    );
    // tag = "zkm/mandate_nullifier_key/v1"
    assert(
        DOMAIN_ZKM_MANDATE_NULLIFIER_KEY
            == 0x13434dd24dcadc2621268e80ba4628bc0d9f8154e5f272a99de4257c9ee9eafd,
        "DOMAIN_ZKM_MANDATE_NULLIFIER_KEY KAT mismatch",
    );
    // tag = "zkm/mandate_root_id/v1"
    assert(
        DOMAIN_ZKM_MANDATE_ROOT_ID
            == 0x0e8b2c7f9831b5cbaaddbe7b8a98cb3d6f0e570b825df5a0ed18ff82b6a29295,
        "DOMAIN_ZKM_MANDATE_ROOT_ID KAT mismatch",
    );
    // tag = "zkm/holder_key/v1"
    assert(
        DOMAIN_ZKM_HOLDER_KEY == 0x12106df0c6acc17eab4e42f1f0509aeaeeaacd580cbee77327869a0fffe0ab52,
        "DOMAIN_ZKM_HOLDER_KEY KAT mismatch",
    );
    // tag = "zkm/issuance_key/v1"
    assert(
        DOMAIN_ZKM_ISSUANCE_KEY
            == 0x13ea79880b4f13adef0c45c92fbf65b495034c93646ac078cb076bff4afa8998,
        "DOMAIN_ZKM_ISSUANCE_KEY KAT mismatch",
    );
    // tag = "zkm/control_attestation/v1"
    assert(
        DOMAIN_ZKM_CONTROL_ATTESTATION
            == 0x2ada2ea2f52b310f53244b1b43a4227881a39cbb648f74aa7ad202588ae76301,
        "DOMAIN_ZKM_CONTROL_ATTESTATION KAT mismatch",
    );
    // tag = "zkm/disclosure_binding/v1"
    assert(
        DOMAIN_ZKM_DISCLOSURE_BINDING
            == 0x0b5325387de003d1f3d1d3c85995e287af94e7bc9a3463bc93b60605a345ec9d,
        "DOMAIN_ZKM_DISCLOSURE_BINDING KAT mismatch",
    );
    // tag = "zkm/zkc-composition/v1"
    assert(
        DOMAIN_ZKM_ZKC_COMPOSITION
            == 0x15d0455dcc699fff3399d8dcbfaf8934ca251d42b00a15425ec5d9ddf8c6606c,
        "DOMAIN_ZKM_ZKC_COMPOSITION KAT mismatch",
    );
    // tag = "zkm/zkc-issuance-context/v1"
    assert(
        DOMAIN_ZKM_ZKC_ISSUANCE_CONTEXT
            == 0x2d558de9eeb08e860ef0fa89499b327f0a3ecb922295b2380642b066334d8e4a,
        "DOMAIN_ZKM_ZKC_ISSUANCE_CONTEXT KAT mismatch",
    );
    // tag = "zkm/zkc-spend-context/v1"
    assert(
        DOMAIN_ZKM_ZKC_SPEND_CONTEXT
            == 0x187257a1677344507d757d1b9e16c6d6418cc8000257de995dd3ede77d4abbf6,
        "DOMAIN_ZKM_ZKC_SPEND_CONTEXT KAT mismatch",
    );
}

// Canonical KAT note: root_id = compute_mandate_root_id(991, 13),
// settlement_domain = KAT_SETTLEMENT_CONTEXT (an honest note is issued for the
// domain it is transitioned on), asset_id = 7, remaining_cap = 1000,
// expiry = 2000, policy_hash = 33, holder_key = derive_holder_key(4242),
// depth = 0, randomness = 555.
fn kat_note() -> MandateNote {
    MandateNote {
        root_id: compute_mandate_root_id(991, 13),
        settlement_domain: KAT_SETTLEMENT_CONTEXT,
        asset_id: 7,
        remaining_cap: 1000,
        expiry: 2000,
        policy_hash: 33,
        holder_key: derive_holder_key(4242),
        depth: 0,
        randomness: 555,
    }
}

/// Canonical KAT settlement context. A deployment derives this the way zka_lib
/// derives its spend context (epoch / chain_id / application_id); the fixed
/// value here only has to be stable and non-zero.
global KAT_SETTLEMENT_CONTEXT: Field = 0x5e77_1e3c;

#[test]
fn kat_mandate_root_id() {
    println(compute_mandate_root_id(991, 13));
    assert(
        compute_mandate_root_id(991, 13)
            == 0x1c4157221a5e964701eefa2d15ecdb5d1df85210832e4d298dd26ae73d688d77,
        "mandate root_id KAT mismatch",
    );
}

#[test]
fn kat_holder_key_derivation() {
    println(derive_holder_key(4242));
    assert(
        derive_holder_key(4242)
            == 0x2d4514b7e35e1f06e985f306fcbbd3eb05e8be6221d7d4c2672dcc885b5911ac,
        "holder_key derivation KAT mismatch",
    );
}

#[test]
fn kat_holder_nullifier_secret_derivation() {
    println(derive_holder_nullifier_secret(4242));
    assert(
        derive_holder_nullifier_secret(4242)
            == 0x1b3e1c5af690abd89c3a7163e53ccc1c5a891cdea50e5dfa26c07828ffe95ffb,
        "holder_nullifier_secret derivation KAT mismatch",
    );
}

#[test]
fn kat_mandate_commitment() {
    println(compute_mandate_commitment(kat_note()));
    assert(
        compute_mandate_commitment(kat_note())
            == 0x125f33ea13d4e172b84667800341a3bef7b0676c5caa6573c7a28206adf690d4,
        "mandate commitment KAT mismatch",
    );
}

// `nf` is `H(DOMAIN, hns, cm, settlement_context)`, and `cm` commits to the
// settlement domain. This KAT is captured from `--show-output` over that full
// preimage and is never adjusted manually.
#[test]
fn kat_mandate_nullifier() {
    let nf = compute_mandate_nullifier(
        derive_holder_nullifier_secret(4242),
        compute_mandate_commitment(kat_note()),
        KAT_SETTLEMENT_CONTEXT,
    );
    println(nf);
    assert(
        nf == 0x116bfd5a40b551832ee1efb53eba914041fc22480f6c0e6623d095a847596ac1,
        "mandate nullifier KAT mismatch",
    );
}

// KAT: version-2 empty full-identifier exclusion root.
#[test]
fn kat_empty_revocation_root_v2_depth_254() {
    let siblings = empty_revocation_siblings();
    println(compute_revocation_root(0, 1, siblings));
    assert(
        compute_revocation_root(0, 1, siblings)
            == 0x0ec9cf7fbcbffa41bc1b25e7569f1bbc85ee742cbe1c6c6f4c6af987b9773f55,
        "version-2 empty full-id root KAT mismatch",
    );
}

// KAT: the empty depth-32 mandate state-tree root. The identical empty root is
// expected because both version-2 trees share depth and hash semantics; leaf
// meaning and root registries keep the state domains distinct.
#[test]
fn kat_empty_mandate_root_depth_32() {
    let siblings = empty_merkle_siblings();
    println(compute_merkle_root(0, 0, siblings));
    assert(
        compute_merkle_root(0, 0, siblings)
            == 0x0b59baa35b9dc267744f0ccb4e3b0255c1fc512460d91130c6bc19fb2668568d,
        "depth-32 empty mandate root KAT mismatch",
    );
}

// KAT: the six MIRRORED ZKA domain separators. These are ZKA's own published
// constants (tags `zka/viewing`, `zka/address`, `zka/nullifier`, `zka/asset`),
// copied verbatim from zka_lib. Pinning them here means an edit is a test
// failure rather than a silent CROSS-REPO hash break — the failure mode this
// guards is a ZKM circuit that nullifies notes ZKA's tree has never seen.
#[test]
fn kat_mirrored_zka_domain_separators() {
    assert(
        DOMAIN_ZKA_SPENDING == 0x14046af3b2a955bb4c450d1b53ffc2798acc3c2924c3519cf923146b775acc67,
        "DOMAIN_ZKA_SPENDING KAT mismatch",
    );
    assert(
        DOMAIN_ZKA_PROOF == 0x193befdd9db847abcc0c6412a4044f4ce9b378786241eab30fbb50b9faaad2d7,
        "DOMAIN_ZKA_PROOF KAT mismatch",
    );
    assert(
        DOMAIN_ZKA_VIEWING == 0x041a8f7dfa88f8b20fd899a83e0bce075c65856e12e7706113f0b326a9b13eff,
        "DOMAIN_ZKA_VIEWING KAT mismatch",
    );
    assert(
        DOMAIN_ZKA_ADDRESS == 0x001b916d980f2edf145af8615825a58890f9ff48dc7c0fa92ed14fe0cd5e5fb8,
        "DOMAIN_ZKA_ADDRESS KAT mismatch",
    );
    assert(
        DOMAIN_ZKA_NULLIFIER == 0x2e03b47965736082429061ee83eba139ece5ee1c8f30983b4d5a54ac8e18c1eb,
        "DOMAIN_ZKA_NULLIFIER KAT mismatch",
    );
    assert(
        DOMAIN_ZKA_ASSET == 0x078574d1857e778c075008cf155293bda6a75e7146a12a32692271782baf7d30,
        "DOMAIN_ZKA_ASSET KAT mismatch",
    );
}

// KAT: the policy domain separator (tag `zkm/policy/v1`) — a ZKM-owned tag
// with a defined, non-provisional value (§2).
#[test]
fn kat_zkm_policy_domain_separator() {
    assert(
        DOMAIN_ZKM_POLICY == 0x21924384b009ec6f6d4fa4058a6282081978d6e026ee2ac3d720470ab2e0ba06,
        "DOMAIN_ZKM_POLICY KAT mismatch",
    );
}

// -----------------------------------------------------------------------------
// KATs: mirrored ZKA value-note primitives.
//
// CROSS-REPO PROVENANCE. The four goldens below were NOT merely captured from
// this crate's own `--show-output`; each was independently reproduced by
// calling ZKA.dev's own `zka_lib` (`derive_address`, `compute_asset_commitment`,
// `compute_note_commitment`, `compute_nullifier`) on the same inputs, under the
// same nargo 1.0.0-beta.22 + poseidon v0.3.0 pin, and the values matched
// digit-for-digit. That is what turns "hash-identical by construction" from a
// claim in a comment into a checked fact: if either repository's construction
// drifts, these tests fail here and the drift is caught before a ZKM proof ever
// nullifies a note ZKA's tree cannot see. Re-run the cross-check (a throwaway
// package depending on ZKA's `zka_lib` by path) whenever either side is bumped.
//
// Fixture: asset 7, value 900, owner sk 4242, randomness 7001 — shared
// value-for-value with `zkm_spend_conjoined`'s fixtures, so that package's
// public-tuple golden and these cross-check each other too.
// -----------------------------------------------------------------------------

global KAT_ZKA_SK: Field = 4242;
global KAT_ZKA_ASSET_ID: Field = 7;
global KAT_ZKA_VALUE: Field = 900;
global KAT_ZKA_RANDOMNESS: Field = 7001;

// AFP-KDC v1.0.2 §A.6 vector KATs. Inputs are the canonical reduced
// `kdcInput` fields; each named vector exercises all six actual derivation APIs.
#[test]
fn kat_afp_kdc_v102_kdc_zero() {
    let seed: Field = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let sk = derive_zka_spending_key(seed);
    assert(
        sk == 0x182877c456caaec9e58390c15c8001c817b8566d8952afd55e5484edbe68363c,
        "zero: spending key",
    );
    assert(
        derive_zka_viewing_key(sk)
            == 0x01a4f9348723ddb88b8cb51bfefa165779b20a0595bcb728fcb56a65b3115575,
        "zero: viewing key",
    );
    assert(
        derive_zka_proof_key(sk)
            == 0x292019ef1768ba0fa512e5ad8442592135ba8c6fcc75824b68858e518771985c,
        "zero: proof key",
    );
    assert(
        derive_zka_address(sk)
            == 0x1e59072f0fac351c5c4e80a8291ec26d58ef4aaf766c8206cd7ca677b0a9b5a5,
        "zero: address",
    );
    assert(
        derive_zkc_credential_binding_key(seed)
            == 0x214266e62f30fbe36989a56722253ef4b4f05c73e7e6e79561523f86bbc0bf69,
        "zero: credential binding key",
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x26911baa3a91df3ae99b57264dd8ffc1a774b75adb6bc44f801eab9a28dbb85c,
        "zero: holder commitment",
    );
}

#[test]
fn kat_afp_kdc_v102_kdc_one() {
    let seed: Field = 0x0000000000000000000000000000000000000000000000000000000000000001;
    let sk = derive_zka_spending_key(seed);
    assert(
        sk == 0x144fa23c717e08e4e14147010d31e2aadd3e7ebb761198d4cbaae23f62b3ef67,
        "one: spending key",
    );
    assert(
        derive_zka_viewing_key(sk)
            == 0x16b8d89ff569ae13d9dc795f0dc70fe3283bc0c9fd66367ea39616d716a33a5d,
        "one: viewing key",
    );
    assert(
        derive_zka_proof_key(sk)
            == 0x23817d38a9dd9cee841fe099e73e3bdf7dc94877661df70d6ce7bede7f741846,
        "one: proof key",
    );
    assert(
        derive_zka_address(sk)
            == 0x0f26d097b8cdb6e1a28dcb476c9ba0404139ccb92567f2ea3bc2136c70e00bfe,
        "one: address",
    );
    assert(
        derive_zkc_credential_binding_key(seed)
            == 0x156363709184916cfd39a0ff03728d2f61eeb21db527764a632ced26248620a9,
        "one: credential binding key",
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x1b5da79c042b6f60628ca40f9f36af41ba93a4e0706f18d63918ead501bded10,
        "one: holder commitment",
    );
}

#[test]
fn kat_afp_kdc_v102_kdc_r_minus_1() {
    let seed: Field = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
    let sk = derive_zka_spending_key(seed);
    assert(
        sk == 0x2aa6de3a01fec0825909dae75f37e1b6093ba378df2965185d135fcd0f6fd421,
        "r_minus_1: spending key",
    );
    assert(
        derive_zka_viewing_key(sk)
            == 0x116d9a4fe480c1d976f48d0122a49fe919de71e813719fa3514bbfd629ab1e02,
        "r_minus_1: viewing key",
    );
    assert(
        derive_zka_proof_key(sk)
            == 0x0bb78d04ccc163c139ff540e6a28ec440ae3e391a19c294b0ee525fad07bd648,
        "r_minus_1: proof key",
    );
    assert(
        derive_zka_address(sk)
            == 0x2f5f49c1a110fc0afaf2757591deb20e1826e1790fb815eed0f371f255fdef01,
        "r_minus_1: address",
    );
    assert(
        derive_zkc_credential_binding_key(seed)
            == 0x0f9ae0ed0936446399b4d8860ba56fad98f3cde0e234351498f9b47157e47770,
        "r_minus_1: credential binding key",
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x0f93ef96e2e9889be72f147c815effddd4836f6a03c133b9383eaa4c0237d9ae,
        "r_minus_1: holder commitment",
    );
}

#[test]
fn kat_afp_kdc_v102_kdc_r() {
    let seed: Field = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let sk = derive_zka_spending_key(seed);
    assert(
        sk == 0x182877c456caaec9e58390c15c8001c817b8566d8952afd55e5484edbe68363c,
        "r: spending key",
    );
    assert(
        derive_zka_viewing_key(sk)
            == 0x01a4f9348723ddb88b8cb51bfefa165779b20a0595bcb728fcb56a65b3115575,
        "r: viewing key",
    );
    assert(
        derive_zka_proof_key(sk)
            == 0x292019ef1768ba0fa512e5ad8442592135ba8c6fcc75824b68858e518771985c,
        "r: proof key",
    );
    assert(
        derive_zka_address(sk)
            == 0x1e59072f0fac351c5c4e80a8291ec26d58ef4aaf766c8206cd7ca677b0a9b5a5,
        "r: address",
    );
    assert(
        derive_zkc_credential_binding_key(seed)
            == 0x214266e62f30fbe36989a56722253ef4b4f05c73e7e6e79561523f86bbc0bf69,
        "r: credential binding key",
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x26911baa3a91df3ae99b57264dd8ffc1a774b75adb6bc44f801eab9a28dbb85c,
        "r: holder commitment",
    );
}

#[test]
fn kat_afp_kdc_v102_kdc_r_plus_1() {
    let seed: Field = 0x0000000000000000000000000000000000000000000000000000000000000001;
    let sk = derive_zka_spending_key(seed);
    assert(
        sk == 0x144fa23c717e08e4e14147010d31e2aadd3e7ebb761198d4cbaae23f62b3ef67,
        "r_plus_1: spending key",
    );
    assert(
        derive_zka_viewing_key(sk)
            == 0x16b8d89ff569ae13d9dc795f0dc70fe3283bc0c9fd66367ea39616d716a33a5d,
        "r_plus_1: viewing key",
    );
    assert(
        derive_zka_proof_key(sk)
            == 0x23817d38a9dd9cee841fe099e73e3bdf7dc94877661df70d6ce7bede7f741846,
        "r_plus_1: proof key",
    );
    assert(
        derive_zka_address(sk)
            == 0x0f26d097b8cdb6e1a28dcb476c9ba0404139ccb92567f2ea3bc2136c70e00bfe,
        "r_plus_1: address",
    );
    assert(
        derive_zkc_credential_binding_key(seed)
            == 0x156363709184916cfd39a0ff03728d2f61eeb21db527764a632ced26248620a9,
        "r_plus_1: credential binding key",
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x1b5da79c042b6f60628ca40f9f36af41ba93a4e0706f18d63918ead501bded10,
        "r_plus_1: holder commitment",
    );
}

#[test]
fn kat_afp_kdc_v102_kdc_high_bit() {
    let seed: Field = 0x1f37631a3d9cbfac8f5f7492fcfd4f45af982f6f0c8d1edd783c14d81ffffffe;
    let sk = derive_zka_spending_key(seed);
    assert(
        sk == 0x054bffb9c2753d29eb67714bedaec3f6f909f62d0b6edc3e8b32f5feae599dd1,
        "high_bit: spending key",
    );
    assert(
        derive_zka_viewing_key(sk)
            == 0x17f2e28a96e45b73ffbe05ae5568b726392f10047e1a2b1ed6a8597c5798665f,
        "high_bit: viewing key",
    );
    assert(
        derive_zka_proof_key(sk)
            == 0x2b4003b5718df23357bbbaf25b96eb4cea82405b01d5f8a47d1567a779e76b63,
        "high_bit: proof key",
    );
    assert(
        derive_zka_address(sk)
            == 0x2cdbe57561dc37866f283823339e4551faffbfa407fc1147bc4db440b8adf826,
        "high_bit: address",
    );
    assert(
        derive_zkc_credential_binding_key(seed)
            == 0x2e0ec1d6d13e07e096d6e97072ada506cfd048265c8e715b48cdb52222211acc,
        "high_bit: credential binding key",
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x20bdb27ab52177af841502649fae65d8f7ad2456c92afa3392c75e40fd4854e3,
        "high_bit: holder commitment",
    );
}

#[test]
fn kat_afp_kdc_v102_kdc_asymmetric() {
    let seed: Field = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
    let sk = derive_zka_spending_key(seed);
    assert(
        sk == 0x25c8b56ae92ceeb873fdba8ebded92b2da7b03fe6330fd464bc68ef60e43d35c,
        "asymmetric: spending key",
    );
    assert(
        derive_zka_viewing_key(sk)
            == 0x302a0ff15a9d16b4f00df3ab76b71a7182b9850d6ec33411515f776f9083ab8d,
        "asymmetric: viewing key",
    );
    assert(
        derive_zka_proof_key(sk)
            == 0x01b48895c3cc1bf9626fe911881b27a856f6fe5c7f73587a647cc3095299f1a6,
        "asymmetric: proof key",
    );
    assert(
        derive_zka_address(sk)
            == 0x28424ceb512ed48ac09bb7f7a8965e4e88b4f1401e7d4988b0fb045b9d45e2e8,
        "asymmetric: address",
    );
    assert(
        derive_zkc_credential_binding_key(seed)
            == 0x13f7a19491d111e859b706bbf4ac09ae04b9ae617fd9810f2c2abc79498b25f7,
        "asymmetric: credential binding key",
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x168c18b64068e5507de96921fc526999752d8df4413ec276a3ab7cd2b57f6223,
        "asymmetric: holder commitment",
    );
}

#[test]
fn kat_zka_address_derivation() {
    println(derive_zka_address(KAT_ZKA_SK));
    assert(
        derive_zka_address(KAT_ZKA_SK)
            == 0x03cd0f3d278fb159c377bacbf05628868336479be6bacc4ac4dc97bed8a30c02,
        "zka address derivation KAT mismatch",
    );
}

#[test]
fn kat_zka_asset_commitment() {
    println(compute_zka_asset_commitment(KAT_ZKA_ASSET_ID));
    assert(
        compute_zka_asset_commitment(KAT_ZKA_ASSET_ID)
            == 0x18086bfe7fca938736950d593f909fad0896bffbeb9f8929c5082aa969e457ce,
        "zka asset commitment KAT mismatch",
    );
}

#[test]
fn kat_zka_note_commitment() {
    let cm = compute_zka_note_commitment(
        compute_zka_asset_commitment(KAT_ZKA_ASSET_ID),
        KAT_ZKA_VALUE,
        derive_zka_address(KAT_ZKA_SK),
        KAT_ZKA_RANDOMNESS,
    );
    println(cm);
    assert(
        cm == 0x2ebc4b4d8645bfdb5de024017b3cf33931bc286e29b493291c72f242ebdc8869,
        "zka note commitment KAT mismatch",
    );
}

#[test]
fn kat_zka_nullifier() {
    let cm = compute_zka_note_commitment(
        compute_zka_asset_commitment(KAT_ZKA_ASSET_ID),
        KAT_ZKA_VALUE,
        derive_zka_address(KAT_ZKA_SK),
        KAT_ZKA_RANDOMNESS,
    );
    let nf = compute_zka_nullifier(cm, KAT_ZKA_SK);
    println(nf);
    assert(
        nf == 0x2c0540439a25670b0c6441614febeb452185856f121eabc87c0197e4f470f8c4,
        "zka nullifier KAT mismatch",
    );
}

// KAT: the canonical fixture policy of `zkm_spend_conjoined` (v1, max_per_spend
// 600, unrestricted, policy_blinding = KAT_POLICY_BLINDING). Pins the policy
// preimage ORDER (including the trailing `policy_blinding` slot added in F4) and
// the `u128 -> Field` encoding of `max_per_spend` as well as the domain
// separator.
#[test]
fn kat_policy_hash_v1_unrestricted() {
    println(compute_policy_hash(v1_view(unrestricted_policy(600))));
    assert(
        compute_policy_hash(v1_view(unrestricted_policy(600)))
            == 0x2b487390249e8dc9619250a062297e450b984d2bdd5f2c0277edbf1f6e5dd32f,
        "policy hash KAT mismatch",
    );
}

// KAT: the empty depth-16 recipient-set root. Distinct from the depth-32
// accumulator roots above — same ladder, different height — so this
// pins the allowlist tree's depth as well as its hash.
#[test]
fn kat_empty_recipient_set_root_depth_16() {
    let root = compute_merkle_root_16(0, 0, empty_recipient_set_siblings());
    println(root);
    assert(
        root == 0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3,
        "depth-16 empty recipient set root KAT mismatch",
    );
}
