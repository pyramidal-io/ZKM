// =============================================================================
// ZKM Aztec Adapter Library
//
// Bridges the ZKM mandate artifact (docs/zkm_specification.md §3) into
// Aztec.nr contracts, mirroring the structure of ZKA's zka_aztec_lib.
//
// Note type:
//   ZKMMandateNote -- Private mandate note (spend authority artifact)
//
// Note-hash scope (IMPORTANT):
//   ZKMMandateNote's note hash delegates to zkm_lib::compute_mandate_commitment
//   and is byte-identical to the standalone reference circuits' mandate
//   commitment, with two platform substitutions:
//     - `holder_key` slot carries the Aztec note owner's address field
//       (owner.to_field()) instead of a Poseidon2-derived holder key. On Aztec
//       the holder-binding is the note-ownership machinery itself (the owner's
//       keys gate nullification), so the owner address IS the holder identity
//       within this deployment.
//     - `randomness` is the framework-supplied note randomness. It is drawn
//       from an UNCONSTRAINED oracle (a malicious wallet could reuse it), so
//       it is NOT what carries §4.3-3 successor distinctness on Aztec —
//       protocol nonce-uniquing does (every inserted note hash is uniquified
//       with the tx's first nullifier + the note's index before it becomes a
//       tree leaf, so even byte-identical raw commitments yield distinct
//       leaves and nullifiers).
//   This cross-environment equality is pinned by
//   test_mandate_note_hash_matches_standalone below.
//
//   The NULLIFIER is platform-substituted entirely: Aztec computes
//   compute_note_nullifier(note_hash, nhk_app) via the owner's app-siloed
//   nullification key -- NOT zkm_lib's
//   H(DOMAIN_ZKM_MANDATE_NULLIFIER, hns, cm, settlement_context). Same caveat
//   as the ZKA Aztec profile (ZKA aztec_native_pay_profile.md: commitments
//   byte-identical, nullifiers platform-substituted). Uniqueness/dedup
//   semantics are preserved (one nullifier per consumed note, enforced by the
//   protocol's nullifier tree); the cross-domain replay-hygiene folding of
//   settlement_context into the nullifier preimage is NOT reproduced -- on
//   Aztec the commitment-level settlement_domain binding (which zkm_lib
//   documents as the load-bearing defence) plus per-contract note siloing
//   carry that property.
//
//   Issuance additionally emits a distinct, domain-separated nullifier over
//   the principal's private issuance preimage and immutable context, preventing
//   duplicate origin authority even after the note has been consumed. This
//   platform-specific nullifier does not change the mandate commitment or
//   standalone transition nullifier scheme.
// =============================================================================

use aztec::{
    keys::getters::{get_nhk_app, get_public_keys, try_get_public_keys},
    macros::notes::custom_note,
    note::{note_interface::NoteHash, utils::compute_note_nullifier},
    protocol::{
        address::AztecAddress,
        traits::{Deserialize, FromField, Packable, Serialize, ToField},
    },
};

use aztec::context::PrivateContext;

use zkm_lib;
use zkm_lib::MandateNote;

// Aztec-only issuance replay domain: exact UTF-8 zkm/aztec/issuance/v1,
// right-aligned in one field. This does not change the native mandate hash.
pub global ZKM_AZTEC_ISSUANCE_NULLIFIER_DOMAIN: Field =
    0x7a6b6d2f617a7465632f69737375616e63652f7631;

/// One original issuance per private root ceremony in this contract instance.
/// Keep the preimage secret: deriving this only from root_id would let a later
/// public revocation root identify its original issuance transaction. The
/// kernel additionally silos this nullifier by the executing contract address.
pub fn compute_issuance_nullifier(
    principal_issuance_key: Field,
    issuance_randomness: Field,
    settlement_context: Field,
) -> Field {
    zkm_lib::poseidon4(
        ZKM_AZTEC_ISSUANCE_NULLIFIER_DOMAIN,
        principal_issuance_key,
        issuance_randomness,
        settlement_context,
    )
}

// =============================================================================
// Range guards
//
// A bare `v as u128` / `v as u64` / `v as u8` cast does NOT range-check -- it
// silently truncates (same hazard class ZKA's conservation.nr documents). Every
// Field that feeds a typed zkm_lib slot must pass through one of these guards
// first so the subsequent cast is provably lossless.
// =============================================================================

/// Assert that the raw `Field` value `v` fits in a u128, i.e. v < 2^128.
pub fn assert_fits_u128(v: Field) {
    assert(v == (v as u128) as Field, "value exceeds u128 range");
}

/// Assert that the raw `Field` value `v` fits in a u64.
pub fn assert_fits_u64(v: Field) {
    assert(v == (v as u64) as Field, "value exceeds u64 range");
}

/// Assert that the raw `Field` value `v` fits in a u8.
pub fn assert_fits_u8(v: Field) {
    assert(v == (v as u8) as Field, "value exceeds u8 range");
}

// =============================================================================
// ZKMMandateNote -- the §3 mandate artifact as an Aztec private note
//
// Field ORDER mirrors zkm_lib::MandateNote (the normative commitment-preimage
// order), minus `holder_key` and `randomness`, which the framework supplies as
// NoteHash method parameters (owner + note randomness).
//
// All fields are Fields (matching ZKANote's style); the contract asserts
// u128/u64/u8 bounds at every creation site, so stored notes always carry
// in-range values.
// =============================================================================

#[derive(Deserialize, Eq, Packable, Serialize)]
#[custom_note]
pub struct ZKMMandateNote {
    /// Stable identifier of the original issuance (revocation anchor, §7.1).
    pub root_id: Field,
    /// Settlement-domain binding, committed in the authority itself (§5).
    pub settlement_domain: Field,
    /// ZKA registry asset encoding.
    pub asset_id: Field,
    /// Remaining spend authority (u128-bounded at creation).
    pub remaining_cap: Field,
    /// Settlement-layer timestamp bound (u64-bounded at creation); MUST NOT
    /// extend across successors.
    pub expiry: Field,
    /// Hash of the versioned policy predicate + parameters (§5).
    pub policy_hash: Field,
    /// Delegation depth (u8-bounded at creation); 0 at issuance, +1 per
    /// delegation (§6).
    pub depth: Field,
}

impl ZKMMandateNote {
    pub fn new(
        root_id: Field,
        settlement_domain: Field,
        asset_id: Field,
        remaining_cap: Field,
        expiry: Field,
        policy_hash: Field,
        depth: Field,
    ) -> Self {
        ZKMMandateNote {
            root_id,
            settlement_domain,
            asset_id,
            remaining_cap,
            expiry,
            policy_hash,
            depth,
        }
    }

    /// Compute the ZKM mandate commitment (matches the standalone reference
    /// circuits via zkm_lib::compute_mandate_commitment). Exposed as a
    /// free-standing helper so contracts/tests can compute the commitment with
    /// an explicit owner + randomness without the framework's NoteHash
    /// plumbing.
    pub fn zkm_mandate_note_hash(self, owner: AztecAddress, randomness: Field) -> Field {
        // Bound every typed slot before its cast (casts truncate silently).
        // Creation sites already enforce these, so for honestly-stored notes
        // the guards are redundant -- but this helper is also the hash used at
        // read time, so it must not rely on caller discipline.
        assert_fits_u128(self.remaining_cap);
        assert_fits_u64(self.expiry);
        assert_fits_u8(self.depth);
        zkm_lib::compute_mandate_commitment(
            MandateNote {
                root_id: self.root_id,
                settlement_domain: self.settlement_domain,
                asset_id: self.asset_id,
                remaining_cap: self.remaining_cap as u128,
                expiry: self.expiry as u64,
                policy_hash: self.policy_hash,
                holder_key: owner.to_field(),
                depth: self.depth as u8,
                randomness,
            },
        )
    }
}

impl NoteHash for ZKMMandateNote {
    fn compute_note_hash(
        self,
        owner: AztecAddress,
        _storage_slot: Field,
        randomness: Field,
    ) -> Field {
        // Delegate to the ZKM commitment scheme so this hash is identical to
        // the one produced by the standalone reference circuits. The Aztec
        // storage slot is NOT folded in; what stands in for it is that the
        // slot's only differentiating input — the owner — is independently in
        // the preimage (holder_key slot) AND separately asserted by the
        // framework's note getter. This is sound while `mandates` remains the
        // contract's sole PrivateSet of this note type, keyed by owner; a
        // second set of ZKMMandateNote would make notes movable between
        // slots. (Cross-TYPE separation is carried by
        // DOMAIN_ZKM_MANDATE_COMMITMENT in preimage slot 0.)
        self.zkm_mandate_note_hash(owner, randomness)
    }

    fn compute_nullifier(
        self,
        context: &mut PrivateContext,
        owner: AztecAddress,
        note_hash_for_nullification: Field,
    ) -> Field {
        let owner_npk_m_hash = get_public_keys(owner).npk_m_hash;
        let secret = context.request_nhk_app(owner_npk_m_hash);
        compute_note_nullifier(note_hash_for_nullification, [secret])
    }

    unconstrained fn compute_nullifier_unconstrained(
        self,
        owner: AztecAddress,
        note_hash_for_nullification: Field,
    ) -> Option<Field> {
        try_get_public_keys(owner).map(|public_keys| {
            let owner_npk_m_hash = public_keys.npk_m_hash;
            let secret = get_nhk_app(owner_npk_m_hash);
            compute_note_nullifier(note_hash_for_nullification, [secret])
        })
    }
}

// =============================================================================
// Cross-environment equality tests (pure -- plain `nargo test`, no TXE oracle)
// =============================================================================

#[test]
fn test_issuance_nullifier_kat() {
    assert(
        compute_issuance_nullifier(991, 13, 0x5e771e3c)
            == 0x2e9f7fe45f66b4e21729afd3fc83450a769ea979b0caee9d6b6a054edc492bba,
        "Aztec issuance nullifier derivation must match the pinned KAT",
    );
}

#[test]
fn test_issuance_nullifier_binds_private_authority_and_context() {
    let original = compute_issuance_nullifier(991, 13, 0x5e771e3c);
    assert(original != compute_issuance_nullifier(992, 13, 0x5e771e3c));
    assert(original != compute_issuance_nullifier(991, 14, 0x5e771e3c));
    assert(original != compute_issuance_nullifier(991, 13, 0x5e771e3d));
    // Revealing root_id at revocation does not reveal either private input.
    let root_id = zkm_lib::compute_mandate_root_id(991, 13);
    assert(
        original != zkm_lib::poseidon3(ZKM_AZTEC_ISSUANCE_NULLIFIER_DOMAIN, root_id, 0x5e771e3c),
    );
}

/// Pin the cross-environment note-hash equality: the Aztec note hash MUST be
/// byte-identical to zkm_lib::compute_mandate_commitment over the same values,
/// with owner.to_field() in the holder_key slot. Uses the zkm_lib KAT fixture
/// values (issuance key 991 / randomness 13 fixture family) so any drift from
/// the standalone commitment scheme fails here first.
#[test]
fn test_mandate_note_hash_matches_standalone() {
    let root_id = zkm_lib::compute_mandate_root_id(991, 13);
    // The fixture holder key (zkm_lib KAT: derive_holder_key(4242)) stands in
    // as an owner address field value.
    let holder_key_field = zkm_lib::derive_holder_key(4242);
    let owner = AztecAddress::from_field(holder_key_field);

    let note = ZKMMandateNote::new(
        root_id,
        0x5e771e3c, // fixture settlement context / domain
        7, // asset_id
        1000, // remaining_cap
        2000, // expiry
        33, // policy_hash
        0, // depth
    );

    let expected = zkm_lib::compute_mandate_commitment(
        MandateNote {
            root_id,
            settlement_domain: 0x5e771e3c,
            asset_id: 7,
            remaining_cap: 1000,
            expiry: 2000,
            policy_hash: 33,
            holder_key: holder_key_field,
            depth: 0,
            randomness: 555,
        },
    );

    assert(
        note.zkm_mandate_note_hash(owner, 555) == expected,
        "Aztec mandate note hash must match the standalone zkm_lib commitment",
    );
}

/// The KAT commitment golden from zkm_lib's fixture family must be reproduced
/// exactly through the Aztec note-hash path (owner = derive_holder_key(4242)).
#[test]
fn test_mandate_note_hash_matches_kat_golden() {
    let root_id = zkm_lib::compute_mandate_root_id(991, 13);
    let owner = AztecAddress::from_field(zkm_lib::derive_holder_key(4242));
    let note = ZKMMandateNote::new(root_id, 0x5e771e3c, 7, 1000, 2000, 33, 0);
    assert(
        note.zkm_mandate_note_hash(owner, 555)
            == 0x125f33ea13d4e172b84667800341a3bef7b0676c5caa6573c7a28206adf690d4,
        "Aztec mandate note hash must reproduce the zkm_lib KAT commitment golden",
    );
}

#[test(should_fail_with = "value exceeds u128 range")]
fn test_note_hash_rejects_out_of_range_cap() {
    let note = ZKMMandateNote::new(1, 2, 3, 0x100000000000000000000000000000000, 2000, 33, 0);
    let _ = note.zkm_mandate_note_hash(AztecAddress::from_field(5), 555);
}

#[test(should_fail_with = "value exceeds u64 range")]
fn test_note_hash_rejects_out_of_range_expiry() {
    let note = ZKMMandateNote::new(1, 2, 3, 1000, 0x10000000000000000, 33, 0);
    let _ = note.zkm_mandate_note_hash(AztecAddress::from_field(5), 555);
}
