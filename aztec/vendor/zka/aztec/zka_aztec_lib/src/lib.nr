// =============================================================================
// ZKA Aztec Adapter Library
//
// Bridges ZKA's key hierarchy and note commitments into Aztec.nr contracts.
// Uses app-siloed nsk_app = H(nsk_m, contract_address) as the AFP-KDC master
// seed within each contract, preserving Aztec's security isolation while
// reusing ZKA's cryptographic primitives from zka_lib.
//
// Note types:
//   ZKANote     -- Private value note (transfers, withdrawals)
//   CredNote    -- Credential binding with selectable attributes
//
// Note-hash scope (IMPORTANT):
//   - ZKANote's note hash delegates to zka_lib::compute_note_commitment and is
//     identical to the standalone zka_transfer circuit. This cross-environment
//     equality is pinned by test_zka_note_hash_matches_standalone.
//   - CredNote uses an Aztec-only commitment layout (also built on
//     compute_note_commitment) that has NO standalone counterpart and is NOT
//     pinned by any cross-env test. It is therefore the reference definition:
//     any future standalone CredNote circuit must match this layout.
//     Its value slot commits to EVERY CredNote field -- credential_data,
//     context and attr0..attr3 -- because the note hash is the only content
//     constraint applied to a prover-supplied note. See the comment on
//     `impl NoteHash for CredNote`; pinned by
//     test_cred_note_hash_binds_every_attribute.
//
// Notes are declared #[custom_note] with a hand-written `impl NoteHash` so
// compute_note_hash delegates to zka_lib's ZKA commitment scheme rather than
// Aztec's default layout; `owner` and `randomness` are NoteHash method
// parameters (framework-managed metadata), not stored struct fields.
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
use std::field::bn254::decompose;

use zka_lib;

pub mod pay_receipt;

// =============================================================================
// Key Mapping Functions
//
// Aztec key hierarchy:  nsk_m (master nullifier secret key)
//                       \--- nsk_app = H(nsk_m, contract_address)
//
// ZKA key hierarchy:    master_seed
//                       |--- spending_key = H(DOMAIN_SPENDING, seed)
//                       |--- viewing_key = H(DOMAIN_VIEWING, sk)
//                       |  \--- address = H(DOMAIN_ADDRESS, vk)
//                       |--- proof_key = H(DOMAIN_PROOF, sk)
//                       \--- credential_binding_key = H(DOMAIN_CREDENTIAL, seed)
//
// Bridge: nsk_app is the app-siloed AFP-KDC seed within contract scope.
// =============================================================================

/// Derive the ZKA spending key from Aztec's app-siloed master seed.
pub fn aztec_nsk_to_zka_sk(nsk_app: Field) -> Field {
    zka_lib::derive_spending_key_from_master_seed(nsk_app)
}

/// Derive ZKA viewing key from Aztec's app-siloed nsk.
pub fn derive_zka_viewing_key(nsk_app: Field) -> Field {
    zka_lib::derive_viewing_key(aztec_nsk_to_zka_sk(nsk_app))
}

/// Derive ZKA address from Aztec's app-siloed nsk.
pub fn derive_zka_address(nsk_app: Field) -> Field {
    zka_lib::derive_address(aztec_nsk_to_zka_sk(nsk_app))
}

/// Derive the sibling ZKA credential binding key from the app-siloed seed.
pub fn derive_zka_cbk(nsk_app: Field) -> Field {
    zka_lib::derive_credential_binding_key(nsk_app)
}

// =============================================================================
// ZKANote -- Private value note for transfers and withdrawals
//
// Wraps (asset_commitment, value). The owner and randomness are supplied by
// the framework as NoteHash method parameters. The note hash delegates to
// zka_lib::compute_note_commitment so hashes are identical to standalone
// ZKA circuits.
// =============================================================================

#[derive(Deserialize, Eq, Packable, Serialize)]
#[custom_note]
pub struct ZKANote {
    pub asset_commitment: Field,
    pub value: Field,
}

impl ZKANote {
    pub fn new(asset_commitment: Field, value: Field) -> Self {
        ZKANote { asset_commitment, value }
    }

    /// Compute the ZKA note commitment (matches standalone zka_transfer circuit).
    /// Exposed as a free-standing helper so contracts/tests can compute the
    /// commitment with an explicit owner + randomness without going through the
    /// framework's NoteHash plumbing.
    pub fn zka_note_hash(self, owner: AztecAddress, randomness: Field) -> Field {
        zka_lib::compute_note_commitment(
            self.asset_commitment,
            self.value,
            owner.to_field(),
            randomness,
        )
    }
}

impl NoteHash for ZKANote {
    fn compute_note_hash(
        self,
        owner: AztecAddress,
        _storage_slot: Field,
        randomness: Field,
    ) -> Field {
        // Delegate to the ZKA commitment scheme so this hash is identical to
        // the one produced by the standalone zka_transfer circuit. The ZKA
        // scheme does not fold in the Aztec storage slot.
        self.zka_note_hash(owner, randomness)
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
// CredNote -- Credential binding with attributes
//
// Wraps (credential_commitment, credential_data, context, attr0..attr3). The
// owner and randomness are supplied by the framework as NoteHash method
// parameters.
//
// FIELD SEMANTICS (v0.6.0 SS5.2 canonical model -- docs/adr/0001):
//   `context` is carried as a SEPARATE field, never folded into
//   credential_data. This matches the normative SS5.2 model (context is a
//   co-equal binding, not part of the disclosure hash) and keeps credential_data
//   byte-identical to the standalone circuit's context-independent
//   disclosed_attribute_hash (the cross-environment equality guarantee).
//
//   * bind_credential (originator-owned note): credential_data carries the
//     underlying credential SECRET; context = 0 (the note is the credential
//     itself, not a session disclosure).
//
//   * disclose_to (recipient-owned note): credential_data carries the RAW
//     context-INDEPENDENT disclosed hash (compute_disclosed_hash output, equal
//     across environments); context carries the SS5.2 session
//     (H(verifierId, sessionId, timestamp)). The recipient reads both fields to
//     learn which disclosure was made and for which session. The originator's
//     secret is NEVER transmitted to recipients via this path.
//
// The two note shapes are disambiguated by which contract entry point produced
// the note. See the ZKACredential contract header ("WIRE CONTRACT FOR
// disclose_to") and docs/adr/0001 for the canonical cross-environment model.
// =============================================================================

#[derive(Deserialize, Eq, Packable, Serialize)]
#[custom_note]
pub struct CredNote {
    pub credential_commitment: Field,
    pub credential_data: Field,
    // SS5.2 session context (0 for an originator credential note; the
    // H(verifierId, sessionId, timestamp) session for a disclose_to note).
    pub context: Field,
    pub attr0: Field,
    pub attr1: Field,
    pub attr2: Field,
    pub attr3: Field,
}

impl CredNote {
    pub fn new(
        credential_commitment: Field,
        credential_data: Field,
        context: Field,
        attributes: [Field; 4],
    ) -> Self {
        CredNote {
            credential_commitment,
            credential_data,
            context,
            attr0: attributes[0],
            attr1: attributes[1],
            attr2: attributes[2],
            attr3: attributes[3],
        }
    }

    pub fn get_attributes(self) -> [Field; 4] {
        [self.attr0, self.attr1, self.attr2, self.attr3]
    }
}

impl NoteHash for CredNote {
    fn compute_note_hash(
        self,
        owner: AztecAddress,
        _storage_slot: Field,
        randomness: Field,
    ) -> Field {
        // Aztec-only commitment layout: there is NO standalone CredNote circuit,
        // so this definition is the reference -- any future standalone circuit
        // must match it (it is not pinned by a cross-env test).
        // Bind the credential to its owner and randomness via the shared ZKA
        // commitment primitive, using the credential_commitment as the asset
        // and (credential_data, context, attr0..attr3) as the value slot.
        //
        // EVERY CredNote field is bound here. That is load-bearing, not
        // incidental: the note hash is the ONLY content constraint the
        // framework applies to a prover-supplied (hinted) note. `get_notes`
        // fetches notes from an unconstrained oracle and the sole check is
        // `compute_note_hash` (aztec-nr note/utils.nr -> assert_note_exists);
        // `check_packed_note` constrains nothing unless the caller passes
        // selects, and `_verify_credential` passes `NoteGetterOptions::new()`.
        // Anything omitted from this hash is therefore a free witness the
        // prover may substitute at will.
        //
        // In particular attr0..attr3 (KYC, jurisdiction, source-of-funds,
        // accreditation) MUST stay in this hash. They are NOT covered by
        // credential_commitment: derive_credential_commitment(cbk) =
        // H2(DOMAIN_ZKC_BINDING, cbk) is a pure function of key material and
        // takes no attribute input, so it is constant for a given owner and
        // cannot carry an attribute binding. Omitting the attributes would let
        // a prover disclose arbitrary compliance values for a real,
        // non-revoked credential.
        // `context` IS bound so a disclose_to note's session cannot be altered.
        //
        // This hash is a NOTE-STORAGE INTEGRITY binding; it is NOT the
        // cross-env disclosure artifact -- that remains the raw
        // context-independent credential_data (docs/adr/0001, Option A).
        // Poseidon2 absorbs the message length into the sponge IV
        // (iv = len * 2^64), so the 6-input encoding is domain-separated from
        // the 2-input H2(credential_data, context) it replaces: no input to
        // one can be reinterpreted as an input to the other. That is
        // separation of encodings, NOT a collision-freedom claim -- both
        // still produce a single Field, so equal outputs remain possible to
        // the usual collision bound of the hash.
        let value_slot = zka_lib::poseidon_hash([
            self.credential_data,
            self.context,
            self.attr0,
            self.attr1,
            self.attr2,
            self.attr3,
        ]);
        zka_lib::compute_note_commitment(
            self.credential_commitment,
            value_slot,
            owner.to_field(),
            randomness,
        )
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
// Credential helpers
// =============================================================================

/// Maximum attributes per credential
pub global MAX_ATTRIBUTES: u32 = 4;

// Credential attribute index conventions for named disclosure functions.
// These map to the 4 attribute slots in CredNote.
pub global ATTR_KYC: u32 = 0;
pub global ATTR_JURISDICTION: u32 = 1;
pub global ATTR_SOURCE_OF_FUNDS: u32 = 2;
pub global ATTR_ACCREDITATION: u32 = 3;

// Pre-computed disclosure masks (big-endian 4-bit) for named functions.
// Bit i (from MSB) controls attributes[i].
pub global MASK_KYC: Field = 8; // 0b1000 -> attr 0
pub global MASK_JURISDICTION: Field = 4; // 0b0100 -> attr 1
pub global MASK_SOURCE_OF_FUNDS: Field = 2; // 0b0010 -> attr 2
pub global MASK_ACCREDITATION: Field = 1; // 0b0001 -> attr 3
pub global MASK_FULL_COMPLIANCE: Field = 15; // 0b1111 -> all attrs

/// Compute selective disclosure hash (matches standalone zka_credential circuit).
/// mask_bits[i] = true -> disclose attributes[i]; false -> substitute 0.
pub fn compute_disclosed_hash(
    credential_data: Field,
    attributes: [Field; 4],
    mask_bits: [bool; 4],
) -> Field {
    let mut acc = credential_data;
    for i in 0..MAX_ATTRIBUTES {
        let disclosed_val = if mask_bits[i] { attributes[i] } else { 0 };
        acc = zka_lib::poseidon2(acc, disclosed_val);
    }
    acc
}

/// Aggregate two disclosure hashes into a single commitment.
/// Used for multi-attribute compliance proofs that combine separate disclosures.
pub fn aggregate_disclosed_hashes(hash_a: Field, hash_b: Field) -> Field {
    zka_lib::poseidon2(hash_a, hash_b)
}

// =============================================================================
// Credential revocation nullifier (ZKA SS5.8)
//
// ZKACredential.revoke(cc) emits revocation_nullifier(cc) as an inner nullifier
// in its own silo, and verify_compliance proves its non-inclusion. The tag
// keeps the admin-chosen input out of every other nullifier domain of that
// contract: hitting a CredNote or initialization nullifier would need a
// Poseidon2 preimage. Anyone who knows cc can compute the value, as before.
// =============================================================================

/// Owner-qualified fixed-byte tag `zka/aztec/revocation/v1`, interpreted as an
/// unsigned big-endian BN254 scalar after left-zero-padding to 32 bytes.
pub global DOMAIN_AZTEC_REVOCATION_V1: Field =
    0x0000000000000000007a6b612f617a7465632f7265766f636174696f6e2f7631;

/// Inner revocation nullifier of a ZKC holderCommitment:
/// H2("zka/aztec/revocation/v1", credential_commitment).
pub fn revocation_nullifier(credential_commitment: Field) -> Field {
    zka_lib::poseidon2(DOMAIN_AZTEC_REVOCATION_V1, credential_commitment)
}

// =============================================================================
// Credential issuance authentication
//
// ZKACredential.bind_credential stores a credential only when the pinned
// issuer signed it. The issuer signs, with ECDSA over secp256k1 (the ZKC
// mandatory issuer-signature profile), the SHA-256 digest of a fixed 320-byte
// transcript. Each slot is 32 bytes, fields big-endian:
//
//   [0]  ISSUANCE_TRANSCRIPT_TAG ("zka/aztec/credential-issuance/v1")
//   [1]  chain_id     [2] version     [3] credential contract address
//   [4]  holder_commitment (the ZKC holderCommitment the contract derives)
//   [5]  credential_data
//   [6..9] attributes[0..3]
//
// The transcript names holderCommitment, not an Aztec address, so the issuer
// never learns the holder's address. The contract recomputes holderCommitment
// from the caller's own key, so a signature is usable only by that holder, in
// that contract instance, on that chain. SHA-256 rather than Poseidon2 keeps
// the transcript out of the Poseidon2 operational-domain inventory.
// =============================================================================

/// Fixed 32-byte transcript tag of the issuance signature.
pub global ISSUANCE_TRANSCRIPT_TAG: str<32> = "zka/aztec/credential-issuance/v1";

/// Uncompressed secp256k1 public key of the pinned credential issuer.
#[derive(Deserialize, Eq, Serialize)]
pub struct IssuerKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

fn pack_u128_halves(bytes: [u8; 32]) -> (Field, Field) {
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + bytes[i] as Field;
        lo = lo * 256 + bytes[16 + i] as Field;
    }
    (hi, lo)
}

fn unpack_u128_halves(hi: Field, lo: Field) -> [u8; 32] {
    let hi_bytes: [u8; 16] = hi.to_be_bytes();
    let lo_bytes: [u8; 16] = lo.to_be_bytes();
    let mut out: [u8; 32] = [0; 32];
    for i in 0..16 {
        out[i] = hi_bytes[i];
        out[16 + i] = lo_bytes[i];
    }
    out
}

// Packed as four 128-bit halves (x_hi, x_lo, y_hi, y_lo). The derived
// byte-per-field packing would need 64 public storage writes, more than one
// transaction may make.
impl Packable for IssuerKey {
    let N: u32 = 4;

    fn pack(self) -> [Field; Self::N] {
        let (x_hi, x_lo) = pack_u128_halves(self.x);
        let (y_hi, y_lo) = pack_u128_halves(self.y);
        [x_hi, x_lo, y_hi, y_lo]
    }

    fn unpack(packed: [Field; Self::N]) -> Self {
        IssuerKey {
            x: unpack_u128_halves(packed[0], packed[1]),
            y: unpack_u128_halves(packed[2], packed[3]),
        }
    }
}

impl IssuerKey {
    /// An all-zero key is the unset value; it is never a valid issuer key.
    pub fn is_zero(self) -> bool {
        let mut zero = true;
        for i in 0..32 {
            zero &= (self.x[i] == 0) & (self.y[i] == 0);
        }
        zero
    }
}

// Canonical (< p) 32-byte big-endian slot, via decompose into two 128-bit
// limbs (same construction as zka_transfer_aztec::withdrawal). A raw 32-byte
// decomposition admits x, x+p, ... as witnesses
// (aztec/scripts/check-field-encoding-canonicity.sh); a non-canonical slot
// could only fail the signature check, but the transcript must still be a
// function of its inputs.
fn write_slot(mut out: [u8; 320], slot: u32, value: Field) -> [u8; 320] {
    let (lo, hi) = decompose(value);
    let hi_bytes: [u8; 16] = hi.to_be_bytes();
    let lo_bytes: [u8; 16] = lo.to_be_bytes();
    for i in 0..16 {
        out[slot * 32 + i] = hi_bytes[i];
        out[slot * 32 + 16 + i] = lo_bytes[i];
    }
    out
}

/// The issuance transcript (layout above).
pub fn issuance_transcript(
    chain_id: Field,
    version: Field,
    credential_contract: AztecAddress,
    holder_commitment: Field,
    credential_data: Field,
    attributes: [Field; 4],
) -> [u8; 320] {
    let mut out: [u8; 320] = [0; 320];
    let tag = ISSUANCE_TRANSCRIPT_TAG.as_bytes();
    for i in 0..32 {
        out[i] = tag[i];
    }
    out = write_slot(out, 1, chain_id);
    out = write_slot(out, 2, version);
    out = write_slot(out, 3, credential_contract.to_field());
    out = write_slot(out, 4, holder_commitment);
    out = write_slot(out, 5, credential_data);
    for i in 0..MAX_ATTRIBUTES {
        out = write_slot(out, 6 + i, attributes[i]);
    }
    out
}

/// SHA-256 digest of the issuance transcript: the message the issuer signs.
pub fn issuance_digest(
    chain_id: Field,
    version: Field,
    credential_contract: AztecAddress,
    holder_commitment: Field,
    credential_data: Field,
    attributes: [Field; 4],
) -> [u8; 32] {
    sha256::digest(issuance_transcript(
        chain_id,
        version,
        credential_contract,
        holder_commitment,
        credential_data,
        attributes,
    ))
}

/// Verify an ECDSA secp256k1 issuer signature (r || s, 64 bytes) over `digest`.
pub fn verify_issuer_signature(issuer: IssuerKey, signature: [u8; 64], digest: [u8; 32]) -> bool {
    std::ecdsa_secp256k1::verify_signature(issuer.x, issuer.y, signature, digest)
}

// NOTE (docs/adr/0001, Option A): there is intentionally NO disclosure-context
// fold helper here. The v0.6.0 SS5.2 canonical model binds `context` as a
// SEPARATE co-equal value (a public input in the standalone circuit; a separate
// CredNote field / function argument in Aztec), NOT folded into the disclosed
// hash. The disclosed hash exposed by both environments is the raw,
// context-independent `compute_disclosed_hash` output, as required by the
// normative specification and ZKC claimBinding model.

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_key_derivation_consistency() {
    let nsk_app: Field = 0x42;

    let zka_sk = aztec_nsk_to_zka_sk(nsk_app);
    let expected_sk = zka_lib::derive_spending_key_from_master_seed(nsk_app);
    assert(zka_sk == expected_sk, "nsk_app must derive the ZKA spending key");

    let vk = derive_zka_viewing_key(nsk_app);
    let expected_vk = zka_lib::derive_viewing_key(expected_sk);
    assert(vk == expected_vk, "Viewing key must match zka_lib derivation");

    let addr = derive_zka_address(nsk_app);
    let expected_addr = zka_lib::derive_address(expected_sk);
    assert(addr == expected_addr, "Address must match zka_lib derivation");

    let cbk = derive_zka_cbk(nsk_app);
    let expected_cbk = zka_lib::derive_credential_binding_key(nsk_app);
    assert(cbk == expected_cbk, "CBK must match zka_lib derivation");
}

#[test]
fn test_zka_note_hash_matches_standalone() {
    let asset_commitment: Field = 0x01;
    let value: Field = 1000;
    let recipient: Field = 0xdeadbeef;
    let randomness: Field = 0xaabb;

    let standalone_hash =
        zka_lib::compute_note_commitment(asset_commitment, value, recipient, randomness);

    let note = ZKANote { asset_commitment, value };
    let owner = AztecAddress::from_field(recipient);
    // compute_note_hash must produce the same value as the standalone circuit;
    // the storage_slot argument is ignored by the ZKA commitment scheme.
    let aztec_hash = note.compute_note_hash(owner, 0, randomness);

    assert(standalone_hash == aztec_hash, "ZKANote hash must match standalone circuit");
}

// The note hash is the only content constraint applied to a prover-supplied
// CredNote, so every field must change it. These tests require each value-slot
// field to affect the hash.
#[test]
fn test_cred_note_hash_binds_every_attribute() {
    let credential_commitment: Field = 0xc0ffee;
    let credential_data: Field = 0xaaaa;
    let context: Field = 0xdeadbeef;
    let owner = AztecAddress::from_field(0xbeef);
    let randomness: Field = 0xaabb;
    let base: [Field; 4] = [11, 22, 33, 44];

    let base_hash = CredNote::new(credential_commitment, credential_data, context, base)
        .compute_note_hash(owner, 0, randomness);

    // Flip each attribute slot in isolation; every one must move the hash.
    for i in 0..MAX_ATTRIBUTES {
        let mut mutated = base;
        mutated[i] = base[i] + 1;
        let mutated_hash = CredNote::new(credential_commitment, credential_data, context, mutated)
            .compute_note_hash(owner, 0, randomness);
        assert(
            base_hash != mutated_hash,
            "CredNote note hash must bind every attribute slot -- an unbound slot is a free witness",
        );
    }
}

#[test]
fn test_cred_note_hash_is_deterministic_and_binds_data_and_context() {
    let credential_commitment: Field = 0xc0ffee;
    let credential_data: Field = 0xaaaa;
    let context: Field = 0xdeadbeef;
    let owner = AztecAddress::from_field(0xbeef);
    let randomness: Field = 0xaabb;
    let attributes: [Field; 4] = [11, 22, 33, 44];

    let note = CredNote::new(credential_commitment, credential_data, context, attributes);
    let hash = note.compute_note_hash(owner, 0, randomness);

    let repeat = CredNote::new(credential_commitment, credential_data, context, attributes)
        .compute_note_hash(owner, 0, randomness);
    assert(hash == repeat, "CredNote note hash must be deterministic");

    let other_data = CredNote::new(
        credential_commitment,
        credential_data + 1,
        context,
        attributes,
    )
        .compute_note_hash(owner, 0, randomness);
    assert(hash != other_data, "CredNote note hash must bind credential_data");

    let other_context = CredNote::new(
        credential_commitment,
        credential_data,
        context + 1,
        attributes,
    )
        .compute_note_hash(owner, 0, randomness);
    assert(hash != other_context, "CredNote note hash must bind context");
}

#[test]
fn test_disclosed_hash_matches_standalone() {
    let credential_data: Field = 0xaaaa;
    let attributes: [Field; 4] = [100, 200, 300, 400];
    let mask_bits: [bool; 4] = [true, false, true, false];

    let hash = compute_disclosed_hash(credential_data, attributes, mask_bits);

    // Manual computation matching zka_credential circuit
    let mut acc = credential_data;
    acc = zka_lib::poseidon2(acc, 100); // disclosed
    acc = zka_lib::poseidon2(acc, 0); // masked
    acc = zka_lib::poseidon2(acc, 300); // disclosed
    acc = zka_lib::poseidon2(acc, 0); // masked

    assert(hash == acc, "Disclosed hash must match standalone credential circuit");
}

#[test]
fn test_aggregate_disclosed_hashes() {
    let credential_data: Field = 0xaaaa;
    let attributes: [Field; 4] = [100, 200, 300, 400];

    let mask_a: [bool; 4] = [true, false, false, false]; // KYC only
    let mask_b: [bool; 4] = [false, true, false, false]; // Jurisdiction only

    let hash_a = compute_disclosed_hash(credential_data, attributes, mask_a);
    let hash_b = compute_disclosed_hash(credential_data, attributes, mask_b);
    let agg = aggregate_disclosed_hashes(hash_a, hash_b);

    // Aggregation must be deterministic
    let agg2 = aggregate_disclosed_hashes(hash_a, hash_b);
    assert(agg == agg2, "Aggregation must be deterministic");

    // Aggregation must differ from individual hashes
    assert(agg != hash_a, "Aggregate must differ from hash_a");
    assert(agg != hash_b, "Aggregate must differ from hash_b");

    // Order matters (not commutative -- prevents replay with swapped proofs)
    let agg_reversed = aggregate_disclosed_hashes(hash_b, hash_a);
    assert(agg != agg_reversed, "Aggregation must not be commutative");
}

#[test]
fn test_compliance_mask_constants() {
    // Verify mask constants match expected bit patterns
    assert(MASK_KYC == 8, "KYC mask must be 0b1000");
    assert(MASK_JURISDICTION == 4, "Jurisdiction mask must be 0b0100");
    assert(MASK_SOURCE_OF_FUNDS == 2, "Source of funds mask must be 0b0010");
    assert(MASK_ACCREDITATION == 1, "Accreditation mask must be 0b0001");
    assert(MASK_FULL_COMPLIANCE == 15, "Full compliance mask must be 0b1111");

    // Named masks must produce different disclosed hashes
    let cred_data: Field = 0xaaaa;
    let attrs: [Field; 4] = [100, 200, 300, 400];

    let h_kyc = compute_disclosed_hash(cred_data, attrs, [true, false, false, false]);
    let h_jur = compute_disclosed_hash(cred_data, attrs, [false, true, false, false]);
    let h_sof = compute_disclosed_hash(cred_data, attrs, [false, false, true, false]);
    let h_acc = compute_disclosed_hash(cred_data, attrs, [false, false, false, true]);

    assert(h_kyc != h_jur, "KYC and jurisdiction hashes must differ");
    assert(h_jur != h_sof, "Jurisdiction and SoF hashes must differ");
    assert(h_sof != h_acc, "SoF and accreditation hashes must differ");
    assert(h_kyc != h_acc, "KYC and accreditation hashes must differ");
}

// KAT for the revocation domain. The tag value is the fixed-byte encoding of
// "zka/aztec/revocation/v1"; the expected hash was computed independently with
// zka_crypto::hash::poseidon2_bn254::poseidon2_hash_bn254 (Rust reference).
#[test]
fn test_revocation_nullifier_kat() {
    assert(
        DOMAIN_AZTEC_REVOCATION_V1
            == 0x0000000000000000007a6b612f617a7465632f7265766f636174696f6e2f7631,
        "revocation tag must be the fixed-byte encoding of zka/aztec/revocation/v1",
    );
    assert(
        revocation_nullifier(0xc0ffee)
            == 0x19bc9bd627e764502df7fd19d3d0f49b53905f92a81ee8ab66f061435c406be3,
        "revocation nullifier must match the Rust reference KAT",
    );
    assert(revocation_nullifier(0xc0ffee) != 0xc0ffee, "the inner nullifier must not be raw cc");
}

// Issuance KATs. Expected values come from aztec/scripts/issuer_test_signatures.py
// (Python hashlib SHA-256 and an independent secp256k1 signer), so these tests
// pin the Noir transcript layout, the sha256 dependency and the ECDSA
// blackbox against an implementation outside Noir. Keys are TEST-ONLY.
global KAT_TRUSTED_KEY: IssuerKey = IssuerKey {
    x: [
        0x49, 0x41, 0xcc, 0xa4, 0xdd, 0x2f, 0x71, 0x88, 0x76, 0x9e, 0xe2, 0x56, 0xc4, 0x71, 0x12,
        0xd3, 0xb6, 0x6e, 0xe3, 0x5c, 0x3f, 0xbc, 0x61, 0xc4, 0xbd, 0xed, 0xf9, 0x0e, 0x34, 0x79,
        0xb9, 0x3b,
    ],
    y: [
        0x81, 0x72, 0xad, 0xc3, 0x03, 0x4c, 0x17, 0x27, 0x3a, 0xbb, 0xa1, 0x3d, 0xf3, 0xa0, 0x59,
        0xcf, 0x83, 0xb8, 0x62, 0xe6, 0x65, 0xee, 0xb0, 0xf9, 0xf8, 0xfd, 0x44, 0x54, 0xab, 0x43,
        0x23, 0x4f,
    ],
};

global KAT_UNTRUSTED_KEY: IssuerKey = IssuerKey {
    x: [
        0x19, 0x04, 0x61, 0x4c, 0x04, 0x01, 0xfd, 0x8f, 0x4e, 0xf7, 0x50, 0x13, 0xd5, 0xec, 0xcb,
        0x45, 0x3c, 0xf3, 0x84, 0x0c, 0x68, 0x4d, 0x5a, 0xc9, 0x2e, 0x40, 0x6f, 0x09, 0x60, 0xd0,
        0x66, 0x0f,
    ],
    y: [
        0x23, 0x92, 0x7d, 0x0a, 0x19, 0x3d, 0x84, 0x21, 0x2d, 0x95, 0xcb, 0x1e, 0x35, 0xf1, 0xe9,
        0x8a, 0xae, 0x64, 0xb0, 0x8f, 0xbc, 0x73, 0xf0, 0xbc, 0x95, 0x6a, 0x30, 0xb5, 0x9f, 0xd5,
        0xe9, 0x5f,
    ],
};

// issuance_digest(1, 2, 3, 4, 5, [6, 7, 8, 9])
global KAT_DIGEST: [u8; 32] = [
    0xdc, 0x41, 0x16, 0x30, 0x4a, 0xfd, 0xc5, 0xd3, 0x0d, 0x78, 0x87, 0xa8, 0x63, 0x88, 0xbc, 0x81,
    0x7a, 0x41, 0xf8, 0x33, 0x48, 0xc9, 0x3d, 0x98, 0x27, 0x7a, 0xf5, 0x48, 0x60, 0xbb, 0xd8, 0xb0,
];

// Trusted-key signature over KAT_DIGEST.
global KAT_TRUSTED_SIG: [u8; 64] = [
    0xc6, 0x0a, 0x9b, 0xcc, 0x64, 0xb1, 0xb6, 0xbe, 0x0c, 0xb8, 0x6a, 0x2b, 0xef, 0xf9, 0x3c, 0x04,
    0xbb, 0x0c, 0x20, 0xc7, 0xeb, 0x26, 0xb1, 0x73, 0x9d, 0xad, 0xa5, 0x18, 0x11, 0x18, 0xfe, 0xc9,
    0x64, 0x7c, 0xf9, 0xd6, 0x2f, 0xd3, 0x28, 0x1d, 0xf6, 0x9c, 0x00, 0xf0, 0xc8, 0xcb, 0xf6, 0x94,
    0x93, 0xb3, 0xae, 0xe0, 0xfe, 0x54, 0x49, 0x38, 0x51, 0xe1, 0xec, 0xc0, 0x37, 0x49, 0x4a, 0xb3,
];

// Untrusted-key signature over KAT_DIGEST.
global KAT_UNTRUSTED_SIG: [u8; 64] = [
    0x23, 0x26, 0x69, 0xb8, 0xeb, 0x17, 0x82, 0xfe, 0x4a, 0x9e, 0x50, 0x07, 0x66, 0xae, 0xb3, 0xfe,
    0x15, 0x99, 0xa5, 0xaf, 0xab, 0x60, 0x0a, 0x73, 0x2b, 0x75, 0xa5, 0x97, 0x33, 0xd8, 0x45, 0x46,
    0x0f, 0x7d, 0x12, 0xab, 0x0d, 0x55, 0x2c, 0xbb, 0xd0, 0x16, 0xd9, 0xb1, 0x80, 0x81, 0x4a, 0x2c,
    0xca, 0x3c, 0xc3, 0x08, 0x86, 0x5a, 0x57, 0x41, 0x32, 0x2a, 0x71, 0x8f, 0xbd, 0x58, 0x2a, 0x43,
];

fn kat_digest_with(slot: u32, value: Field) -> [u8; 32] {
    let mut v: [Field; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    v[slot] = value;
    issuance_digest(
        v[0],
        v[1],
        AztecAddress::from_field(v[2]),
        v[3],
        v[4],
        [v[5], v[6], v[7], v[8]],
    )
}

#[test]
fn test_issuance_transcript_layout() {
    let t = issuance_transcript(1, 2, AztecAddress::from_field(3), 4, 5, [6, 7, 8, 9]);
    let tag = ISSUANCE_TRANSCRIPT_TAG.as_bytes();
    for i in 0..32 {
        assert(t[i] == tag[i], "slot 0 must be the transcript tag");
    }
    for slot in 1..10 {
        for i in 0..31 {
            assert(t[slot * 32 + i] == 0, "field slots are 32-byte big-endian");
        }
        assert(t[slot * 32 + 31] == slot as u8, "slot order must match the documented layout");
    }
}

#[test]
fn test_issuance_digest_kat() {
    assert(kat_digest_with(0, 1) == KAT_DIGEST, "issuance digest must match the Python KAT");
}

#[test]
fn test_issuer_signature_accepts_pinned_key() {
    assert(
        verify_issuer_signature(KAT_TRUSTED_KEY, KAT_TRUSTED_SIG, KAT_DIGEST),
        "the pinned issuer's signature must verify",
    );
}

#[test]
fn test_issuer_signature_rejects_other_key() {
    assert(
        !verify_issuer_signature(KAT_TRUSTED_KEY, KAT_UNTRUSTED_SIG, KAT_DIGEST),
        "a signature by another key must not verify under the pinned key",
    );
    assert(
        verify_issuer_signature(KAT_UNTRUSTED_KEY, KAT_UNTRUSTED_SIG, KAT_DIGEST),
        "control: the other key's signature is itself valid",
    );
}

#[test]
fn test_issuer_signature_binds_every_transcript_field() {
    for slot in 0..9 {
        let digest = kat_digest_with(slot, 0x77);
        assert(digest != KAT_DIGEST, "every transcript field must change the digest");
        assert(
            !verify_issuer_signature(KAT_TRUSTED_KEY, KAT_TRUSTED_SIG, digest),
            "a signature must not verify after any transcript field changes",
        );
    }
}

#[test]
fn test_issuer_signature_rejects_zero_signature() {
    assert(
        !verify_issuer_signature(KAT_TRUSTED_KEY, [0; 64], KAT_DIGEST),
        "an all-zero signature must not verify",
    );
}

#[test]
fn test_issuer_key_pack_roundtrip() {
    let packed = KAT_TRUSTED_KEY.pack();
    assert(packed[0] == 0x4941cca4dd2f7188769ee256c47112d3, "x_hi is the first 16 bytes of x");
    assert(packed[3] == 0x83b862e665eeb0f9f8fd4454ab43234f, "y_lo is the last 16 bytes of y");
    assert(IssuerKey::unpack(packed) == KAT_TRUSTED_KEY, "pack/unpack must round-trip");
}

#[test]
fn test_issuer_key_zero_detection() {
    assert(IssuerKey { x: [0; 32], y: [0; 32] }.is_zero(), "all-zero key is unset");
    assert(!KAT_TRUSTED_KEY.is_zero(), "a real key is not zero");
}
