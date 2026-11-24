// =============================================================================
// ZKA Shared Library for Noir Circuits
//
// Canonical cryptographic primitives used by all ZKA circuits.
// AFP-tagged domain separators are Blake2b512("ZKA-Domain-" || tag) mod
// BN254.Fr, matching src/zka-crypto/src/hash/bn254_domain.rs. Explicitly
// documented fixed-byte tags use their owner-qualified UTF-8 bytes directly.
//
// Hash function: Poseidon2 via poseidon::poseidon2::Poseidon2 (external noir-lang/poseidon)
// Merkle tree: custom Poseidon2-based implementation (std::merkle removed in beta.21)
// =============================================================================

use poseidon::poseidon2::Poseidon2;

mod sparse_nullifier;
pub use sparse_nullifier::{NULLIFIER_TREE_DEPTH, verify_nullifier_absent_and_insert};

// =============================================================================
// Canonical Domain Separators
//
// AFP-tagged constants are computed by
// src/zka-crypto/src/hash/bn254_domain.rs::domain_separator_bn254(). ContextV1
// below is the governed fixed-byte exception described at its declaration.
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
pub global DOMAIN_ZKC_CREDENTIAL: Field =
    0x3010b194aeae94550e7a48d065d9dc931108c2d15136704bf4ad78eae07f0e26;
pub global DOMAIN_ZKC_BINDING: Field =
    0x12b8b6de2c8fc6b63102155d15c31799845a1f360ab0df6266284bde48e3a93f;
// ZKC v0.4: derive_domain("zkc/presentation-scope:v1").
pub global DOMAIN_ZKC_PRESENTATION_SCOPE: Field =
    0x2f7a94a38bb647d343fc7abc74b6466fe1eb566d71c185cc9537b7e768c466ae;
pub global DOMAIN_ZKA_NOTE: Field =
    0x09a4260bf4256607461da644a2ee12d3e78c2aafb37427a010b4f3c7e021a72e;
pub global DOMAIN_ZKA_ASSET: Field =
    0x078574d1857e778c075008cf155293bda6a75e7146a12a32692271782baf7d30;
pub global DOMAIN_ZKA_COMMITMENT: Field =
    0x0d574a2db0485ef65bee07d885fc5874f66989c7f56a1b6750fac9fcfb5d11c9;
/// Owner-qualified fixed-byte tag `zka/namada/proof-context/v1`, interpreted
/// as an unsigned big-endian BN254 scalar after left-zero-padding to 32 bytes.
pub global DOMAIN_NAMADA_PROOF_CONTEXT_V1: Field =
    0x00000000007a6b612f6e616d6164612f70726f6f662d636f6e746578742f7631;

/// Merkle tree depth (matches Halo 2 implementation)
pub global MERKLE_DEPTH: u32 = 32;

// Poseidon2 empty-tree root at depth 32 with leaf = 0.
// Computed: H_0=0, H_{i+1}=poseidon2(H_i, H_i) for i in 0..32.
// Verified by the kat_poseidon2_empty_root_depth_32 test below.
// Used by zka_root_update and any circuit that needs the genesis root.
pub global POSEIDON2_EMPTY_ROOT_DEPTH_32: Field =
    0x0b59baa35b9dc267744f0ccb4e3b0255c1fc512460d91130c6bc19fb2668568d;

// 2^160 -- the smallest value that does NOT fit in a 20-byte L1 address.
pub global TWO_POW_160: Field = 0x10000000000000000000000000000000000000000;

/// 2^64 - 1 -- the saturating maximum of the ZKA balance value domain.
/// Canonical `upper_bound` for proof_type 0, so `v >= T` and
/// `v in [T, U64_MAX]` are the SAME statement, not an approximation.
pub global U64_MAX: Field = 0xffffffffffffffff;

// =============================================================================
// L1 address bounds
// =============================================================================

/// Assert that `v` fits in a 20-byte L1 (Ethereum) address, i.e. v < 2^160.
///
/// Shared cross-environment because every ZKA exit path eventually right-aligns
/// a recipient into a 32-byte L1 word, and Solidity's `address` type occupies
/// only the low 20 of those bytes. A recipient wider than 20 bytes therefore has
/// NO valid L1 encoding: on the Aztec portal path it produces an L2->L1 message
/// content hash that `abi.encode(address)` can never reproduce (funds burned on
/// L2 become unrecoverable), and on the Ethereum pool/bridge paths it describes
/// a recipient the settling contract's `address` parameter cannot express.
///
/// A circuit should state this bound itself rather than inherit it from a
/// contract's parameter type: the constraint is a property of the encoding, not
/// of any one caller.
///
/// `assert_max_bit_size` is the stdlib's purpose-built range check -- 1 ACIR
/// opcode, and verified to survive dead-code elimination even when the checked
/// value has no other use (unlike a bare `as` cast, which is silently dropped;
/// see the u128 notes in zka_transfer_aztec/src/conservation.nr). Its failure
/// message is compiler-generated, so the `should_fail_with` tests below pin the
/// exact string: a toolchain bump that changes it fails loudly in CI rather than
/// silently weakening the tests.
pub fn assert_fits_u160(v: Field) {
    v.assert_max_bit_size::<160>();
}

/// Assert `v` fits in the u64 balance domain. Uses `assert_max_bit_size`
/// for the same reason `assert_fits_u160` does: 1 ACIR opcode, and it
/// survives dead-code elimination even when the checked value has no
/// other use (a bare `as u64` cast round-trip is DCE-fragile).
pub fn assert_fits_u64(v: Field) {
    v.assert_max_bit_size::<64>();
}

// =============================================================================
// Poseidon2 Hash Wrappers
// =============================================================================

/// Hash an arbitrary-length field array with Poseidon2.
pub fn poseidon_hash<let N: u32>(inputs: [Field; N]) -> Field {
    Poseidon2::hash(inputs, N)
}

/// Hash 2 field elements with Poseidon2
pub fn poseidon2(a: Field, b: Field) -> Field {
    poseidon_hash([a, b])
}

/// Hash 3 field elements with Poseidon2
pub fn poseidon3(a: Field, b: Field, c: Field) -> Field {
    poseidon_hash([a, b, c])
}

/// Hash 4 field elements with Poseidon2
pub fn poseidon4(a: Field, b: Field, c: Field, d: Field) -> Field {
    poseidon_hash([a, b, c, d])
}

// =============================================================================
// Note Commitment
//
// Two-layer construction:
//   inner = H(asset_commitment, value, recipient)
//   commitment = H(inner, randomness)
//
// The asset_commitment is a public input identifying the asset type.
// =============================================================================

/// Compute note commitment (canonical two-layer construction)
pub fn compute_note_commitment(
    asset_commitment: Field,
    value: Field,
    recipient: Field,
    randomness: Field,
) -> Field {
    let inner = poseidon3(asset_commitment, value, recipient);
    poseidon2(inner, randomness)
}

// =============================================================================
// Nullifier
//
// Two-step construction:
//   intermediate = H(DOMAIN_ZKA_NULLIFIER, commitment)
//   nullifier = H(intermediate, spending_key)
// =============================================================================

/// Compute nullifier for a note
pub fn compute_nullifier(commitment: Field, spending_key: Field) -> Field {
    let intermediate = poseidon2(DOMAIN_ZKA_NULLIFIER, commitment);
    poseidon2(intermediate, spending_key)
}

// =============================================================================
// Key Derivation
//
// spending_key -> viewing_key = H(DOMAIN_VIEWING, sk)
// viewing_key  -> address     = H(DOMAIN_ADDRESS, vk)
// =============================================================================

/// Derive viewing key from spending key
pub fn derive_viewing_key(spending_key: Field) -> Field {
    poseidon2(DOMAIN_ZKA_VIEWING, spending_key)
}

/// Derive address from viewing key
pub fn derive_address_from_vk(viewing_key: Field) -> Field {
    poseidon2(DOMAIN_ZKA_ADDRESS, viewing_key)
}

/// Derive address from spending key (convenience)
pub fn derive_address(spending_key: Field) -> Field {
    let vk = derive_viewing_key(spending_key);
    derive_address_from_vk(vk)
}

/// Derive proof authorizing key from spending key
pub fn derive_proof_key(spending_key: Field) -> Field {
    poseidon2(DOMAIN_ZKA_PROOF, spending_key)
}

/// AFP-KDC v1.0.2 §A.6 credential binding key. `master_seed` is the
/// big-endian-reduced seed field and is a sibling input to spending-key
/// derivation; callers MUST NOT pass the spending key here.
pub fn derive_credential_binding_key(master_seed: Field) -> Field {
    poseidon2(DOMAIN_ZKC_CREDENTIAL, master_seed)
}

/// AFP-KDC v1.0.2 §A.6 `holderCommitment = H("zkc/binding", cbk)`.
pub fn derive_credential_commitment(credential_binding_key: Field) -> Field {
    poseidon2(DOMAIN_ZKC_BINDING, credential_binding_key)
}

/// Compatibility alias for ZKC v0.4 callers. Prefer
/// `derive_credential_binding_key` for AFP-KDC v1.0.2 code.
pub fn derive_zkc_v04_credential_binding_key(master_seed: Field) -> Field {
    derive_credential_binding_key(master_seed)
}

/// Explicit pre-AFP-KDC legacy profile: `cbk = H("zkc/binding", sk)`.
pub fn derive_legacy_v1_credential_binding_key(spending_key: Field) -> Field {
    poseidon2(DOMAIN_ZKC_BINDING, spending_key)
}

/// Explicit pre-AFP-KDC legacy profile:
/// `holderCommitment = H("zkc/credential", legacy_cbk)`.
pub fn derive_legacy_v1_credential_commitment(credential_binding_key: Field) -> Field {
    poseidon2(DOMAIN_ZKC_CREDENTIAL, credential_binding_key)
}

/// ZKC holder anchor `holderCommitment = H("zkc/binding", cbk)`.
pub fn derive_zkc_holder_commitment(credential_binding_key: Field) -> Field {
    derive_credential_commitment(credential_binding_key)
}
/// ZKA spending key derived from the same master seed used by ZKC v0.4.
pub fn derive_spending_key_from_master_seed(master_seed: Field) -> Field {
    poseidon2(DOMAIN_ZKA_SPENDING, master_seed)
}

/// ZKC v0.4 scoped pseudonym. Scope zero is reserved for anonymous proofs.
pub fn derive_presentation_pseudonym(credential_binding_key: Field, scope_id: Field) -> Field {
    assert(scope_id != 0, "scope_id 0 is the anonymous sentinel");
    poseidon3(
        DOMAIN_ZKC_PRESENTATION_SCOPE,
        credential_binding_key,
        scope_id,
    )
}

/// Enforce the ZKC v0.4 anonymous/scoped public-input shape.
pub fn assert_presentation_binding(
    presentation_pseudonym: Field,
    scope_id: Field,
    credential_binding_key: Field,
) {
    if scope_id == 0 {
        assert(presentation_pseudonym == 0, "anonymous profile must not carry a pseudonym");
    } else {
        assert(
            presentation_pseudonym
                == derive_presentation_pseudonym(credential_binding_key, scope_id),
            "scoped presentation pseudonym mismatch",
        );
    }
}

// =============================================================================
// Merkle Tree Verification (Poseidon2-based, std::merkle removed in beta.21)
// =============================================================================

/// Compute a depth-32 Merkle root by folding `leaf` with `siblings`,
/// selecting child order from the bits of `path_index`. Uses Poseidon2
/// for internal nodes (consistent with all other ZKA hashing).
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
// Asset Commitment
// =============================================================================

/// Compute asset commitment from asset descriptor
pub fn compute_asset_commitment(asset_id: Field) -> Field {
    poseidon2(DOMAIN_ZKA_ASSET, asset_id)
}

/// Project an L1-anchored asset id into a Field (cross-environment; see ADR 0003).
///
/// `digest_be` is the 32-byte big-endian keccak digest from Ethereum
/// (`assetId = keccak256(abi.encode(chainId, token))`). The canonical field is its low 248
/// bits: the top byte is dropped, so the value is `< 2^248 < the BN254 modulus`. This MUST
/// match the Solidity `assetIdField` and the `zka-crypto` reference (golden pinned in the
/// test below).
pub fn l1_asset_id_field(digest_be: [u8; 32]) -> Field {
    let mut acc: Field = 0;
    // Fold bytes [1..32] big-endian (byte 0, the top 8 bits, is dropped).
    for i in 1..32 {
        acc = acc * 256 + digest_be[i] as Field;
    }
    acc
}

// =============================================================================
// Context Binding
// =============================================================================

/// Compute the consensus-bound Namada proof context.
///
/// The six digest limbs are the two big-endian u128 halves of their respective
/// canonical 32-byte digests. Typed integer inputs make the encoding injective;
/// callers must not reduce a 256-bit digest into a single field element.
/// `circuit_code`, `circuit_version`, `statement_domain_hi`, and
/// `statement_domain_lo` MUST be circuit constants, never prover witnesses.
pub fn compute_namada_proof_context_v1(
    circuit_code: Field,
    circuit_version: Field,
    statement_domain_hi: Field,
    statement_domain_lo: Field,
    chain_id_digest_hi: u128,
    chain_id_digest_lo: u128,
    vp_address_digest_hi: u128,
    vp_address_digest_lo: u128,
    vp_code_hash_hi: u128,
    vp_code_hash_lo: u128,
    consensus_protocol_version: u64,
    consensus_epoch: u64,
) -> Field {
    let inputs: [Field; 14] = [
        DOMAIN_NAMADA_PROOF_CONTEXT_V1,
        1,
        circuit_code,
        circuit_version,
        statement_domain_hi,
        statement_domain_lo,
        chain_id_digest_hi as Field,
        chain_id_digest_lo as Field,
        vp_address_digest_hi as Field,
        vp_address_digest_lo as Field,
        vp_code_hash_hi as Field,
        vp_code_hash_lo as Field,
        consensus_protocol_version as Field,
        consensus_epoch as Field,
    ];
    hash_namada_proof_context_v1_preimage(inputs)
}

/// Hash the exact ContextV1 preimage assembled by the typed public helper.
///
/// This stays private so circuits cannot supply their own tag or schema
/// version. Keeping the final H14 operation in one function also lets the KAT
/// below exercise every committed position independently.
fn hash_namada_proof_context_v1_preimage(inputs: [Field; 14]) -> Field {
    poseidon_hash(inputs)
}

/// Compute context binding from epoch, chain_id, and application_id
pub fn compute_context(epoch: Field, chain_id: Field, application_id: Field) -> Field {
    poseidon3(epoch, chain_id, application_id)
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_namada_proof_context_v1_complete_h14_kat_and_component_binding() {
    let preimage: [Field; 14] = [
        DOMAIN_NAMADA_PROOF_CONTEXT_V1,
        1,
        1,
        1,
        0x3c385d28bdfc4964a27ef693c4dbfb23,
        0x737008146beae63657ac30c312e72b70,
        0x940b07a21b480879128b91654073511c,
        0xab42cf89ea2146076af109a23652de84,
        0x6685ff144f5a85a1211b01ca3b866fb8,
        0xa0b71c62889e9540766b1127d04855c6,
        0x93a44bbb96c751218e4c00d479e4c143,
        0x58122a389acca16205b1e4d0dc5f9476,
        1,
        7,
    ];
    let expected: Field = 0x08bab26ee954327f2a7943d624f5ecfc9815d00893af02dcca9ccc4bb9d8128a;

    // Pin the typed circuit API to the Rust/generator ContextV1 KAT.
    let typed = compute_namada_proof_context_v1(
        1,
        1,
        0x3c385d28bdfc4964a27ef693c4dbfb23,
        0x737008146beae63657ac30c312e72b70,
        0x940b07a21b480879128b91654073511c,
        0xab42cf89ea2146076af109a23652de84,
        0x6685ff144f5a85a1211b01ca3b866fb8,
        0xa0b71c62889e9540766b1127d04855c6,
        0x93a44bbb96c751218e4c00d479e4c143,
        0x58122a389acca16205b1e4d0dc5f9476,
        1,
        7,
    );
    assert(typed == expected);
    assert(hash_namada_proof_context_v1_preimage(preimage) == expected);

    // Every H14 position is load-bearing, including the private tag/schema
    // positions that callers cannot override.
    for i in 0..14 {
        let mut changed = preimage;
        changed[i] = changed[i] + 1;
        assert(hash_namada_proof_context_v1_preimage(changed) != expected);
    }
}

#[test]
fn test_l1_asset_id_field_golden() {
    // Golden from ADR 0003 / the zka-crypto reference: chainId = 1, token = USDC
    // 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48.
    // digest = keccak256(abi.encode(1, USDC))
    //        = b340dcebc6634c8db42e41014206798ccc4b36e5bf3a1ed61b89a5f70afa8cd4
    let digest_be: [u8; 32] = [
        0xb3, 0x40, 0xdc, 0xeb, 0xc6, 0x63, 0x4c, 0x8d, 0xb4, 0x2e, 0x41, 0x01, 0x42, 0x06, 0x79,
        0x8c, 0xcc, 0x4b, 0x36, 0xe5, 0xbf, 0x3a, 0x1e, 0xd6, 0x1b, 0x89, 0xa5, 0xf7, 0x0a, 0xfa,
        0x8c, 0xd4,
    ];
    // Low 248 bits == digest with the top byte (0xb3) zeroed.
    let expected: Field = 0x0040dcebc6634c8db42e41014206798ccc4b36e5bf3a1ed61b89a5f70afa8cd4;
    assert(l1_asset_id_field(digest_be) == expected);
}

#[test]
fn test_domain_separators_all_unique() {
    let domains = [
        DOMAIN_ZKA_SPENDING,
        DOMAIN_ZKA_VIEWING,
        DOMAIN_ZKA_PROOF,
        DOMAIN_ZKA_ADDRESS,
        DOMAIN_ZKA_NULLIFIER,
        DOMAIN_ZKC_CREDENTIAL,
        DOMAIN_ZKC_BINDING,
        DOMAIN_ZKC_PRESENTATION_SCOPE,
        DOMAIN_ZKA_NOTE,
        DOMAIN_ZKA_ASSET,
        DOMAIN_ZKA_COMMITMENT,
    ];
    for i in 0..11 {
        for j in (i + 1)..11 {
            assert(domains[i] != domains[j], "Domain separators must be unique");
        }
    }
}

#[test]
fn test_domain_separators_nonzero() {
    assert(DOMAIN_ZKA_SPENDING != 0, "spending domain must be nonzero");
    assert(DOMAIN_ZKA_NULLIFIER != 0, "nullifier domain must be nonzero");
    assert(DOMAIN_ZKA_ADDRESS != 0, "address domain must be nonzero");
}

#[test]
fn test_note_commitment_deterministic() {
    let c1 = compute_note_commitment(1, 100, 42, 999);
    let c2 = compute_note_commitment(1, 100, 42, 999);
    assert(c1 == c2, "Commitment must be deterministic");
}

#[test]
fn test_note_commitment_binding() {
    let base = compute_note_commitment(1, 100, 42, 999);
    assert(base != compute_note_commitment(2, 100, 42, 999), "Different asset must differ");
    assert(base != compute_note_commitment(1, 200, 42, 999), "Different value must differ");
    assert(base != compute_note_commitment(1, 100, 43, 999), "Different recipient must differ");
    assert(base != compute_note_commitment(1, 100, 42, 998), "Different randomness must differ");
}

#[test]
fn test_nullifier_deterministic() {
    let n1 = compute_nullifier(100, 42);
    let n2 = compute_nullifier(100, 42);
    assert(n1 == n2, "Nullifier must be deterministic");
}

#[test]
fn test_nullifier_different_keys() {
    assert(compute_nullifier(100, 42) != compute_nullifier(100, 99), "Different keys must differ");
}

#[test]
fn test_nullifier_different_commitments() {
    assert(
        compute_nullifier(100, 42) != compute_nullifier(200, 42),
        "Different commitments must differ",
    );
}

#[test]
fn test_nullifier_nonzero_with_zero_inputs() {
    assert(
        compute_nullifier(0, 0) != 0,
        "Nullifier with zero inputs must be nonzero (domain separation)",
    );
}

#[test]
fn test_key_derivation_deterministic() {
    let addr1 = derive_address(42);
    let addr2 = derive_address(42);
    assert(addr1 == addr2, "Address derivation must be deterministic");
}

#[test]
fn test_key_derivation_different_keys() {
    assert(
        derive_address(42) != derive_address(99),
        "Different spending keys must derive different addresses",
    );
}

#[test]
fn test_key_hierarchy_all_distinct() {
    let sk: Field = 42;
    let vk = derive_viewing_key(sk);
    let addr = derive_address_from_vk(vk);
    let pk = derive_proof_key(sk);
    let cbk = derive_legacy_v1_credential_binding_key(sk);
    let cc = derive_legacy_v1_credential_commitment(cbk);

    assert(sk != vk, "sk != vk");
    assert(vk != addr, "vk != addr");
    assert(addr != pk, "addr != pk");
    assert(pk != cbk, "pk != cbk");
    assert(cbk != cc, "cbk != cc");
}

#[test]
fn test_credential_binding_key_is_seed_sibling() {
    let seed: Field = 0x5a;
    let sk = derive_spending_key_from_master_seed(seed);
    let cbk = derive_credential_binding_key(seed);
    let wrong_descendant = derive_credential_binding_key(sk);

    assert(cbk != sk, "cbk must not expose spending authority");
    assert(cbk != wrong_descendant, "cbk must derive from seed, not spending key");
}

#[test]
fn kat_afp_kdc_v101_seed_42_credential_path() {
    let cbk = derive_credential_binding_key(42);
    assert(
        cbk == 0x2245b9bc69578eaf6d9975c8f8dab4e9d434080bb0f38fb602f11c5074220105,
        "AFP-KDC cbk KAT mismatch",
    );
    assert(
        derive_credential_commitment(cbk)
            == 0x24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf,
        "AFP-KDC holderCommitment KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v101_seed_0x42_credential_path() {
    let cbk = derive_credential_binding_key(0x42);
    assert(
        cbk == 0x240cd59ef0b0476917c3be146aaa0d1c143facf6159c7cce310af66d7d1737c9,
        "AFP-KDC 0x42 cbk KAT mismatch",
    );
    assert(
        derive_credential_commitment(cbk)
            == 0x0722370a0b95bdeb10637afefad2bcc13ac61ae203ab21647c5c1543ca991f7d,
        "AFP-KDC 0x42 holderCommitment KAT mismatch",
    );
}

#[test]
fn kat_zkc_v04_scoped_presentation_binding() {
    let master_seed: Field = 42;
    let scope_id: Field = 0x2632aaf1e51423d6eab07aa448f245c91490f34a5b3e6744e47f584fab96c4d5;
    let cbk = derive_zkc_v04_credential_binding_key(master_seed);
    let pseudonym = derive_presentation_pseudonym(cbk, scope_id);

    assert(
        pseudonym == 0x22dfa15cbccd21643c573b1123e29ab0ba4a7463347e376a7fba2f5832f03ae2,
        "ZKC v0.4 presentation pseudonym KAT mismatch",
    );
}

#[test]
fn test_anonymous_presentation_uses_zero_sentinels() {
    let cbk = derive_zkc_v04_credential_binding_key(42);
    assert_presentation_binding(0, 0, cbk);
}

#[test(should_fail_with = "anonymous profile must not carry a pseudonym")]
fn test_anonymous_presentation_rejects_holder_handle() {
    let cbk = derive_zkc_v04_credential_binding_key(42);
    assert_presentation_binding(1, 0, cbk);
}

#[test]
fn test_asset_commitment_deterministic() {
    let a1 = compute_asset_commitment(777);
    let a2 = compute_asset_commitment(777);
    assert(a1 == a2, "Asset commitment must be deterministic");
}

#[test]
fn test_asset_commitment_different_assets() {
    assert(
        compute_asset_commitment(777) != compute_asset_commitment(888),
        "Different assets must produce different commitments",
    );
}

#[test]
fn test_merkle_root_deterministic() {
    let siblings = [0; 32];
    let r1 = compute_merkle_root(42, 0, siblings);
    let r2 = compute_merkle_root(42, 0, siblings);
    assert(r1 == r2, "Merkle root must be deterministic");
}

#[test]
fn test_merkle_root_different_leaves() {
    let siblings = [0; 32];
    assert(
        compute_merkle_root(42, 0, siblings) != compute_merkle_root(43, 0, siblings),
        "Different leaves must produce different roots",
    );
}

#[test]
fn test_merkle_root_right_child_branch() {
    // Exercise the is_right == true path with a non-zero path_index and a
    // non-zero sibling so child-order selection is actually meaningful.
    let mut siblings = [0; 32];
    siblings[0] = 7;

    // Swapping the leaf must change the root (root depends on the leaf).
    assert(
        compute_merkle_root(42, 1, siblings) != compute_merkle_root(43, 1, siblings),
        "Different leaves must produce different roots on the right-child path",
    );

    // path_index = 1 (right child at the bottom level) must differ from
    // path_index = 0 (left child) for the same leaf + siblings, confirming
    // child order genuinely affects the computed root.
    assert(
        compute_merkle_root(42, 1, siblings) != compute_merkle_root(42, 0, siblings),
        "Child order must affect the root (left vs right placement)",
    );
}

// =============================================================================
// Known-Answer Tests (KAT): Poseidon2 parameterization guard
//
// These pin the exact Poseidon2 output of the external `noir-lang/poseidon`
// dependency (Nargo.toml: tag v0.3.0, which is commit
// 0880c371e88e583d39515fd3f877538657ac41eb) as resolved by the pinned
// toolchain (nargo 1.0.0-beta.25, see .noir-version).
//
// Every ZKA note commitment, nullifier, and key derivation routes through
// poseidon2/poseidon3/poseidon4, so if a dependency tag re-point or toolchain
// bump silently changed the underlying Poseidon2 instantiation (round
// constants, MDS/linear layers, round counts), every protocol hash would
// change with no source diff. These vectors make that failure loud: the test
// suite breaks instead of the protocol silently forking.
//
// WARNING: do NOT "fix" a failing KAT by pasting in the new value. A change
// here means the Poseidon2 parameterization changed. Treat it as a protocol
// break and investigate the dependency/toolchain before re-blessing.
//
// To intentionally re-bless after an audited parameterization change, capture
// fresh values with the pinned toolchain:
//   nargo test --show-output kat_  (read the printed Field values)
// Values below were captured under nargo 1.0.0-beta.21 + poseidon v0.3.0
// (verified unchanged under nargo 1.0.0-beta.25).
// =============================================================================

#[test]
fn kat_afp_kdc_v102_raw_sponge_p0_empty() {
    assert(
        poseidon_hash([]) == 0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e,
        "AFP-KDC v1.0.2 P0 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p1_one() {
    assert(
        poseidon_hash([1]) == 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373,
        "AFP-KDC v1.0.2 P1 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p2_two() {
    assert(
        poseidon_hash([1, 2]) == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
        "AFP-KDC v1.0.2 P2 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p3_three() {
    assert(
        poseidon_hash([1, 2, 3])
            == 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
        "AFP-KDC v1.0.2 P3 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p4_four() {
    assert(
        poseidon_hash([1, 2, 3, 4])
            == 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9,
        "AFP-KDC v1.0.2 P4 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p6_six() {
    assert(
        poseidon_hash([1, 2, 3, 4, 5, 6])
            == 0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a,
        "AFP-KDC v1.0.2 P6 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p7_seven() {
    assert(
        poseidon_hash([1, 2, 3, 4, 5, 6, 7])
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

// KAT: verify the POSEIDON2_EMPTY_ROOT_DEPTH_32 constant is correct.
// Computes H_0=0, H_{i+1}=poseidon2(H_i,H_i) for i in 0..32 and asserts
// the result equals the pinned constant. Fails loudly if the constant drifts.
#[test]
fn kat_poseidon2_empty_root_depth_32() {
    let mut h: Field = 0;
    for _i in 0..32 {
        h = poseidon2(h, h);
    }
    assert(
        h == POSEIDON2_EMPTY_ROOT_DEPTH_32,
        "POSEIDON2_EMPTY_ROOT_DEPTH_32 constant mismatch: Poseidon2 parameterization or constant changed",
    );
}

// L1 address bound: 2^160 is the smallest value that does NOT fit in the
// 20 bytes of an Ethereum address.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn assert_fits_u160_rejects_at_boundary() {
    assert_fits_u160(TWO_POW_160);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn assert_fits_u160_rejects_above_boundary() {
    assert_fits_u160(TWO_POW_160 + 12345);
}

#[test]
fn assert_fits_u160_accepts_real_addresses() {
    assert_fits_u160(0);
    assert_fits_u160(1);
    assert_fits_u160(0xdeadbeef);
    assert_fits_u160(TWO_POW_160 - 1); // 0xffff...ff, the largest L1 address
}

// u64 balance-domain bound: U64_MAX is the largest value in the ZKA balance
// value domain, so U64_MAX + 1 is the smallest value that does NOT fit.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn assert_fits_u64_rejects_above_boundary() {
    assert_fits_u64(U64_MAX + 1);
}

// A field element just below the BN254 modulus is the wraparound witness the
// balance circuit must reject: it is "negative" as an integer difference.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn assert_fits_u64_rejects_field_wraparound() {
    assert_fits_u64(
        21888242871839275222246405745257275088548364400416034343698204186575808495616,
    );
}

#[test]
fn assert_fits_u64_accepts_domain() {
    assert_fits_u64(0);
    assert_fits_u64(1);
    assert_fits_u64(10_000);
    assert_fits_u64(U64_MAX);
}
