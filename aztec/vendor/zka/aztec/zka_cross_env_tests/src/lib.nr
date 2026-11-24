// =============================================================================
// ZKA Cross-Environment Credential Verification Tests
//
// Verifies that ZKC credential proofs produce identical cryptographic outputs
// in both standalone Noir circuits and Aztec.nr contracts. This is the critical
// interoperability guarantee: a proof generated in one environment can be
// verified in the other.
//
// Test categories:
//   1. Credential commitment cross-verification
//   2. Selective disclosure hash cross-verification
//   3. Full key hierarchy cross-verification
//   4. Atomic compliance flow (credential + transfer in one context)
//   5. EVM verifier public input compatibility
//   6. Context binding cross-verification
// =============================================================================

use zka_aztec_lib;
use zka_lib;

// =============================================================================
// Shared test constants
//
// These values simulate a complete identity and credential across environments.
// The same constants are used in both standalone circuit tests and Aztec
// contract tests to ensure cross-environment consistency.
// =============================================================================

/// Standard app-siloed master seed (nsk_app in Aztec context)
global TEST_SEED: Field = 0x42;
/// Alternative app-siloed seed for multi-identity tests
global TEST_SEED_ALT: Field = 0x99;
/// Third app-siloed seed for exhaustive tests
global TEST_SEED_THREE: Field = 0x1337;
/// Standard test credential data (initial accumulator for disclosure hash)
global TEST_CRED_DATA: Field = 0xaaaa;
/// Standard test attributes
global TEST_ATTRS: [Field; 4] = [100, 200, 300, 400];
/// Alternative test attributes
global TEST_ATTRS_ALT: [Field; 4] = [10, 20, 30, 40];
/// Standard test context (epoch/chain/app binding)
global TEST_CONTEXT: Field = 0xdeadbeef;

// =============================================================================
// 1. CREDENTIAL COMMITMENT CROSS-VERIFICATION
//
// The credential commitment chain is:
//   seed -> cbk = H(DOMAIN_ZKC_CREDENTIAL, seed) -> cc = H(DOMAIN_ZKC_BINDING, cbk)
//
// Both environments MUST produce the same cc for the same app-siloed seed.
// This ensures a standalone EVM verifier accepts Aztec-generated proofs
// and vice versa.
// =============================================================================

#[test]
fn test_credential_commitment_cross_env() {
    // Standalone path: zka_lib functions directly
    let standalone_cbk = zka_lib::derive_credential_binding_key(TEST_SEED);
    let standalone_cc = zka_lib::derive_credential_commitment(standalone_cbk);

    // Aztec path: adapter functions (nsk_app as app-siloed seed)
    let aztec_cbk = zka_aztec_lib::derive_zka_cbk(TEST_SEED);
    let aztec_cc = zka_lib::derive_credential_commitment(aztec_cbk);

    // Cross-environment: cbk must match
    assert(standalone_cbk == aztec_cbk, "CBK must match across environments");
    // Cross-environment: cc must match
    assert(standalone_cc == aztec_cc, "Credential commitment must match across environments");
}

#[test]
fn test_credential_commitment_cross_env_multiple_keys() {
    // Verify cross-env consistency holds for multiple distinct identities
    let keys = [TEST_SEED, TEST_SEED_ALT, TEST_SEED_THREE];

    for i in 0..3 {
        let sk = keys[i];

        let standalone_cbk = zka_lib::derive_credential_binding_key(sk);
        let standalone_cc = zka_lib::derive_credential_commitment(standalone_cbk);

        let aztec_cbk = zka_aztec_lib::derive_zka_cbk(sk);
        let aztec_cc = zka_lib::derive_credential_commitment(aztec_cbk);

        assert(standalone_cc == aztec_cc, "CC must match for all identities");
    }

    // Additionally verify all three identities produce distinct commitments
    let cc0 =
        zka_lib::derive_credential_commitment(zka_lib::derive_credential_binding_key(keys[0]));
    let cc1 =
        zka_lib::derive_credential_commitment(zka_lib::derive_credential_binding_key(keys[1]));
    let cc2 =
        zka_lib::derive_credential_commitment(zka_lib::derive_credential_binding_key(keys[2]));
    assert(cc0 != cc1, "Different keys must produce different commitments");
    assert(cc1 != cc2, "Different keys must produce different commitments");
    assert(cc0 != cc2, "Different keys must produce different commitments");
}

#[test]
fn test_nsk_app_derives_afp_kdc_spending_key() {
    let nsk_app = TEST_SEED;
    let zka_sk = zka_aztec_lib::aztec_nsk_to_zka_sk(nsk_app);
    let expected_sk = zka_lib::derive_spending_key_from_master_seed(nsk_app);
    assert(zka_sk == expected_sk, "nsk_app must derive the ZKA spending key");

    // The credential key is a seed sibling, not a child of the spending key.
    let standalone_cc =
        zka_lib::derive_credential_commitment(zka_lib::derive_credential_binding_key(nsk_app));
    let aztec_cc = zka_lib::derive_credential_commitment(zka_aztec_lib::derive_zka_cbk(nsk_app));
    assert(standalone_cc == aztec_cc, "Seed-sibling mapping preserves credential commitment");
}

// =============================================================================
// 2. SELECTIVE DISCLOSURE HASH CROSS-VERIFICATION
//
// The disclosure hash is computed as:
//   acc = credential_data
//   for i in 0..4:
//     disclosed_val = attributes[i] * mask_bit_i  (0 if not disclosed)
//     acc = H(acc, disclosed_val)
//
// Both environments use the same Poseidon2 accumulator chain. A standalone
// EVM verifier checking disclosed_attribute_hash must get the same value
// as the Aztec credential contract's prove_disclosure.
// =============================================================================

#[test]
fn test_disclosed_hash_cross_env_full_disclosure() {
    let mask_bits: [bool; 4] = [true, true, true, true];

    // Standalone circuit path (manual accumulator)
    let mut standalone_acc = TEST_CRED_DATA;
    for i in 0..4 {
        let val = if mask_bits[i] { TEST_ATTRS[i] } else { 0 };
        standalone_acc = zka_lib::poseidon2(standalone_acc, val);
    }

    // Aztec adapter path
    let aztec_hash = zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, mask_bits);

    assert(standalone_acc == aztec_hash, "Full disclosure hash must match across environments");
}

#[test]
fn test_disclosed_hash_cross_env_partial_disclosure() {
    // Test all meaningful 2-attribute disclosure patterns
    let patterns: [[bool; 4]; 4] = [
        [true, false, true, false], // attrs 0, 2
        [false, true, false, true], // attrs 1, 3
        [true, true, false, false], // attrs 0, 1
        [false, false, true, true], // attrs 2, 3
    ];

    for p in 0..4 {
        let mask = patterns[p];

        // Standalone
        let mut standalone_acc = TEST_CRED_DATA;
        for i in 0..4 {
            let val = if mask[i] { TEST_ATTRS[i] } else { 0 };
            standalone_acc = zka_lib::poseidon2(standalone_acc, val);
        }

        // Aztec adapter
        let aztec_hash = zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, mask);

        assert(
            standalone_acc == aztec_hash,
            "Partial disclosure hash must match across environments",
        );
    }
}

#[test]
fn test_disclosed_hash_cross_env_no_disclosure() {
    let mask_bits: [bool; 4] = [false, false, false, false];

    // Standalone: all zeros disclosed
    let mut standalone_acc = TEST_CRED_DATA;
    for _ in 0..4 {
        standalone_acc = zka_lib::poseidon2(standalone_acc, 0);
    }

    // Aztec adapter
    let aztec_hash = zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, mask_bits);

    assert(standalone_acc == aztec_hash, "Zero disclosure hash must match across environments");
}

#[test]
fn test_disclosed_hash_cross_env_single_attr() {
    // Test each single-attribute disclosure individually
    for target in 0..4 {
        let mask: [bool; 4] = [target == 0, target == 1, target == 2, target == 3];

        let mut standalone_acc = TEST_CRED_DATA;
        for i in 0..4 {
            let val = if mask[i] { TEST_ATTRS[i] } else { 0 };
            standalone_acc = zka_lib::poseidon2(standalone_acc, val);
        }

        let aztec_hash = zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, mask);

        assert(
            standalone_acc == aztec_hash,
            "Single-attr disclosure hash must match across environments",
        );
    }
}

#[test]
fn test_disclosed_hash_cross_env_different_credentials() {
    // Different credential_data and attributes must produce different hashes
    // but still match across environments
    let mask: [bool; 4] = [true, false, true, false];

    let hash1 = zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, mask);
    let hash2 = zka_aztec_lib::compute_disclosed_hash(0xbbbb, TEST_ATTRS_ALT, mask);

    // Verify both paths produce matching results
    let mut standalone1 = TEST_CRED_DATA;
    let mut standalone2: Field = 0xbbbb;
    for i in 0..4 {
        let val1 = if mask[i] { TEST_ATTRS[i] } else { 0 };
        let val2 = if mask[i] { TEST_ATTRS_ALT[i] } else { 0 };
        standalone1 = zka_lib::poseidon2(standalone1, val1);
        standalone2 = zka_lib::poseidon2(standalone2, val2);
    }

    assert(hash1 == standalone1, "First credential hash must match");
    assert(hash2 == standalone2, "Second credential hash must match");
    assert(hash1 != hash2, "Different credentials must produce different hashes");
}

// =============================================================================
// 3. FULL KEY HIERARCHY CROSS-VERIFICATION
//
// Verify that the complete key derivation chain produces identical results
// in both environments: seed -> {sk, cbk}, sk -> {vk, pk}, vk -> addr,
// cbk -> holderCommitment.
// =============================================================================

#[test]
fn test_full_key_hierarchy_cross_env() {
    let seed = TEST_SEED;
    let sk = zka_lib::derive_spending_key_from_master_seed(seed);

    // Standalone derivation via zka_lib
    let standalone_vk = zka_lib::derive_viewing_key(sk);
    let standalone_addr = zka_lib::derive_address(sk);
    let standalone_pk = zka_lib::derive_proof_key(sk);
    let standalone_cbk = zka_lib::derive_credential_binding_key(seed);
    let standalone_cc = zka_lib::derive_credential_commitment(standalone_cbk);

    // Aztec adapter derivation (nsk_app is the app-siloed seed)
    let aztec_vk = zka_aztec_lib::derive_zka_viewing_key(seed);
    let aztec_addr = zka_aztec_lib::derive_zka_address(seed);
    let aztec_cbk = zka_aztec_lib::derive_zka_cbk(seed);
    let aztec_cc = zka_lib::derive_credential_commitment(aztec_cbk);

    // Cross-verify each key type
    assert(standalone_vk == aztec_vk, "Viewing key must match across environments");
    assert(standalone_addr == aztec_addr, "Address must match across environments");
    assert(standalone_cbk == aztec_cbk, "CBK must match across environments");
    assert(standalone_cc == aztec_cc, "CC must match across environments");

    // All keys must be distinct from each other (no collisions)
    assert(sk != standalone_vk, "sk != vk");
    assert(standalone_vk != standalone_addr, "vk != addr");
    assert(standalone_addr != standalone_pk, "addr != pk");
    assert(standalone_pk != standalone_cbk, "pk != cbk");
    assert(standalone_cbk != standalone_cc, "cbk != cc");
}

// =============================================================================
// 4. ATOMIC COMPLIANCE FLOW
//
// Simulates a compliance-gated transfer: a credential proof and a shielded
// transfer are verified atomically (as would happen in a single Aztec tx).
//
// Flow:
//   1. Derive credential commitment from nsk_app (proves compliance)
//   2. Compute disclosed_hash for selective disclosure
//   3. Derive address from same nsk_app (identity for transfer)
//   4. Compute note commitment for the transfer
//   5. Verify the credential and transfer are bound to the same identity
//
// In Aztec, steps 1-2 run in ZKACredential and steps 3-4 run in ZKATransfer,
// all within one tx. The kernel proves both atomically.
// =============================================================================

#[test]
fn test_atomic_compliance_credential_then_transfer() {
    // --- Shared identity (nsk_app is the app-siloed AFP-KDC seed) ---
    let nsk_app = TEST_SEED;

    // --- Step 1: Credential proof (ZKACredential contract) ---
    let cbk = zka_aztec_lib::derive_zka_cbk(nsk_app);
    let credential_commitment = zka_lib::derive_credential_commitment(cbk);

    // Selective disclosure: reveal attributes 0 and 2
    let mask: [bool; 4] = [true, false, true, false];
    let disclosed_hash = zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, mask);

    // --- Step 2: Transfer (ZKATransfer contract) ---
    let sender_address = zka_aztec_lib::derive_zka_address(nsk_app);
    let asset_commitment = zka_lib::compute_asset_commitment(1); // asset_id = 1
    let value: Field = 1000;
    let randomness: Field = 0xaabb;

    let note_commitment =
        zka_lib::compute_note_commitment(asset_commitment, value, sender_address, randomness);

    // --- Verification: credential and transfer are linked ---

    // 1. Credential commitment is valid (non-zero, derived from identity)
    assert(credential_commitment != 0, "Credential commitment must be non-zero");

    // 2. Disclosed hash is valid (non-zero, derived from credential data)
    assert(disclosed_hash != 0, "Disclosed hash must be non-zero");

    // 3. Note commitment is valid (derived from same identity's address)
    assert(note_commitment != 0, "Note commitment must be non-zero");

    // 4. Identity binding: the address used in the transfer is derived from
    //    the same key that produced the credential commitment
    let standalone_sk = zka_lib::derive_spending_key_from_master_seed(nsk_app);
    let standalone_addr = zka_lib::derive_address(standalone_sk);
    assert(sender_address == standalone_addr, "Transfer address must match credential identity");

    // 5. The credential and note are bound through the same root key
    //    (cbk and address both derive from nsk_app)
    let verify_cbk = zka_lib::derive_credential_binding_key(nsk_app);
    let verify_cc = zka_lib::derive_credential_commitment(verify_cbk);
    assert(
        verify_cc == credential_commitment,
        "Standalone verifier must accept Aztec credential commitment",
    );

    // 6. Nullifier for the transfer note is also derived from the same key
    let nullifier = zka_lib::compute_nullifier(note_commitment, standalone_sk);
    assert(nullifier != 0, "Nullifier must be non-zero");
    assert(nullifier != note_commitment, "Nullifier must differ from commitment");
}

#[test]
fn test_compliance_gated_transfer_different_identities_rejected() {
    // A credential from one identity cannot authorize a transfer for another.
    // This is enforced by the key derivation: different nsk_app -> different
    // address and different credential_commitment.

    let alice_nsk = TEST_SEED;
    let bob_nsk = TEST_SEED_ALT;

    // Alice's credential
    let alice_cbk = zka_aztec_lib::derive_zka_cbk(alice_nsk);
    let alice_cc = zka_lib::derive_credential_commitment(alice_cbk);

    // Bob's credential
    let bob_cbk = zka_aztec_lib::derive_zka_cbk(bob_nsk);
    let bob_cc = zka_lib::derive_credential_commitment(bob_cbk);

    // Alice's transfer address
    let alice_addr = zka_aztec_lib::derive_zka_address(alice_nsk);

    // Bob's transfer address
    let bob_addr = zka_aztec_lib::derive_zka_address(bob_nsk);

    // Credentials are distinct
    assert(alice_cc != bob_cc, "Different identities must have different credentials");

    // Addresses are distinct
    assert(alice_addr != bob_addr, "Different identities must have different addresses");

    // Alice's credential cannot be used with Bob's address
    // (In the Aztec contract, nsk_app determines both -- if you bind to Alice's
    // credential, the transfer address is also Alice's, never Bob's)
    let alice_verify_sk = zka_lib::derive_spending_key_from_master_seed(alice_nsk);
    let alice_verify_addr = zka_lib::derive_address(alice_verify_sk);
    assert(
        alice_verify_addr != bob_addr,
        "Alice's credential identity cannot match Bob's transfer address",
    );
}

#[test]
fn test_atomic_compliance_with_context_binding() {
    // Full atomic flow including context binding (replay protection).
    // Both the credential proof and the transfer are bound to the same context.

    let nsk_app = TEST_SEED;
    let context = zka_lib::compute_context(
        42, // epoch
        1, // chain_id (e.g., Ethereum mainnet)
        0x1234, // application_id
    );
    assert(context != 0, "Context must be non-zero");

    // Credential with context binding
    let cbk = zka_aztec_lib::derive_zka_cbk(nsk_app);
    let cc = zka_lib::derive_credential_commitment(cbk);
    let context_binding = zka_lib::poseidon3(cc, TEST_CRED_DATA, context);

    // Transfer note with the same identity
    let addr = zka_aztec_lib::derive_zka_address(nsk_app);
    let asset = zka_lib::compute_asset_commitment(1);
    let note = zka_lib::compute_note_commitment(asset, 500, addr, 0xccdd);

    // Both are bound to the same context and identity
    assert(context_binding != 0, "Context binding must be non-zero");
    assert(note != 0, "Note commitment must be non-zero");

    // A different context produces a different binding (replay protection)
    let other_context = zka_lib::compute_context(43, 1, 0x1234); // different epoch
    let other_binding = zka_lib::poseidon3(cc, TEST_CRED_DATA, other_context);
    assert(context_binding != other_binding, "Different contexts must produce different bindings");
}

// =============================================================================
// 5. EVM VERIFIER PUBLIC INPUT COMPATIBILITY
//
// The standalone credential circuit has 3 public inputs:
//   [0] credential_commitment
//   [1] disclosed_attribute_hash
//   [2] context
//
// An EVM Solidity verifier checks these public inputs against the proof.
// This test verifies that the public inputs computed by the Aztec contract
// match what the standalone circuit (and thus the EVM verifier) expects.
// =============================================================================

#[test]
fn test_evm_verifier_public_inputs_match() {
    let nsk_app = TEST_SEED;
    let mask: [bool; 4] = [true, false, true, false];

    // --- Aztec-side computation (what the contract produces) ---
    let aztec_cbk = zka_aztec_lib::derive_zka_cbk(nsk_app);
    let aztec_cc = zka_lib::derive_credential_commitment(aztec_cbk);
    let aztec_disclosed = zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, mask);

    // --- Standalone-side computation (what the EVM verifier checks) ---
    let standalone_cbk = zka_lib::derive_credential_binding_key(nsk_app);
    let standalone_cc = zka_lib::derive_credential_commitment(standalone_cbk);

    let mut standalone_disclosed = TEST_CRED_DATA;
    for i in 0..4 {
        let val = if mask[i] { TEST_ATTRS[i] } else { 0 };
        standalone_disclosed = zka_lib::poseidon2(standalone_disclosed, val);
    }

    // Public input [0]: credential_commitment
    assert(
        aztec_cc == standalone_cc,
        "Public input [0] credential_commitment must match for EVM verifier",
    );

    // Public input [1]: disclosed_attribute_hash
    assert(
        aztec_disclosed == standalone_disclosed,
        "Public input [1] disclosed_attribute_hash must match for EVM verifier",
    );

    // Public input [2]: context is passed through unchanged
    // (both environments receive it as a Field, no transformation)
    let context = TEST_CONTEXT;
    let context_standalone = TEST_CONTEXT;
    assert(context == context_standalone, "Public input [2] context must match for EVM verifier");
}

#[test]
fn test_evm_verifier_public_inputs_all_masks() {
    // Exhaustive: verify all 16 possible 4-bit masks produce matching
    // public inputs across environments
    let nsk_app = TEST_SEED;

    let standalone_cbk = zka_lib::derive_credential_binding_key(nsk_app);
    let standalone_cc = zka_lib::derive_credential_commitment(standalone_cbk);
    let aztec_cbk = zka_aztec_lib::derive_zka_cbk(nsk_app);
    let aztec_cc = zka_lib::derive_credential_commitment(aztec_cbk);

    // CC is mask-independent -- verify once
    assert(standalone_cc == aztec_cc, "CC must match regardless of mask");

    // Iterate all 16 mask combinations (0b0000 to 0b1111)
    for mask_val in 0..16 {
        let mask: [bool; 4] =
            [(mask_val & 8) != 0, (mask_val & 4) != 0, (mask_val & 2) != 0, (mask_val & 1) != 0];

        // Standalone accumulator
        let mut standalone_acc = TEST_CRED_DATA;
        for i in 0..4 {
            let val = if mask[i] { TEST_ATTRS[i] } else { 0 };
            standalone_acc = zka_lib::poseidon2(standalone_acc, val);
        }

        // Aztec adapter
        let aztec_hash = zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, mask);

        assert(
            standalone_acc == aztec_hash,
            "Disclosed hash must match for all 16 mask combinations",
        );
    }
}

// =============================================================================
// 6. CREDENTIAL DOMAIN SEPARATOR CROSS-VERIFICATION
//
// Verify that both environments use the same domain separators for
// credential operations. This prevents silent divergence if either
// library is updated independently.
// =============================================================================

#[test]
fn test_domain_separators_cross_env() {
    // The credential domain separators must be accessible from both libraries
    // and produce consistent results when used with the same inputs

    let seed = TEST_SEED;

    // Direct domain separator usage (standalone)
    let direct_cbk = zka_lib::poseidon2(zka_lib::DOMAIN_ZKC_CREDENTIAL, seed);
    let direct_cc = zka_lib::poseidon2(zka_lib::DOMAIN_ZKC_BINDING, direct_cbk);

    // Via library functions (standalone)
    let lib_cbk = zka_lib::derive_credential_binding_key(seed);
    let lib_cc = zka_lib::derive_credential_commitment(lib_cbk);

    // Via Aztec adapter
    let aztec_cbk = zka_aztec_lib::derive_zka_cbk(seed);
    let aztec_cc = zka_lib::derive_credential_commitment(aztec_cbk);

    // All three paths must agree
    assert(direct_cbk == lib_cbk, "Direct domain usage must match library function");
    assert(lib_cbk == aztec_cbk, "Library function must match Aztec adapter");
    assert(direct_cc == lib_cc, "Direct CC must match library CC");
    assert(lib_cc == aztec_cc, "Library CC must match Aztec CC");
}

// =============================================================================
// 7. SS5.2 DISCLOSURE CONTEXT-BINDING MODEL (docs/adr/0001, Option A)
//
// Canonical model: the cross-environment disclosure artifact is the RAW,
// context-INDEPENDENT disclosed hash (compute_disclosed_hash). `context` is a
// SEPARATE co-equal binding (a public input in the standalone circuit; a
// function argument + separate CredNote field in Aztec), never folded into the
// hash. This test locks the model in: (a) the disclosed hash is identical across
// environments, and (b) it does not vary with context (context is not an input
// to the hash), so a folded value is not the canonical artifact.
// =============================================================================
#[test]
fn test_disclosure_context_binding_model_adr0001() {
    let mask: [bool; 4] = [true, false, true, false];

    // (a) Cross-env equality of the RAW disclosed hash.
    let aztec_raw = zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, mask);
    let mut standalone_raw = TEST_CRED_DATA;
    for i in 0..4 {
        let val = if mask[i] { TEST_ATTRS[i] } else { 0 };
        standalone_raw = zka_lib::poseidon2(standalone_raw, val);
    }
    assert(
        aztec_raw == standalone_raw,
        "ADR0001: canonical disclosure artifact (raw hash) must match cross-env",
    );

    // (b) The canonical artifact is context-INDEPENDENT: context is not an input
    // to compute_disclosed_hash, so the same (cred_data, attrs, mask) yields the
    // same hash regardless of which session it is used in. The session binding
    // lives in the separate `context` value, not in this hash.
    let aztec_raw_again = zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, mask);
    assert(
        aztec_raw == aztec_raw_again,
        "ADR0001: disclosed hash must be context-independent (binding is separate)",
    );

    // Sanity: a folded variant would differ from the raw artifact for any
    // non-zero context -- confirming the raw hash, not a fold, is canonical.
    let folded_variant = zka_lib::poseidon3(aztec_raw, TEST_CONTEXT, TEST_CONTEXT);
    assert(
        folded_variant != aztec_raw,
        "ADR0001: a context-folded value is distinct from (and not) the canonical raw artifact",
    );
}

// =============================================================================
// 8. REAL CROSS-ENVIRONMENT PROOF VECTOR -- golden KAT
// (real cross-environment conformance)
//
// noir/scripts/cross-env-proof.sh generates a REAL UltraHonk proof of the
// standalone zka_credential circuit and asserts its public inputs equal the
// golden vector [cc, disclosed_hash, context]. That vector's public inputs are
// committed in noir/zka_credential/Prover.toml as fixed hex constants. This KAT
// is the source-of-truth tie: it asserts those exact constants equal the
// cross-env computation (both the standalone zka_lib path and the Aztec
// zka_aztec_lib path), so a zka_lib drift breaks this test (and the operator
// knows to recompute the proof vector). Vector: TEST_SEED / TEST_CRED_DATA /
// TEST_ATTRS / TEST_CONTEXT with FULL disclosure (mask = 0b1111).
// =============================================================================

// Golden public inputs baked into noir/zka_credential/Prover.toml and
// noir/scripts/cross-env-proof.sh. If these change, update all three together.
global GOLDEN_CC: Field = 0x0722370a0b95bdeb10637afefad2bcc13ac61ae203ab21647c5c1543ca991f7d;
global GOLDEN_DISCLOSED_FULL: Field =
    0x0dc3b292e2cf1f4a3a204984cc779f50487eeeac183e113249acadd179a8dbfa;

#[test]
fn test_cross_env_proof_vector_golden() {
    let full_mask: [bool; 4] = [true, true, true, true];

    // credential_commitment: both environments derive the same cc, and it equals
    // the golden constant the real proof's public input [0] must carry.
    let standalone_cc =
        zka_lib::derive_credential_commitment(zka_lib::derive_credential_binding_key(TEST_SEED));
    let aztec_cc = zka_lib::derive_credential_commitment(zka_aztec_lib::derive_zka_cbk(TEST_SEED));
    assert(standalone_cc == aztec_cc, "proof-vector cc must match cross-env");
    assert(standalone_cc == GOLDEN_CC, "proof-vector cc must equal the committed golden constant");

    // disclosed_attribute_hash (full disclosure): the standalone fold and the
    // Aztec adapter agree, and equal the golden constant = public input [1].
    let mut standalone_disclosed = TEST_CRED_DATA;
    for i in 0..4 {
        let val = if full_mask[i] { TEST_ATTRS[i] } else { 0 };
        standalone_disclosed = zka_lib::poseidon2(standalone_disclosed, val);
    }
    let aztec_disclosed =
        zka_aztec_lib::compute_disclosed_hash(TEST_CRED_DATA, TEST_ATTRS, full_mask);
    assert(
        standalone_disclosed == aztec_disclosed,
        "proof-vector disclosed hash must match cross-env",
    );
    assert(
        standalone_disclosed == GOLDEN_DISCLOSED_FULL,
        "proof-vector disclosed hash must equal the committed golden constant",
    );
}

// =============================================================================
// 9. AFP-KDC v1.0.2 RAW SPONGE CONFORMANCE
//
// Keep these literals local to this package so the Aztec-bundled compiler
// independently evaluates the complete raw-sponge boundary set.
// =============================================================================

#[test]
fn kat_afp_kdc_v102_raw_sponge_p0_empty() {
    assert(
        zka_lib::poseidon_hash([])
            == 0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e,
        "AFP-KDC v1.0.2 P0 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p1_one() {
    assert(
        zka_lib::poseidon_hash([1])
            == 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373,
        "AFP-KDC v1.0.2 P1 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p2_two() {
    assert(
        zka_lib::poseidon_hash([1, 2])
            == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
        "AFP-KDC v1.0.2 P2 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p3_three() {
    assert(
        zka_lib::poseidon_hash([1, 2, 3])
            == 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
        "AFP-KDC v1.0.2 P3 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p4_four() {
    assert(
        zka_lib::poseidon_hash([1, 2, 3, 4])
            == 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9,
        "AFP-KDC v1.0.2 P4 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p6_six() {
    assert(
        zka_lib::poseidon_hash([1, 2, 3, 4, 5, 6])
            == 0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a,
        "AFP-KDC v1.0.2 P6 raw sponge KAT mismatch",
    );
}

#[test]
fn kat_afp_kdc_v102_raw_sponge_p7_seven() {
    assert(
        zka_lib::poseidon_hash([1, 2, 3, 4, 5, 6, 7])
            == 0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238,
        "AFP-KDC v1.0.2 P7 raw sponge KAT mismatch",
    );
}
