pub global NULLIFIER_TREE_DEPTH: u32 = 128;

pub fn verify_nullifier_absent_and_insert(
    old_root: Field,
    nullifier: Field,
    siblings: [Field; 128],
) -> Field {
    assert(nullifier != 0, "nullifier must be non-zero");
    let index: Field = low_128_bits(nullifier);
    assert(
        compute_sparse_root(0, index, siblings) == old_root,
        "nullifier is present or path is invalid",
    );
    compute_sparse_root(nullifier, index, siblings)
}

/// Canonical low 128 bits of `nullifier`, used as its sparse-tree slot index.
///
/// MUST use `std::field::bn254::decompose`. It MUST NOT be re-expressed as a
/// `to_be_bits::<254>()` projection: for a 254-bit decomposition nargo emits only
/// (a) 254 booleanity checks and (b) one recomposition equation, and that equation
/// holds *modulo p*. For any `x < 2^254 - p` (~32.25% of the field) both `x` and
/// `x + p` are therefore valid 254-bit witnesses for the same field element, with
/// different low 128 bits — so a malicious prover could derive two distinct slots
/// for one nullifier and insert it twice. `decompose` binds the limbs to `x < p`
/// by comparing them against the modulus limbs, making the index a function of the
/// field element alone. This matches the Rust reference `low_128_index`
/// (src/zka-crypto/src/tree/sparse_nullifier.rs), which reads the low 16 bytes of
/// the canonical big-endian encoding.
fn low_128_bits(nullifier: Field) -> Field {
    let (low, _high) = std::field::bn254::decompose(nullifier);
    low
}

/// `index` MUST already be a canonical `< 2^128` slot (i.e. produced by
/// `low_128_bits`). Unlike the 254-bit case above, `to_be_bits::<128>()` is
/// unambiguous on its own: nargo emits 128 booleanity checks plus one
/// recomposition equation, and because every satisfying assignment sums to a
/// value in `[0, 2^128)` — strictly below p — that equation cannot wrap, so it
/// admits exactly one decomposition per field element and additionally rejects
/// any `index >= 2^128`.
fn compute_sparse_root(leaf: Field, index: Field, siblings: [Field; 128]) -> Field {
    let index_bits: [bool; 128] = index.to_be_bits();
    let mut current = leaf;
    for i in 0..128 {
        let is_right = index_bits[127 - i];
        let left = if is_right { siblings[i] } else { current };
        let right = if is_right { current } else { siblings[i] };
        current = crate::poseidon2(left, right);
    }
    current
}

#[test]
fn low_128_bits_discards_high_bits() {
    let value: Field = 0x0000000000000000000000000000000100000000000000000000000000000007;
    assert(low_128_bits(value) == 7, "low-128-bit extraction mismatch");
}

// Pins the canonical-representative semantics at the top of the field. Note that
// this test cannot, on its own, catch a regression to the `to_be_bits::<254>()`
// projection: `nargo test` runs the honest witness solver, which always emits the
// canonical decomposition, so the buggy and fixed versions agree on every honest
// input. The regression gate is the ACIR check in
// noir/scripts/check-nullifier-index-canonicity.sh, which asserts the compiled
// constraint system actually binds the slot index to `nullifier < p`.
#[test]
fn low_128_bits_is_canonical_at_modulus_boundary() {
    // p - 1, the largest BN254 scalar-field element.
    let value: Field = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
    assert(
        low_128_bits(value) == 0x2833e84879b9709143e1f593f0000000,
        "canonical low-128 limb mismatch at p-1",
    );
    // 0 maps to slot 0 -- never to the low limb of p, which is what the discarded
    // non-canonical 254-bit witness for 0 would have produced.
    assert(low_128_bits(0) == 0, "zero must map to slot 0");
}

#[test(should_fail_with = "nullifier must be non-zero")]
fn zero_nullifier_sentinel_is_rejected() {
    let siblings = empty_siblings();
    let old_root: Field = 0x2413c3e2b026ffff5628832762082690520fc5a22f825e3af1a86cc435901981;
    let _new_root = verify_nullifier_absent_and_insert(old_root, 0, siblings);
}

#[test]
fn empty_root_matches_cross_language_kat() {
    let siblings = empty_siblings();
    assert(
        compute_sparse_root(0, 0, siblings)
            == 0x2413c3e2b026ffff5628832762082690520fc5a22f825e3af1a86cc435901981,
        "depth-128 empty root KAT mismatch",
    );
}

#[test]
fn first_insertion_matches_cross_language_kat() {
    let siblings = empty_siblings();
    let old_root: Field = 0x2413c3e2b026ffff5628832762082690520fc5a22f825e3af1a86cc435901981;
    assert(
        verify_nullifier_absent_and_insert(old_root, 7, siblings)
            == 0x1b0bd3abf090fd482eff2296f0221f57ccbde03fb885d0fba107f4f11f66caf4,
        "first nullifier insertion KAT mismatch",
    );
}

#[test]
fn second_insertion_matches_cross_language_kat() {
    let mut siblings = empty_siblings();
    let mut subtree: Field = 7;
    for depth in 0..3 {
        subtree = crate::poseidon2(siblings[depth], subtree);
    }
    siblings[3] = subtree;

    let first_root: Field = 0x1b0bd3abf090fd482eff2296f0221f57ccbde03fb885d0fba107f4f11f66caf4;
    assert(
        verify_nullifier_absent_and_insert(first_root, 9, siblings)
            == 0x13dfafaefdfdecda00bbda7cba0d0e7edf23da7bf1e79e24cc2f322aece77b22,
        "second nullifier insertion KAT mismatch",
    );
}

fn empty_siblings() -> [Field; 128] {
    let mut siblings = [0; 128];
    let mut empty: Field = 0;
    for depth in 0..128 {
        siblings[depth] = empty;
        empty = crate::poseidon2(empty, empty);
    }
    siblings
}
