//! L2->L1 withdrawal message encoding (docs/adr/0002).
//!
//! This module lives outside the `#[aztec] contract` block because that block
//! only admits `#[external]`/`#[internal]`/`#[test]` functions; a plain helper
//! and its `aztec::protocol` import resolve cleanly here.

use aztec::protocol::hash::sha256_to_field;
use std::field::bn254::decompose;

/// The canonical big-endian 32-byte encoding of a field element.
///
/// SOUNDNESS: this MUST NOT be re-expressed as `x.to_be_bytes::<32>()`. For a
/// 32-byte decomposition nargo (1.0.0-beta.25) emits only 32 eight-bit range
/// checks plus ONE recomposition equation, and that equation is a `Field`
/// equation -- it holds *modulo p*. Because `2^256 > 5p`, EVERY field element
/// admits five distinct 32-byte witnesses (`x`, `x + p`, ... `x + 4p`), and the
/// lowest ~29% of the field admits six. A raw `to_be_bytes::<32>()` therefore
/// does not determine the bytes, so the content hash would not be a function of
/// `(recipient, amount)` alone.
///
/// `decompose` splits `x` into `(lo, hi)`, range-checks each to 128 bits, and
/// then compares the pair against the BN254 modulus limbs (a borrow-propagating
/// subtraction against PLO/PHI) so that `lo + 2^128*hi < p` -- the canonical
/// representative. Re-encoding each limb as 16 bytes is unambiguous on its own:
/// 16 bytes recompose to a value in `[0, 2^128)`, strictly below p, so that
/// equation cannot wrap.
///
/// This matches the Rust reference `zka_bridge_aztec::withdraw_content_hash`
/// (src/zka-bridge-aztec/types.rs), which is canonical by construction because
/// it takes a typed `[u8; 20]` recipient and a `u128` amount.
pub fn canonical_be_bytes_32(x: Field) -> [u8; 32] {
    let (lo, hi) = decompose(x);
    let hi_bytes: [u8; 16] = hi.to_be_bytes();
    let lo_bytes: [u8; 16] = lo.to_be_bytes();

    let mut out: [u8; 32] = [0; 32];
    for i in 0..16 {
        out[i] = hi_bytes[i];
        out[i + 16] = lo_bytes[i];
    }
    out
}

/// Assert the withdrawal recipient fits in a 20-byte L1 address (v < 2^160).
///
/// Delegates to `zka_lib` (the same cross-environment sharing used for note
/// hashes and nullifiers) so the Aztec portal path and the Ethereum pool/bridge
/// paths enforce one identical bound. It is surfaced here because the bound is a
/// PRECONDITION OF `withdraw_content_hash` below, not an incidental input check.
///
/// WHY THIS IS A FUND-LOSS GUARD, not a cosmetic check: `withdraw_content_hash`
/// right-aligns the recipient in a 32-byte slot. The L1 `ZKAAztecPortal`
/// reconstructs that slot with
/// `abi.encodeWithSignature("withdraw(address,uint256)", ...)`, and
/// `abi.encode(address)` ALWAYS zero-pads the top 12 bytes. So a recipient with
/// any non-zero byte above the low 20 produces a content hash that NO address
/// argument can reproduce -- `outbox.consume` can never match it, and the notes
/// burned on L2 to fund the message are permanently unrecoverable. The message
/// is built L2-side, so there is no L1 type chokepoint to catch this: the bound
/// must be stated here, and it must be stated BEFORE any note is burned.
pub fn assert_fits_u160(v: Field) {
    zka_lib::assert_fits_u160(v)
}

/// Build the L2->L1 withdrawal message content for the Aztec Outbox:
///   sha256_to_field( selector ++ recipient_be(32) ++ amount_be(32) )
///
/// `selector = keccak256("withdraw(address,uint256)")[0..4] = 0xf3fef3a3` (the
/// standard ERC-style ABI selector). The L1 `ZKAAztecPortal` MUST reconstruct
/// the content with the SAME function signature so its `Hash.sha256ToField(...)`
/// matches the content the Aztec Outbox stored for this message. `recipient` is
/// the L1 address right-aligned in the Field; `amount` is the uint256 value.
///
/// SHA-256 (not keccak) is used for the content, matching the aztec-packages
/// v5 L2->L1 message hashing (`sha256_to_field` on L2 == `Hash.sha256ToField`
/// on L1).
pub fn withdraw_content_hash(recipient: Field, amount: Field) -> Field {
    let selector: [u8; 4] = [0xf3, 0xfe, 0xf3, 0xa3];
    // Canonical (< p) encodings -- see `canonical_be_bytes_32`. A raw
    // `to_be_bytes::<32>()` here would let a prover pick among several byte
    // strings for the same field element, so the content would not be a
    // function of its inputs.
    let recipient_bytes: [u8; 32] = canonical_be_bytes_32(recipient);
    let amount_bytes: [u8; 32] = canonical_be_bytes_32(amount);

    let mut hash_bytes: [u8; 68] = [0; 68];
    for i in 0..4 {
        hash_bytes[i] = selector[i];
    }
    for i in 0..32 {
        hash_bytes[i + 4] = recipient_bytes[i];
        hash_bytes[i + 36] = amount_bytes[i];
    }
    sha256_to_field(hash_bytes)
}

use zka_lib::TWO_POW_160;

// A recipient at the 20-byte boundary must be rejected: its 32-byte message slot
// would carry non-zero top bytes, which `abi.encode(address)` can never produce.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn assert_fits_u160_rejects_at_boundary() {
    assert_fits_u160(TWO_POW_160);
}

// A recipient above the boundary must also be rejected.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn assert_fits_u160_rejects_above_boundary() {
    assert_fits_u160(TWO_POW_160 + 12345);
}

// Every real L1 address (incl. 0 and the all-ones address) must pass.
#[test]
fn assert_fits_u160_accepts_real_addresses() {
    assert_fits_u160(0);
    assert_fits_u160(1);
    assert_fits_u160(0xdeadbeef);
    assert_fits_u160(TWO_POW_160 - 1); // 0xffff...ff, the largest L1 address
}

#[test]
fn content_hash_is_deterministic() {
    let a = withdraw_content_hash(0xbeef, 1000);
    let b = withdraw_content_hash(0xbeef, 1000);
    assert(a == b, "content hash must be a pure function of (recipient, amount)");
}

#[test]
fn content_hash_binds_recipient_and_amount() {
    let base = withdraw_content_hash(0xbeef, 1000);
    assert(withdraw_content_hash(0xc0de, 1000) != base, "content must depend on recipient");
    assert(withdraw_content_hash(0xbeef, 2000) != base, "content must depend on amount");
}

#[test]
fn content_hash_layout_matches_manual_sha256() {
    // Recompute the exact 68-byte preimage by hand and compare, locking the
    // selector + field layout the L1 portal must reconstruct.
    let recipient: Field = 0xabcd;
    let amount: Field = 42;
    let recipient_bytes: [u8; 32] = canonical_be_bytes_32(recipient);
    let amount_bytes: [u8; 32] = canonical_be_bytes_32(amount);
    let mut preimage: [u8; 68] = [0; 68];
    preimage[0] = 0xf3;
    preimage[1] = 0xfe;
    preimage[2] = 0xf3;
    preimage[3] = 0xa3;
    for i in 0..32 {
        preimage[i + 4] = recipient_bytes[i];
        preimage[i + 36] = amount_bytes[i];
    }
    assert(withdraw_content_hash(recipient, amount) == sha256_to_field(preimage));
}

// Pins the canonical-representative semantics of the encoding, including at the
// top of the field where a non-canonical witness would differ.
//
// NOTE: this test cannot, on its own, catch a regression to `to_be_bytes::<32>()`.
// `nargo test` runs the honest witness solver, which always emits the canonical
// decomposition, so the sound and unsound versions agree on every honest input.
// The regression gate is the source check in
// aztec/scripts/check-field-encoding-canonicity.sh.
#[test]
fn canonical_be_bytes_32_matches_expected_layout() {
    // Small values are right-aligned with a zero-padded prefix -- the layout the
    // L1 portal reconstructs via `abi.encode`.
    let small = canonical_be_bytes_32(0xbeef);
    for i in 0..30 {
        assert(small[i] == 0, "small value must be zero-padded on the left");
    }
    assert(small[30] == 0xbe, "byte 30 mismatch");
    assert(small[31] == 0xef, "byte 31 mismatch");

    // Zero encodes as 32 zero bytes -- never as the byte string of p, which is
    // the non-canonical witness a raw 32-byte decomposition would also admit.
    let zero = canonical_be_bytes_32(0);
    for i in 0..32 {
        assert(zero[i] == 0, "zero must encode as 32 zero bytes");
    }

    // p - 1, the largest BN254 scalar-field element: the canonical encoding is
    // the modulus limbs with the low limb decremented, and it is the ONLY
    // representative below 2^256 that is also < p.
    let max: Field = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
    let max_bytes = canonical_be_bytes_32(max);
    let expected: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x00,
    ];
    for i in 0..32 {
        assert(max_bytes[i] == expected[i], "p-1 canonical encoding mismatch");
    }
}

// Cross-environment golden. This exact value is asserted on L1 by
// `test_ContentHashMatchesL2Golden` in test/ZKAAztecPortal.t.sol and by the Rust
// reference `zka_bridge_aztec::withdraw_content_hash`. Pinning it here proves the
// canonicity fix did NOT change the encoding for honest inputs -- the three
// implementations stay byte-for-byte identical.
#[test]
fn content_hash_matches_l1_golden() {
    let golden: Field = 0x002c54ccb6af0251a12093d39b5dd48465cf1061ebf84a15c54cb7839261ef99;
    assert(
        withdraw_content_hash(0xbeef, 1000) == golden,
        "L2 content must equal the L1 ZKAAztecPortal.withdrawContentHash golden",
    );
}
