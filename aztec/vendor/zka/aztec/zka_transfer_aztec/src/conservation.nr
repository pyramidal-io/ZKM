// =============================================================================
// Value-conservation core for ZKATransfer (pure, contract-free).
//
// This module isolates the value-conservation arithmetic so it can be unit-tested
// under plain `nargo test` (no TXE oracle needed). Change is the sum of all popped
// note values minus the spend amount; every popped note's value is conserved.
//
// `conserved_change` is the single source of truth used by the contract's
// private `_spend`, and is exercised directly by the unit tests below.
// =============================================================================

/// Sum `values[0..count]` (the values of all popped notes), assert the total
/// covers `amount`, and return the change to return to the sender.
///
/// # Arguments
/// - `values` - packed note values; only the first `count` entries are summed.
/// - `count`  - number of valid entries in `values` (i.e. `notes.len()`).
/// - `amount` - the amount being spent.
///
/// # Returns
/// - `total - amount`, the change owed back to the sender (0 means no change).
///
/// Reverts with "insufficient balance" if the summed value is below `amount`.
pub fn conserved_change<let N: u32>(values: [u128; N], count: u32, amount: u128) -> u128 {
    let total = sum_values(values, count);
    assert(total >= amount, "insufficient balance");
    total - amount
}

/// Sum the first `count` entries of `values`. Iterates to the compile-time
/// bound `N` (cheaper constraints) and guards each add with `i < count`.
pub fn sum_values<let N: u32>(values: [u128; N], count: u32) -> u128 {
    let mut total: u128 = 0;
    for i in 0..N {
        if i < count {
            total += values[i];
        }
    }
    total
}

/// Assert that the raw `Field` value `v` fits in a u128, i.e. v < 2^128.
///
/// IMPORTANT: a bare `v as u128` cast does NOT range-check -- under nargo
/// beta.21 it SILENTLY TRUNCATES (e.g. `(2^128 as Field) as u128 == 0`), which
/// would reintroduce the same value-loss bug class this contract fixes. Every
/// value-introduction path (deposit claim amount, spend `amount`, and each
/// popped note value before summing) must pass through this guard so the
/// subsequent `as u128` cast is provably lossless.
///
/// The check uses the round-trip idiom: casting down to u128 and back up to
/// Field is the identity exactly when `v` was already < 2^128. (Verified under
/// beta.21: this fails for 2^128 and passes for u128::MAX = 2^128 - 1.)
pub fn assert_fits_u128(v: Field) {
    assert(v == (v as u128) as Field, "value exceeds u128 range");
}

// =============================================================================
// Unit tests (pure -- run under plain `nargo test`, no TXE oracle required)
// =============================================================================

// Owner holds three notes of one asset: [100, 50, 30] (total 180). Spending 40
// must leave change = 140. This test pins the conserved result.
#[test]
fn conserves_value_across_multiple_notes() {
    let values: [u128; 16] = [100, 50, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let change = conserved_change(values, 3, 40);
    assert(change == 140, "change must conserve all popped value: 180 - 40 = 140 (not 60)");

    // Contrast the total with the first note's value to ensure every popped note
    // contributes to change.
    let buggy_change = values[0] - 40; // == 60
    assert(buggy_change == 60, "sanity: old single-note logic would have yielded 60");
    assert(change != buggy_change, "fix must differ from the buggy single-note result");
}

#[test]
fn exact_amount_leaves_no_change() {
    let values: [u128; 4] = [40, 0, 0, 0];
    assert(conserved_change(values, 1, 40) == 0, "exact spend leaves zero change");
}

#[test]
fn single_note_change() {
    let values: [u128; 4] = [100, 0, 0, 0];
    assert(conserved_change(values, 1, 40) == 60, "single note: 100 - 40 = 60");
}

#[test]
fn sums_all_entries_up_to_count() {
    let values: [u128; 8] = [7, 11, 13, 17, 999, 0, 0, 0];
    // Only the first 4 are valid; 999 must be ignored.
    assert(sum_values(values, 4) == 48, "sum of first 4 = 48");
    assert(sum_values(values, 5) == 1047, "sum of first 5 = 1047");
}

#[test(should_fail_with = "insufficient balance")]
fn insufficient_balance_reverts() {
    let values: [u128; 4] = [100, 50, 0, 0];
    // 150 < 200 -> revert.
    let _ = conserved_change(values, 2, 200);
}

// 2^128 as a Field literal -- the smallest value that does NOT fit in a u128.
global TWO_POW_128: Field = 0x100000000000000000000000000000000;

// A value at the u128 boundary (2^128) must be rejected by the guard. Without
// this guard, `2^128 as u128` would silently truncate to 0 -- the exact
// value-loss class this contract exists to prevent.
#[test(should_fail_with = "value exceeds u128 range")]
fn assert_fits_u128_rejects_at_boundary() {
    assert_fits_u128(TWO_POW_128);
}

// A value above the boundary must also be rejected.
#[test(should_fail_with = "value exceeds u128 range")]
fn assert_fits_u128_rejects_above_boundary() {
    assert_fits_u128(TWO_POW_128 + 12345);
}

// In-range values (incl. 0 and u128::MAX = 2^128 - 1) must pass.
#[test]
fn assert_fits_u128_accepts_in_range() {
    assert_fits_u128(0);
    assert_fits_u128(1);
    assert_fits_u128(180);
    assert_fits_u128(TWO_POW_128 - 1); // u128::MAX
}
