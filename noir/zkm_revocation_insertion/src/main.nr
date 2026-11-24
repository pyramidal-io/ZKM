// ZKM §7.1 accumulator-update companion, zkm:revocation-insertion:v1.
// This proves tree continuity, NOT issuance authority. A target must also
// verify zkm:revocation-auth:v1, matched on root_id and settlement_context.
// Both folds use the SAME private siblings and canonical full-id path: the
// only change is the leaf at root_id, from zero to that complete identifier.
// The target compares previous_root to its current tip and epoch to its own
// clock, then records the insertion and next_root atomically. No ZKA value,
// mandate-note, nullifier, or custody effect is authorized by this statement.

use zkm_lib::{compute_mandate_root_id, compute_revocation_root, poseidon2};

fn main(
    root_id: pub Field,
    previous_root: pub Field,
    next_root: pub Field,
    revocation_scheme: pub u8,
    epoch: pub u64,
    settlement_context: pub Field,
    siblings: [Field; 254],
) {
    assert(root_id != 0, "root_id must be non-zero");
    assert(previous_root != 0, "previous root must be non-zero");
    assert(next_root != 0, "next root must be non-zero");
    assert(revocation_scheme == 2, "only revocation scheme 2 is accepted");
    assert(settlement_context != 0, "settlement context must be non-zero");
    // epoch is authenticated by the target, not by a prover-selected clock.
    let _epoch = epoch;
    assert(
        compute_revocation_root(0, root_id, siblings) == previous_root,
        "previous root does not contain the empty root_id leaf",
    );
    assert(
        compute_revocation_root(root_id, root_id, siblings) == next_root,
        "next root is not the authorized insertion",
    );
}

global CONTEXT: Field = 0x5e77_1e3c;
global EPOCH: u64 = 42;

fn empty_siblings() -> [Field; 254] {
    let mut siblings = [0; 254];
    for i in 1..254 {
        siblings[i] = poseidon2(siblings[i - 1], siblings[i - 1]);
    }
    siblings
}

fn run(root_id: Field, siblings: [Field; 254]) {
    main(
        root_id,
        compute_revocation_root(0, root_id, siblings),
        compute_revocation_root(root_id, root_id, siblings),
        2,
        EPOCH,
        CONTEXT,
        siblings,
    );
}

#[test]
fn test_empty_tree_insert() {
    run(compute_mandate_root_id(991, 13), empty_siblings());
}

#[test]
fn test_field_boundary_insert() {
    run(-1, empty_siblings());
}

#[test]
fn test_low_half_twins_are_independent() {
    let mut siblings = empty_siblings();
    let previous_root = compute_revocation_root(1, 1, siblings);
    // Identifier 1 and 1 + 2^128 diverge at level 128. The sibling on
    // the latter's path is the already-revoked former's depth-128 subtree.
    let mut occupied = poseidon2(0, 1);
    for i in 1..128 {
        occupied = poseidon2(occupied, siblings[i]);
    }
    siblings[128] = occupied;
    assert(
        compute_revocation_root(0, 0x100000000000000000000000000000001, siblings) == previous_root,
        "the second insertion must preserve the first revoked identifier",
    );
    run(0x100000000000000000000000000000001, siblings);
}

#[test(should_fail_with = "previous root does not contain the empty root_id leaf")]
fn test_nonempty_leaf_rejected() {
    let root_id = compute_mandate_root_id(991, 13);
    let siblings = empty_siblings();
    let root = compute_revocation_root(root_id, root_id, siblings);
    main(root_id, root, root, 2, EPOCH, CONTEXT, siblings);
}

#[test(should_fail_with = "previous root does not contain the empty root_id leaf")]
fn test_wrong_old_root_rejected() {
    let siblings = empty_siblings();
    main(
        1,
        7,
        compute_revocation_root(1, 1, siblings),
        2,
        EPOCH,
        CONTEXT,
        siblings,
    );
}

#[test(should_fail_with = "next root is not the authorized insertion")]
fn test_dropped_insertion_rejected() {
    let siblings = empty_siblings();
    let old_root = compute_revocation_root(0, 1, siblings);
    main(1, old_root, old_root, 2, EPOCH, CONTEXT, siblings);
}

#[test(should_fail_with = "next root is not the authorized insertion")]
fn test_unwitnessable_published_root_rejected() {
    let siblings = empty_siblings();
    main(
        1,
        compute_revocation_root(0, 1, siblings),
        7,
        2,
        EPOCH,
        CONTEXT,
        siblings,
    );
}

#[test(should_fail_with = "next root is not the authorized insertion")]
fn test_wrong_full_identifier_leaf_rejected() {
    let siblings = empty_siblings();
    main(
        1,
        compute_revocation_root(0, 1, siblings),
        compute_revocation_root(2, 1, siblings),
        2,
        EPOCH,
        CONTEXT,
        siblings,
    );
}

#[test(should_fail_with = "only revocation scheme 2 is accepted")]
fn test_legacy_scheme_rejected() {
    let siblings = empty_siblings();
    main(1, 1, 1, 1, EPOCH, CONTEXT, siblings);
}

#[test(should_fail_with = "root_id must be non-zero")]
fn test_zero_id_rejected() {
    main(0, 1, 1, 2, EPOCH, CONTEXT, empty_siblings());
}

#[test(should_fail_with = "settlement context must be non-zero")]
fn test_zero_context_rejected() {
    main(1, 1, 1, 2, EPOCH, 0, empty_siblings());
}

#[test]
fn emit_toml_revocation_insertion() {
    let root_id = compute_mandate_root_id(991, 13);
    let siblings = empty_siblings();
    let previous_root = compute_revocation_root(0, root_id, siblings);
    let next_root = compute_revocation_root(root_id, root_id, siblings);
    let revocation_scheme: u8 = 2;
    let epoch = EPOCH;
    let settlement_context = CONTEXT;
    println(f"root_id={root_id}");
    println(f"previous_root={previous_root}");
    println(f"next_root={next_root}");
    println(f"revocation_scheme={revocation_scheme}");
    println(f"epoch={epoch}");
    println(f"settlement_context={settlement_context}");
    for i in 0..254 {
        let sibling = siblings[i];
        println(f"siblings[]={sibling}");
    }
}
