// ZKM revocation-authorization circuit — the §7.1 authorization statement.
//
// §7.1: revocation is `root_id` insertion into the exclusion accumulator,
// "exercisable only by the principal's issuance authority" — and issuance
// authority IS knowledge of the `root_id` preimage (§3: the issuance proof
// guarantees that preimage material existed for every accepted leaf). This
// circuit is that authorization made checkable: the settlement layer MUST
// accept a revocation insertion only against a verifying proof under this VK
// whose public `root_id` is the id being inserted.
//
// WHAT THIS PREVENTS. Without it, revocation insertion is either
// permissioned out-of-band (an operator decides who may revoke — a
// Safeguard-3 shape ZKM forbids) or open (anyone can insert any field
// element, griefing arbitrary lineages: `root_id`s are not secret forever —
// §7.1 publishes one at each honest revocation, and a malicious settlement
// participant could otherwise front-insert garbage or replay-kill a lineage
// it observed). With it, the ONLY party that can kill a lineage is the party
// that could have issued it.
//
// REPLAY IS IDEMPOTENT. A replayed (root_id, proof) pair re-inserts an
// already-revoked id — a no-op. Cross-domain replay is bound out by
// `settlement_context` in the public vector: a revocation authorized for one
// settlement target does not verify on another (the §5 hygiene every ZKM
// proof carries). Note what the context binding does NOT do: the same
// `root_id` can only exist on one domain anyway (`settlement_domain` is
// inside the mandate commitment, and §3 fresh randomness gives every
// issuance its own root_id), so the binding is hygiene, not a soundness
// requirement.
//
// PRIVACY. `root_id` is public here BY DESIGN — revocation is the one
// deliberate disclosure (§4.6 claim 3): the accumulator's contents are
// public, and every prover must be able to build non-membership witnesses
// against them. The preimage stays private; publishing the revocation links
// nothing (§4.6).

use zkm_lib::compute_mandate_root_id;

fn main(
    // ---- public inputs -------------------------------------------------
    // The lineage being revoked: inserted into the exclusion accumulator at
    // the §7.1 slot derived from this value iff this proof verifies.
    root_id: pub Field,
    // Settlement-domain binding (§5 hygiene; see header).
    settlement_context: pub Field,
    // ---- private witnesses ---------------------------------------------
    principal_issuance_key: Field,
    issuance_randomness: Field,
) {
    assert(root_id != 0, "root_id must be non-zero");
    assert(settlement_context != 0, "settlement context must be non-zero");
    assert(principal_issuance_key != 0, "principal issuance key must be non-zero");

    // THE AUTHORIZATION: the inserter knows the issuance material behind the
    // lineage it is killing.
    assert(
        compute_mandate_root_id(principal_issuance_key, issuance_randomness) == root_id,
        "prover does not hold the issuance authority for this root_id",
    );
}

// =============================================================================
// Tests — fixture constants mirror the sibling packages: the root_id revoked
// here is the root_id their fixtures issue and transition.
// =============================================================================

global PRINCIPAL_ISSUANCE_KEY: Field = 991;
global ISSUANCE_RANDOMNESS: Field = 13;
global SETTLEMENT_CONTEXT: Field = 0x5e77_1e3c;

struct RevocationAuth {
    root_id: Field,
    settlement_context: Field,
    principal_issuance_key: Field,
    issuance_randomness: Field,
}

impl RevocationAuth {
    fn run(self) {
        main(
            self.root_id,
            self.settlement_context,
            self.principal_issuance_key,
            self.issuance_randomness,
        );
    }
}

fn auth_of() -> RevocationAuth {
    RevocationAuth {
        root_id: compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS),
        settlement_context: SETTLEMENT_CONTEXT,
        principal_issuance_key: PRINCIPAL_ISSUANCE_KEY,
        issuance_randomness: ISSUANCE_RANDOMNESS,
    }
}

#[test]
fn test_revocation_authorized() {
    auth_of().run();
}

#[test(should_fail_with = "prover does not hold the issuance authority for this root_id")]
fn test_wrong_key_rejected() {
    let mut a = auth_of();
    a.principal_issuance_key = PRINCIPAL_ISSUANCE_KEY + 1;
    a.run();
}

#[test(should_fail_with = "prover does not hold the issuance authority for this root_id")]
fn test_wrong_randomness_rejected() {
    let mut a = auth_of();
    a.issuance_randomness = ISSUANCE_RANDOMNESS + 1;
    a.run();
}

#[test(should_fail_with = "prover does not hold the issuance authority for this root_id")]
fn test_foreign_root_id_rejected() {
    // The griefing case: a party that observed some root_id (e.g. from an
    // honest revocation on another lineage) cannot authorize killing it.
    let mut a = auth_of();
    a.root_id = compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY + 1, ISSUANCE_RANDOMNESS);
    a.run();
}

#[test(should_fail_with = "root_id must be non-zero")]
fn test_zero_root_id_rejected() {
    let mut a = auth_of();
    a.root_id = 0;
    a.run();
}

#[test(should_fail_with = "settlement context must be non-zero")]
fn test_zero_settlement_context_rejected() {
    let mut a = auth_of();
    a.settlement_context = 0;
    a.run();
}

#[test(should_fail_with = "principal issuance key must be non-zero")]
fn test_zero_issuance_key_rejected() {
    let mut a = auth_of();
    a.principal_issuance_key = 0;
    a.run();
}

// =============================================================================
// Prover.toml emission for the bb proving harness.
// =============================================================================

fn emit_prover_toml(a: RevocationAuth) {
    let root_id = a.root_id;
    let settlement_context = a.settlement_context;
    println(f"root_id={root_id}");
    println(f"settlement_context={settlement_context}");

    let principal_issuance_key = a.principal_issuance_key;
    let issuance_randomness = a.issuance_randomness;
    println(f"principal_issuance_key={principal_issuance_key}");
    println(f"issuance_randomness={issuance_randomness}");
}

#[test]
fn emit_toml_revocation_auth() {
    emit_prover_toml(auth_of());
}
