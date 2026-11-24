// ZKM issuance circuit — the §3 issuance proof statement.
//
// WHAT ISSUANCE IS IN ZKM. The issuer is the principal itself — self-issued
// authority with no external attestor (§1.1, inverting ZKC, where issuers are
// public accepted-set authorities). So there is NO issuer signature to verify
// here: ZKC-Core's issuance-signature primitive exists because a ZKC issuer
// and holder are different parties, and ZKM's principal and issuer are the
// same party. What binds a mandate to its principal is `root_id` —
// `H_{zkm/mandate_root_id/v1}(principal_issuance_key, issuance_randomness)` —
// and the binding fact is PREIMAGE KNOWLEDGE, proven here, not a signature.
//
// WHY INSERTION NEEDS A PROOF AT ALL. A mandate note is pure authority — it
// moves no value at insertion, so a garbage commitment harms no third party
// directly. Three things still make an unproven insertion unacceptable:
//
//   1. REVOCABILITY. §7 revocation is `root_id` insertion by "the principal's
//      issuance authority" — which is exactly knowledge of the `root_id`
//      preimage. A leaf whose `root_id` has no known preimage is a mandate NO
//      ONE can ever revoke. This proof makes every tree leaf
//      revocation-capable by construction: the inserter knew the preimage at
//      insertion, so a revocation authority exists.
//   2. WELL-FORMEDNESS. Every §3 zero-sentinel and shape rule (non-zero
//      `root_id` / `asset_id` / `policy_hash` / `holder_key`, `depth == 0` at
//      issuance, domain binding) is asserted once, here, so no later
//      transition ever consumes a malformed origin.
//   3. STATEMENT INTEGRITY. §1.1's claim is "authorization FROM A PRINCIPAL".
//      This proof is what makes "a principal exists" literal: some party
//      holds `(principal_issuance_key, issuance_randomness)`. It
//      deliberately does NOT prove the principal is anyone in particular, or
//      is distinct from the agent — self-issued authority means an agent MAY
//      be its own principal; where a counterparty needs "a principal that is
//      not the agent" or "a principal holding credential X", that is a ZKC
//      conjunction (§10.3), not an issuance property.
//
// PUBLIC VECTOR. `cm` (the inserted commitment) and `settlement_context`
// only. `root_id` is NOT public — publishing it at issuance would hand every
// observer the revocation-watch handle for the whole subtree (§4.6); it
// surfaces publicly only if and when the principal revokes (§7.1, an
// accepted, deliberate disclosure). The settlement layer inserts `cm` into
// the mandate state tree iff this proof verifies against it.
//
// WHAT KEEPS ISSUANCE HONEST ECONOMICALLY: nothing here bounds `remaining_cap`
// — a principal may self-issue any cap it likes, exactly as it may deposit
// any amount it likes. Authority is only exercisable over value the holder
// actually custodies at spend time (§5 three-legs-one-holder), so an inflated
// cap authorizes spending of nothing.

use zkm_lib::{compute_mandate_commitment, compute_mandate_root_id, derive_holder_key, MandateNote};

fn main(
    // ---- public inputs -------------------------------------------------
    // The mandate commitment being inserted as a new depth-0 leaf.
    cm: pub Field,
    // Settlement-domain binding (§5), asserted equal to the note's committed
    // `settlement_domain`: a mandate is issued FOR a settlement target, and
    // an issuance proof for one target is unwitnessable on another.
    settlement_context: pub Field,
    // ---- private witnesses ---------------------------------------------
    // The principal's issuance material. `root_id` is NOT witnessed directly:
    // it is derived, which is the §3 binding statement.
    principal_issuance_key: Field,
    issuance_randomness: Field,
    // The issued note's opening (§3). `holder_key` IS witnessed here — unlike
    // the transition circuits, issuance is proven by the PRINCIPAL, who need
    // not (and generally does not) know the agent's secret key; it binds the
    // agent by its public holder key.
    settlement_domain: Field,
    asset_id: Field,
    remaining_cap: u128,
    expiry: u64,
    policy_hash: Field,
    holder_key: Field,
    randomness: Field,
) {
    // §3 zero sentinels: absent fields cannot be issued.
    assert(cm != 0, "mandate commitment must be non-zero");
    assert(principal_issuance_key != 0, "principal issuance key must be non-zero");
    assert(asset_id != 0, "asset_id must be non-zero");
    assert(policy_hash != 0, "policy_hash must be non-zero");
    assert(holder_key != 0, "holder key must be non-zero");

    // §3/§5 authority-domain binding. The context itself must be non-zero:
    // settlement_domain = settlement_context = 0 would satisfy the equality
    // and insert a mandate no transition can ever consume
    // (`verify_input_mandate` requires a non-zero context) — a permanently
    // dead leaf minted as if live.
    assert(settlement_context != 0, "settlement context must be non-zero");
    assert(
        settlement_domain == settlement_context,
        "mandate settlement domain must match the settlement context",
    );

    // THE BINDING STATEMENT: root_id is the image of issuance material the
    // prover knows. Preimage knowledge IS the principal's revocation
    // authority (§7.1), so proving it at insertion is what guarantees every
    // leaf has a living revocation authority.
    let root_id = compute_mandate_root_id(principal_issuance_key, issuance_randomness);
    assert(root_id != 0, "root_id must be non-zero");

    // The inserted leaf opens to exactly this origin note — depth 0 is a
    // constant, not a witness: issuance can never mint mid-chain depth.
    let expected = compute_mandate_commitment(
        MandateNote {
            root_id,
            settlement_domain,
            asset_id,
            remaining_cap,
            expiry,
            policy_hash,
            holder_key,
            depth: 0,
            randomness,
        },
    );
    assert(cm == expected, "commitment does not open to a well-formed issuance");
}

// =============================================================================
// Tests — fixture constants mirror the sibling packages so this circuit's
// issued note is bit-identical to the origin note their transition fixtures
// consume: the issuance proved here is the issuance those transitions extend.
// =============================================================================

global HOLDER_SK: Field = 4242;
global PRINCIPAL_ISSUANCE_KEY: Field = 991;
global ISSUANCE_RANDOMNESS: Field = 13;
global ASSET_ID: Field = 7;
global POLICY_HASH: Field = 33;
global IN_RANDOMNESS: Field = 555;
global CAP: u128 = 1000;
global EXPIRY: u64 = 2000;
global SETTLEMENT_CONTEXT: Field = 0x5e77_1e3c;

struct Issuance {
    cm: Field,
    settlement_context: Field,
    principal_issuance_key: Field,
    issuance_randomness: Field,
    settlement_domain: Field,
    asset_id: Field,
    remaining_cap: u128,
    expiry: u64,
    policy_hash: Field,
    holder_key: Field,
    randomness: Field,
}

impl Issuance {
    fn run(self) {
        main(
            self.cm,
            self.settlement_context,
            self.principal_issuance_key,
            self.issuance_randomness,
            self.settlement_domain,
            self.asset_id,
            self.remaining_cap,
            self.expiry,
            self.policy_hash,
            self.holder_key,
            self.randomness,
        );
    }
}

fn issuance_of() -> Issuance {
    let root_id = compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS);
    let holder_key = derive_holder_key(HOLDER_SK);
    let cm = compute_mandate_commitment(
        MandateNote {
            root_id,
            settlement_domain: SETTLEMENT_CONTEXT,
            asset_id: ASSET_ID,
            remaining_cap: CAP,
            expiry: EXPIRY,
            policy_hash: POLICY_HASH,
            holder_key,
            depth: 0,
            randomness: IN_RANDOMNESS,
        },
    );
    Issuance {
        cm,
        settlement_context: SETTLEMENT_CONTEXT,
        principal_issuance_key: PRINCIPAL_ISSUANCE_KEY,
        issuance_randomness: ISSUANCE_RANDOMNESS,
        settlement_domain: SETTLEMENT_CONTEXT,
        asset_id: ASSET_ID,
        remaining_cap: CAP,
        expiry: EXPIRY,
        policy_hash: POLICY_HASH,
        holder_key,
        randomness: IN_RANDOMNESS,
    }
}

// ---- positive ---------------------------------------------------------------

#[test]
fn test_issuance() {
    issuance_of().run();
}

#[test]
fn test_issuance_of_zero_cap_is_legal() {
    // A zero-cap mandate is degenerate but well-formed (0 is a cap value, not
    // an absent-field sentinel); it can only ever RETIRE.
    let mut i = issuance_of();
    i.remaining_cap = 0;
    let root_id = compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS);
    i.cm = compute_mandate_commitment(
        MandateNote {
            root_id,
            settlement_domain: SETTLEMENT_CONTEXT,
            asset_id: ASSET_ID,
            remaining_cap: 0,
            expiry: EXPIRY,
            policy_hash: POLICY_HASH,
            holder_key: i.holder_key,
            depth: 0,
            randomness: IN_RANDOMNESS,
        },
    );
    i.run();
}

// ---- negative ---------------------------------------------------------------

#[test(should_fail_with = "commitment does not open to a well-formed issuance")]
fn test_wrong_issuance_key_rejected() {
    // The §3 binding: a party without the root_id preimage cannot issue under
    // that root_id — and therefore every accepted leaf has a revocation
    // authority.
    let mut i = issuance_of();
    i.principal_issuance_key = PRINCIPAL_ISSUANCE_KEY + 1;
    i.run();
}

#[test(should_fail_with = "commitment does not open to a well-formed issuance")]
fn test_nonzero_depth_unmintable() {
    // depth is a circuit constant, not a witness: the commitment of a depth-1
    // note can never satisfy this VK, so issuance cannot mint mid-chain depth
    // (which would forge a delegation hop that never happened).
    let root_id = compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS);
    let mut i = issuance_of();
    i.cm = compute_mandate_commitment(
        MandateNote {
            root_id,
            settlement_domain: SETTLEMENT_CONTEXT,
            asset_id: ASSET_ID,
            remaining_cap: CAP,
            expiry: EXPIRY,
            policy_hash: POLICY_HASH,
            holder_key: i.holder_key,
            depth: 1,
            randomness: IN_RANDOMNESS,
        },
    );
    i.run();
}

#[test(should_fail_with = "commitment does not open to a well-formed issuance")]
fn test_tampered_commitment_rejected() {
    let mut i = issuance_of();
    i.cm += 1;
    i.run();
}

#[test(should_fail_with = "settlement context must be non-zero")]
fn test_zero_settlement_context_rejected() {
    let mut i = issuance_of();
    i.settlement_context = 0;
    i.settlement_domain = 0;
    i.run();
}

#[test(should_fail_with = "mandate settlement domain must match the settlement context")]
fn test_domain_mismatch_rejected() {
    let mut i = issuance_of();
    i.settlement_domain = SETTLEMENT_CONTEXT + 1;
    i.run();
}

#[test(should_fail_with = "mandate commitment must be non-zero")]
fn test_zero_commitment_rejected() {
    let mut i = issuance_of();
    i.cm = 0;
    i.run();
}

#[test(should_fail_with = "principal issuance key must be non-zero")]
fn test_zero_issuance_key_rejected() {
    let mut i = issuance_of();
    i.principal_issuance_key = 0;
    i.run();
}

#[test(should_fail_with = "asset_id must be non-zero")]
fn test_zero_asset_id_rejected() {
    let mut i = issuance_of();
    i.asset_id = 0;
    i.run();
}

#[test(should_fail_with = "policy_hash must be non-zero")]
fn test_zero_policy_hash_rejected() {
    let mut i = issuance_of();
    i.policy_hash = 0;
    i.run();
}

#[test(should_fail_with = "holder key must be non-zero")]
fn test_zero_holder_key_rejected() {
    let mut i = issuance_of();
    i.holder_key = 0;
    i.run();
}

// =============================================================================
// Prover.toml emission for the bb proving harness — same one-source-of-truth
// pattern as the sibling packages.
// =============================================================================

fn emit_prover_toml(i: Issuance) {
    let cm = i.cm;
    let settlement_context = i.settlement_context;
    println(f"cm={cm}");
    println(f"settlement_context={settlement_context}");

    let principal_issuance_key = i.principal_issuance_key;
    let issuance_randomness = i.issuance_randomness;
    let settlement_domain = i.settlement_domain;
    let asset_id = i.asset_id;
    let remaining_cap = i.remaining_cap;
    let expiry = i.expiry;
    let policy_hash = i.policy_hash;
    let holder_key = i.holder_key;
    let randomness = i.randomness;
    println(f"principal_issuance_key={principal_issuance_key}");
    println(f"issuance_randomness={issuance_randomness}");
    println(f"settlement_domain={settlement_domain}");
    println(f"asset_id={asset_id}");
    println(f"remaining_cap={remaining_cap}");
    println(f"expiry={expiry}");
    println(f"policy_hash={policy_hash}");
    println(f"holder_key={holder_key}");
    println(f"randomness={randomness}");
}

#[test]
fn emit_toml_issuance() {
    emit_prover_toml(issuance_of());
}
