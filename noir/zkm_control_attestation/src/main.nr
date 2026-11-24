// ZKM control-attestation circuit — the §5 `zkm:control-attestation:v1`
// statement, introduced in rev 7 alongside the `zkm:disclosure:v1` envelope.
//
// WHAT IT PROVES. "The party that assembled this disclosure envelope holds the
// issuance authority behind the lineage the envelope describes." A disclosure
// recipient (an auditor, a PSP, a counterparty the principal chose to inform)
// needs that assurance, or the envelope is an unattributed pile of openings
// anyone could have forged from observed settlement state.
//
// THE HAZARD THIS CIRCUIT EXISTS TO AVOID — READ BEFORE CHANGING ANYTHING HERE.
// ============================================================================
// The obvious way to prove lineage control is to reuse `zkm_revocation_auth`:
// it already proves knowledge of the `root_id` preimage, which §7.1 calls "the
// principal's issuance authority". Doing that would be a serious defect. That
// circuit's public vector `(root_id, settlement_context)` is *exactly* the
// statement a settlement layer accepts as authorization to insert `root_id`
// into the §7.1 exclusion accumulator. An envelope carrying one would hand its
// recipient a live, transferable capability to KILL the lineage — the principal
// would be disclosing its books and enclosing the murder weapon. Disclosure
// must transfer information, never authority (§5).
//
// THE RESOLUTION IS STRUCTURAL, NOT PROCEDURAL. This is a separate circuit with
// a separate VK, and — the load-bearing part — its public vector CONTAINS NO
// `root_id`. It publishes
// `lineage_tag = H(DOMAIN, root_id, settlement_context, disclosure_binding)`
// instead. A settlement layer performing a revocation insertion must know which
// field element to insert, and it takes that value from the proof's public
// inputs; this vector supplies no `root_id` to take. The safety property is
// therefore an ABSENCE that is checkable by reading the public vector — the
// same species of argument §5 makes for the mandate-only VK carrying no ZKA
// value leg — rather than a rule an integrator must remember.
//
// BE PRECISE ABOUT WHAT THIS DOES AND DOES NOT DO, because overclaiming it
// would be worse than not claiming it. It is NOT a secrecy argument about
// `root_id`: the disclosure recipient learns `root_id` anyway, from the note
// openings the envelope exists to deliver. What actually stops that recipient
// revoking is that `zkm_revocation_auth` requires WITNESS knowledge of the
// issuance-key preimage, which §5 rule 3 keeps out of the envelope — knowing
// `root_id` buys nothing against preimage resistance. The absent public input
// defends a narrower and still-worthwhile case: a settlement layer that has
// been misconfigured to accept this VK for revocation insertion has no field
// element to insert, so the misconfiguration is inert rather than exploitable.
// Layer 3 below is the primary defense; this is the one that survives its
// failure.
//
// Three independent things must hold, and they are listed in the order a
// reviewer should check them:
//   1. (here) the vector carries no `root_id`;
//   2. (§6 registry) the deployment maps `zkm:control-attestation:v1` to THIS
//      VK and `zkm:revocation-auth:v1` to the other one — one VK per statement;
//   3. (§7.1) a settlement layer accepts revocation insertion ONLY under the
//      revocation-auth VK.
// Rule 3 alone would suffice against a correct implementation. Rule 1 is what
// survives an incorrect one.
//
// AND NOT THE CONVERSE, EITHER. A `zkm_revocation_auth` proof MUST NOT be
// placed in a disclosure envelope as a substitute for this attestation, even
// though it would convince a recipient of the same fact. §5 makes that an SDK
// MUST NOT. It cannot be enforced here — a circuit cannot police what an SDK
// puts in a JSON envelope — so it is stated where it can be: in the SDK rules
// and in the envelope schema, which admits only this statement discriminator.
//
// DISCLOSURE BINDING. `disclosure_binding` is an opaque public field the
// discloser computes off-circuit over the audience and the envelope contents
// (§5; REQUIRED construction under `zkm/disclosure_binding/v1`). This
// circuit deliberately does not interpret it. It cannot: no in-circuit check
// can establish that an off-circuit digest was computed over the envelope
// honestly claimed. What the circuit DOES give is binding — UltraHonk verifies
// against the exact public vector, so an attestation proven for one binding
// does not verify under another. The recipient MUST recompute that binding
// from the normative projection and check its authenticated audience/nonce;
// accepting the supplied field alone does not prevent envelope lifting.
// Folding the binding into `lineage_tag` additionally makes the tag itself
// per-envelope, so two attestations of one lineage to two audiences have
// different tags. Disclosed note openings themselves intentionally reveal `root_id`, so
// recipients comparing openings can still correlate a disclosed lineage.
//
// PRIVACY. This proof is never published. It travels inside a holder-assembled
// envelope to a party the principal chose (§5), so it adds no observable
// surface to settlement — the §4.6 residual list is unchanged by rev 7's
// disclosure machinery, and that is stated there explicitly. Within the
// envelope the recipient learns `root_id` anyway, from the note openings the
// envelope exists to deliver.
//
// REPLAY, honestly. Nothing here is single-use: a recipient can re-verify the
// attestation forever, and can show it to third parties along with the envelope
// it is bound to. That is inherent to disclosure and is not a defect — an
// envelope cannot be un-sent (§5 SDK rules say so in as many words). What the
// binding prevents is the attestation being LIFTED into a different envelope,
// which is the transferability that would matter.

use zkm_lib::{compute_control_attestation_tag, compute_mandate_root_id};

fn main(
    // ---- public inputs -------------------------------------------------
    // `H_{zkm/control_attestation/v1}(root_id, settlement_context,
    // disclosure_binding)` — the preimage order is normative, and an
    // independent implementer deriving it in any other order produces a tag
    // the recipient's rule-1(e) check will reject. NOT `root_id` itself: see
    // the hazard note above. Changing this to a bare `root_id` reintroduces
    // the revocation-capability leak and is the single change reviewers of
    // this file must refuse.
    lineage_tag: pub Field,
    // Settlement-domain binding. UNLIKE the other ZKM statements, where this is
    // bare "§5 hygiene" (asserted non-zero and otherwise unconstrained), here it
    // is IN THE TAG PREIMAGE — so the recipient's own tag recomputation detects
    // an attestation presented against the wrong domain, without having to
    // remember a separate comparison. See the note on
    // `compute_control_attestation_tag`.
    settlement_context: pub Field,
    // Audience + envelope binding, opaque here (see header).
    disclosure_binding: pub Field,
    // ---- private witnesses ---------------------------------------------
    principal_issuance_key: Field,
    issuance_randomness: Field,
) {
    assert(lineage_tag != 0, "lineage tag must be non-zero");
    assert(settlement_context != 0, "settlement context must be non-zero");
    assert(disclosure_binding != 0, "disclosure binding must be non-zero");
    assert(principal_issuance_key != 0, "principal issuance key must be non-zero");

    // The lineage this attestation speaks for. Never public.
    let root_id = compute_mandate_root_id(principal_issuance_key, issuance_randomness);
    assert(root_id != 0, "root_id must be non-zero");

    // THE ATTESTATION: the assembler knows the issuance material behind the
    // lineage, and this proof is bound to this settlement domain, this envelope
    // and this audience.
    assert(
        compute_control_attestation_tag(root_id, settlement_context, disclosure_binding)
            == lineage_tag,
        "prover does not hold the issuance authority for this lineage tag",
    );
}

// =============================================================================
// Tests — fixture constants mirror `zkm_revocation_auth`, deliberately: the
// lineage attested here is the lineage that package revokes, so a reader can
// hold the two public vectors side by side and see that one carries `root_id`
// and the other does not.
// =============================================================================

global PRINCIPAL_ISSUANCE_KEY: Field = 991;
global ISSUANCE_RANDOMNESS: Field = 13;
global SETTLEMENT_CONTEXT: Field = 0x5e77_1e3c;
global DISCLOSURE_BINDING: Field = 0x0d15_c105;

struct ControlAttestation {
    lineage_tag: Field,
    settlement_context: Field,
    disclosure_binding: Field,
    principal_issuance_key: Field,
    issuance_randomness: Field,
}

impl ControlAttestation {
    fn run(self) {
        main(
            self.lineage_tag,
            self.settlement_context,
            self.disclosure_binding,
            self.principal_issuance_key,
            self.issuance_randomness,
        );
    }
}

fn attestation_of() -> ControlAttestation {
    let root_id = compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS);
    ControlAttestation {
        lineage_tag: compute_control_attestation_tag(
            root_id,
            SETTLEMENT_CONTEXT,
            DISCLOSURE_BINDING,
        ),
        settlement_context: SETTLEMENT_CONTEXT,
        disclosure_binding: DISCLOSURE_BINDING,
        principal_issuance_key: PRINCIPAL_ISSUANCE_KEY,
        issuance_randomness: ISSUANCE_RANDOMNESS,
    }
}

#[test]
fn test_control_attested() {
    attestation_of().run();
}

#[test(should_fail_with = "prover does not hold the issuance authority for this lineage tag")]
fn test_wrong_key_rejected() {
    let mut a = attestation_of();
    a.principal_issuance_key = PRINCIPAL_ISSUANCE_KEY + 1;
    a.run();
}

#[test(should_fail_with = "prover does not hold the issuance authority for this lineage tag")]
fn test_wrong_randomness_rejected() {
    let mut a = attestation_of();
    a.issuance_randomness = ISSUANCE_RANDOMNESS + 1;
    a.run();
}

#[test(should_fail_with = "prover does not hold the issuance authority for this lineage tag")]
fn test_foreign_lineage_rejected() {
    // A party that observed some other lineage's `root_id` — from an honest
    // revocation, say (§7.1 publishes one) — cannot attest control of it.
    let mut a = attestation_of();
    let foreign = compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY + 1, ISSUANCE_RANDOMNESS);
    a.lineage_tag =
        compute_control_attestation_tag(foreign, SETTLEMENT_CONTEXT, DISCLOSURE_BINDING);
    a.run();
}

#[test(should_fail_with = "prover does not hold the issuance authority for this lineage tag")]
fn test_attestation_not_transferable_between_envelopes() {
    // THE BINDING PROPERTY. An attestation assembled for one envelope/audience
    // must not verify once lifted into another. Here the tag is the one
    // computed for DISCLOSURE_BINDING while the public binding says otherwise;
    // the recomputation inside the circuit no longer matches.
    let mut a = attestation_of();
    a.disclosure_binding = DISCLOSURE_BINDING + 1;
    a.run();
}

#[test(should_fail_with = "prover does not hold the issuance authority for this lineage tag")]
fn test_raw_root_id_as_tag_rejected() {
    // THE HAZARD, ASSERTED. Someone "simplifying" this circuit toward
    // `zkm_revocation_auth`'s shape would publish `root_id` directly. This
    // pins that a bare `root_id` is NOT a valid `lineage_tag`, so the two
    // statements cannot be silently conflated by a prover.
    let mut a = attestation_of();
    a.lineage_tag = compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS);
    a.run();
}

#[test]
fn test_distinct_audiences_yield_uncorrelatable_tags() {
    // Two attestations of ONE lineage to TWO audiences have different tags.
    // Tags alone do not link the lineage; the note openings in a disclosure
    // intentionally reveal root_id and can be correlated (§4.6).
    let root_id = compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS);
    let tag_a = compute_control_attestation_tag(root_id, SETTLEMENT_CONTEXT, DISCLOSURE_BINDING);
    let tag_b =
        compute_control_attestation_tag(root_id, SETTLEMENT_CONTEXT, DISCLOSURE_BINDING + 1);
    assert(tag_a != tag_b, "per-envelope tags must differ");
    assert(tag_a != root_id, "tag must not equal the root_id it hides");
    assert(tag_b != root_id, "tag must not equal the root_id it hides");
}

#[test(should_fail_with = "prover does not hold the issuance authority for this lineage tag")]
fn test_attestation_not_transferable_across_settlement_domains() {
    // THE DOMAIN BINDING. An attestation assembled for one settlement target
    // must not verify when presented against another. The proof would already
    // reject this — UltraHonk binds the whole public vector — but the point of
    // folding `settlement_context` into the tag is that the RECIPIENT'S OWN
    // recomputation catches it too (§5 disclosure rule 1(e)), rather than
    // relying on the recipient to separately compare the attestation's context
    // against the envelope's `metadata.context`.
    let mut a = attestation_of();
    a.settlement_context = SETTLEMENT_CONTEXT + 1;
    a.run();
}

#[test]
fn test_same_lineage_on_two_domains_yields_distinct_tags() {
    // The companion property, stated positively: the tag identifies
    // (lineage, domain, envelope), so it cannot be lifted between domains
    // even by a party that knows every other input.
    let root_id = compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS);
    let on_a = compute_control_attestation_tag(root_id, SETTLEMENT_CONTEXT, DISCLOSURE_BINDING);
    let on_b = compute_control_attestation_tag(root_id, SETTLEMENT_CONTEXT + 1, DISCLOSURE_BINDING);
    assert(on_a != on_b, "per-domain tags must differ");
}

#[test(should_fail_with = "lineage tag must be non-zero")]
fn test_zero_lineage_tag_rejected() {
    let mut a = attestation_of();
    a.lineage_tag = 0;
    a.run();
}

#[test(should_fail_with = "settlement context must be non-zero")]
fn test_zero_settlement_context_rejected() {
    let mut a = attestation_of();
    a.settlement_context = 0;
    a.run();
}

#[test(should_fail_with = "disclosure binding must be non-zero")]
fn test_zero_disclosure_binding_rejected() {
    let mut a = attestation_of();
    a.disclosure_binding = 0;
    a.run();
}

#[test(should_fail_with = "principal issuance key must be non-zero")]
fn test_zero_issuance_key_rejected() {
    let mut a = attestation_of();
    a.principal_issuance_key = 0;
    a.run();
}

// =============================================================================
// Prover.toml emission for the bb proving harness.
// =============================================================================

fn emit_prover_toml(a: ControlAttestation) {
    let lineage_tag = a.lineage_tag;
    let settlement_context = a.settlement_context;
    let disclosure_binding = a.disclosure_binding;
    println(f"lineage_tag={lineage_tag}");
    println(f"settlement_context={settlement_context}");
    println(f"disclosure_binding={disclosure_binding}");

    let principal_issuance_key = a.principal_issuance_key;
    let issuance_randomness = a.issuance_randomness;
    println(f"principal_issuance_key={principal_issuance_key}");
    println(f"issuance_randomness={issuance_randomness}");
}

#[test]
fn emit_toml_control_attestation() {
    emit_prover_toml(attestation_of());
}

/// Emits the fixture's `root_id` for the harness's N3 negative case, which
/// asserts that this value appears NOWHERE in the circuit's real public
/// inputs. Keeping the emission here means the harness and the circuit share
/// one source of truth for the fixture: a change to the fixture constants
/// cannot make N3 silently check the wrong lineage.
#[test]
fn emit_fixture_root_id() {
    let root_id = compute_mandate_root_id(PRINCIPAL_ISSUANCE_KEY, ISSUANCE_RANDOMNESS);
    println(f"fixture_root_id={root_id}");
}
