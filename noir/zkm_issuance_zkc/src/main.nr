use zkm_lib::{
    compute_mandate_commitment, compute_mandate_root_id, compute_zkc_composition_binding,
    compute_zkc_issuance_context, derive_zkc_composable_subject_handle, derive_zkm_issuance_key,
    MandateNote, ZKC_PROFILE_LINKABLE, ZKC_PROFILE_SCOPED,
};

fn main(
    cm: pub Field,
    settlement_context: pub Field,
    zkc_composition_binding: pub Field,
    entity_seed: Field,
    principal_issuance_key: Field,
    issuance_randomness: Field,
    settlement_domain: Field,
    asset_id: Field,
    remaining_cap: u128,
    expiry: u64,
    policy_hash: Field,
    holder_key: Field,
    randomness: Field,
    zkc_profile: u8,
    zkc_subject_handle: Field,
    zkc_scope_id: Field,
    zkc_vk_hash: Field,
    zkc_proof_digest: Field,
) {
    assert(cm != 0, "mandate commitment must be non-zero");
    assert(settlement_context != 0, "settlement context must be non-zero");
    assert(zkc_composition_binding != 0, "ZKC composition binding must be non-zero");
    assert(entity_seed != 0, "entity seed must be non-zero");
    assert(principal_issuance_key != 0, "principal issuance key must be non-zero");
    assert(asset_id != 0, "asset_id must be non-zero");
    assert(policy_hash != 0, "policy_hash must be non-zero");
    assert(holder_key != 0, "holder key must be non-zero");
    assert(zkc_vk_hash != 0, "ZKC VK hash must be non-zero");
    assert(zkc_proof_digest != 0, "ZKC proof digest must be non-zero");
    assert(settlement_domain == settlement_context, "issuance settlement domain mismatch");

    assert(
        principal_issuance_key == derive_zkm_issuance_key(entity_seed),
        "issuance key and ZKC holder must derive from the same entity seed",
    );
    let root_id = compute_mandate_root_id(principal_issuance_key, issuance_randomness);
    assert(root_id != 0, "root_id must be non-zero");
    let expected_cm = compute_mandate_commitment(
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
    assert(cm == expected_cm, "credential-bound issuance commitment mismatch");

    let expected_handle =
        derive_zkc_composable_subject_handle(entity_seed, zkc_profile, zkc_scope_id);
    assert(expected_handle == zkc_subject_handle, "ZKC subject handle mismatch");
    let proof_context = compute_zkc_issuance_context(cm, settlement_context);
    let expected_binding = compute_zkc_composition_binding(
        zkc_vk_hash,
        zkc_proof_digest,
        proof_context,
        zkc_profile,
        zkc_subject_handle,
        zkc_scope_id,
    );
    assert(
        expected_binding == zkc_composition_binding,
        "ZKC proof, VK, profile or issuance context mismatch",
    );
}

struct IssuanceZkc {
    cm: Field,
    settlement_context: Field,
    zkc_composition_binding: Field,
    entity_seed: Field,
    principal_issuance_key: Field,
    issuance_randomness: Field,
    settlement_domain: Field,
    asset_id: Field,
    remaining_cap: u128,
    expiry: u64,
    policy_hash: Field,
    holder_key: Field,
    randomness: Field,
    zkc_profile: u8,
    zkc_subject_handle: Field,
    zkc_scope_id: Field,
    zkc_vk_hash: Field,
    zkc_proof_digest: Field,
}

impl IssuanceZkc {
    fn run(self) {
        main(
            self.cm,
            self.settlement_context,
            self.zkc_composition_binding,
            self.entity_seed,
            self.principal_issuance_key,
            self.issuance_randomness,
            self.settlement_domain,
            self.asset_id,
            self.remaining_cap,
            self.expiry,
            self.policy_hash,
            self.holder_key,
            self.randomness,
            self.zkc_profile,
            self.zkc_subject_handle,
            self.zkc_scope_id,
            self.zkc_vk_hash,
            self.zkc_proof_digest,
        );
    }
}

fn fixture() -> IssuanceZkc {
    let entity_seed = 4242;
    let principal_issuance_key = derive_zkm_issuance_key(entity_seed);
    let issuance_randomness = 13;
    let settlement_context = 0x5e77_1e3c;
    let asset_id = 7;
    let policy_hash = 33;
    let holder_key = 44;
    let randomness = 555;
    let root_id = compute_mandate_root_id(principal_issuance_key, issuance_randomness);
    let cm = compute_mandate_commitment(
        MandateNote {
            root_id,
            settlement_domain: settlement_context,
            asset_id,
            remaining_cap: 1000,
            expiry: 2000,
            policy_hash,
            holder_key,
            depth: 0,
            randomness,
        },
    );
    let zkc_profile = ZKC_PROFILE_SCOPED;
    let zkc_scope_id = 9001;
    let zkc_subject_handle =
        derive_zkc_composable_subject_handle(entity_seed, zkc_profile, zkc_scope_id);
    let zkc_vk_hash = 10001;
    let zkc_proof_digest = 11001;
    let proof_context = compute_zkc_issuance_context(cm, settlement_context);
    let zkc_composition_binding = compute_zkc_composition_binding(
        zkc_vk_hash,
        zkc_proof_digest,
        proof_context,
        zkc_profile,
        zkc_subject_handle,
        zkc_scope_id,
    );
    IssuanceZkc {
        cm,
        settlement_context,
        zkc_composition_binding,
        entity_seed,
        principal_issuance_key,
        issuance_randomness,
        settlement_domain: settlement_context,
        asset_id,
        remaining_cap: 1000,
        expiry: 2000,
        policy_hash,
        holder_key,
        randomness,
        zkc_profile,
        zkc_subject_handle,
        zkc_scope_id,
        zkc_vk_hash,
        zkc_proof_digest,
    }
}

fn linkable_fixture() -> IssuanceZkc {
    let mut f = fixture();
    f.zkc_profile = ZKC_PROFILE_LINKABLE;
    f.zkc_scope_id = 0;
    f.zkc_subject_handle =
        derive_zkc_composable_subject_handle(f.entity_seed, f.zkc_profile, f.zkc_scope_id);
    let proof_context = compute_zkc_issuance_context(f.cm, f.settlement_context);
    f.zkc_composition_binding = compute_zkc_composition_binding(
        f.zkc_vk_hash,
        f.zkc_proof_digest,
        proof_context,
        f.zkc_profile,
        f.zkc_subject_handle,
        f.zkc_scope_id,
    );
    f
}

#[test]
fn test_scoped_credential_bound_issuance() {
    fixture().run();
}

#[test(should_fail_with = "scoped ZKC presentation requires a non-zero scope")]
fn test_scoped_credential_bound_issuance_zero_scope_rejected() {
    let mut f = fixture();
    f.zkc_scope_id = 0;
    // Rebuild the raw handle and binding without the guarded derivation helper.
    // Every other witness stays consistent, so only the zero-scope guard rejects it.
    f.zkc_subject_handle = zkm_lib::poseidon3(
        zkm_lib::DOMAIN_ZKC_PRESENTATION_SCOPE,
        zkm_lib::derive_zkc_credential_binding_key(f.entity_seed),
        0,
    );
    f.zkc_composition_binding = compute_zkc_composition_binding(
        f.zkc_vk_hash,
        f.zkc_proof_digest,
        compute_zkc_issuance_context(f.cm, f.settlement_context),
        f.zkc_profile,
        f.zkc_subject_handle,
        f.zkc_scope_id,
    );
    f.run();
}

#[test]
fn test_linkable_credential_bound_issuance() {
    linkable_fixture().run();
}

#[test(should_fail_with = "issuance key and ZKC holder must derive from the same entity seed")]
fn test_swapped_holder_rejected() {
    let mut f = fixture();
    f.entity_seed += 1;
    f.run();
}

#[test(should_fail_with = "issuance key and ZKC holder must derive from the same entity seed")]
fn test_swapped_issuance_key_rejected() {
    let mut f = fixture();
    f.principal_issuance_key += 1;
    f.run();
}

#[test(should_fail_with = "ZKC proof, VK, profile or issuance context mismatch")]
fn test_swapped_context_rejected() {
    let mut f = fixture();
    f.settlement_context += 1;
    f.settlement_domain = f.settlement_context;
    let root_id = compute_mandate_root_id(f.principal_issuance_key, f.issuance_randomness);
    f.cm = compute_mandate_commitment(
        MandateNote {
            root_id,
            settlement_domain: f.settlement_domain,
            asset_id: f.asset_id,
            remaining_cap: f.remaining_cap,
            expiry: f.expiry,
            policy_hash: f.policy_hash,
            holder_key: f.holder_key,
            depth: 0,
            randomness: f.randomness,
        },
    );
    f.run();
}

#[test(should_fail)]
fn test_swapped_profile_rejected() {
    let mut f = fixture();
    f.zkc_profile = ZKC_PROFILE_LINKABLE;
    f.run();
}

#[test(should_fail_with = "ZKC proof, VK, profile or issuance context mismatch")]
fn test_swapped_vk_rejected() {
    let mut f = fixture();
    f.zkc_vk_hash += 1;
    f.run();
}

#[test(should_fail_with = "ZKC proof, VK, profile or issuance context mismatch")]
fn test_swapped_proof_rejected() {
    let mut f = fixture();
    f.zkc_proof_digest += 1;
    f.run();
}

#[test(should_fail_with = "ZKC proof, VK, profile or issuance context mismatch")]
fn test_swapped_composition_binding_rejected() {
    let mut f = fixture();
    f.zkc_composition_binding += 1;
    f.run();
}

#[test(should_fail_with = "ZKC subject handle mismatch")]
fn test_swapped_zkc_subject_handle_rejected() {
    let mut f = fixture();
    f.zkc_subject_handle += 1;
    f.run();
}

#[test(should_fail)]
fn test_anonymous_profile_rejected() {
    let mut f = fixture();
    f.zkc_profile = 0;
    f.zkc_subject_handle = 0;
    f.zkc_scope_id = 0;
    f.run();
}

#[test(should_fail_with = "anonymous or unknown ZKC profile cannot use handle composition")]
fn test_unknown_profile_rejected() {
    let mut f = fixture();
    f.zkc_profile = 3;
    f.run();
}

#[test(should_fail_with = "linkable ZKC presentation must not carry a scope")]
fn test_linkable_profile_with_scope_rejected() {
    let mut f = linkable_fixture();
    f.zkc_scope_id = 1;
    f.run();
}

fn emit_prover_toml(f: IssuanceZkc) {
    let cm = f.cm;
    let settlement_context = f.settlement_context;
    let zkc_composition_binding = f.zkc_composition_binding;
    let entity_seed = f.entity_seed;
    let principal_issuance_key = f.principal_issuance_key;
    let issuance_randomness = f.issuance_randomness;
    let settlement_domain = f.settlement_domain;
    let asset_id = f.asset_id;
    let remaining_cap = f.remaining_cap;
    let expiry = f.expiry;
    let policy_hash = f.policy_hash;
    let holder_key = f.holder_key;
    let randomness = f.randomness;
    let zkc_profile = f.zkc_profile;
    let zkc_subject_handle = f.zkc_subject_handle;
    let zkc_scope_id = f.zkc_scope_id;
    let zkc_vk_hash = f.zkc_vk_hash;
    let zkc_proof_digest = f.zkc_proof_digest;
    println(f"cm={cm}");
    println(f"settlement_context={settlement_context}");
    println(f"zkc_composition_binding={zkc_composition_binding}");
    println(f"entity_seed={entity_seed}");
    println(f"principal_issuance_key={principal_issuance_key}");
    println(f"issuance_randomness={issuance_randomness}");
    println(f"settlement_domain={settlement_domain}");
    println(f"asset_id={asset_id}");
    println(f"remaining_cap={remaining_cap}");
    println(f"expiry={expiry}");
    println(f"policy_hash={policy_hash}");
    println(f"holder_key={holder_key}");
    println(f"randomness={randomness}");
    println(f"zkc_profile={zkc_profile}");
    println(f"zkc_subject_handle={zkc_subject_handle}");
    println(f"zkc_scope_id={zkc_scope_id}");
    println(f"zkc_vk_hash={zkc_vk_hash}");
    println(f"zkc_proof_digest={zkc_proof_digest}");
}

#[test]
fn emit_toml_issuance_zkc_scoped() {
    emit_prover_toml(fixture());
}

#[test]
fn emit_toml_issuance_zkc_linkable() {
    emit_prover_toml(linkable_fixture());
}
// ZKM credential-bound issuance statement (`zkm:issuance-zkc:v1`).
//
// This is additive to the base issuance VK. It proves the mandate is a
// well-formed depth-0 issuance and that the principal issuance authority and a
// separately verified scoped/linkable ZKC presentation derive from the same
// private KDC entity seed. The inner ZKC proof is verified by the settlement or
// recursive bundle layer; this circuit binds its canonical digest, VK, exact
// interaction context, profile and subject handle into one public field.
// Anonymous v0.4 presentations expose no subject handle and are rejected here;
// they require a predicate-specific single circuit that shares the entity seed
// directly with the ZKC predicate constraints.
