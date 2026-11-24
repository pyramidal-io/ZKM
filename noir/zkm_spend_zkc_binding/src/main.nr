use zkm_lib::{
    compute_zka_asset_commitment, compute_zka_note_commitment, compute_zkc_composition_binding,
    compute_zkc_spend_context, derive_zka_address, derive_zka_spending_key,
    derive_zkc_composable_subject_handle, derive_zkc_holder_commitment, ZKC_PROFILE_LINKABLE,
    ZKC_PROFILE_SCOPED,
};

fn main(
    nf: pub Field,
    zka_cm_recipient: pub Field,
    asset_id: pub Field,
    settlement_context: pub Field,
    zkc_composition_binding: pub Field,
    recipient_entity_seed: Field,
    amount: u128,
    recipient_randomness: Field,
    zkc_profile: u8,
    zkc_subject_handle: Field,
    zkc_scope_id: Field,
    zkc_vk_hash: Field,
    zkc_proof_digest: Field,
) {
    assert(nf != 0, "mandate nullifier must be non-zero");
    assert(zka_cm_recipient != 0, "ZKA recipient commitment must be non-zero");
    assert(asset_id != 0, "asset_id must be non-zero");
    assert(settlement_context != 0, "settlement context must be non-zero");
    assert(zkc_composition_binding != 0, "ZKC composition binding must be non-zero");
    assert(recipient_entity_seed != 0, "recipient entity seed must be non-zero");
    assert(recipient_randomness != 0, "recipient randomness must be non-zero");
    assert(zkc_vk_hash != 0, "ZKC VK hash must be non-zero");
    assert(zkc_proof_digest != 0, "ZKC proof digest must be non-zero");

    let recipient = recipient_address(recipient_entity_seed);
    let asset_cm = compute_zka_asset_commitment(asset_id);
    let expected_recipient_cm =
        compute_zka_note_commitment(asset_cm, amount as Field, recipient, recipient_randomness);
    assert(
        expected_recipient_cm == zka_cm_recipient,
        "ZKC holder does not control the ZKA recipient note",
    );

    let expected_handle =
        derive_zkc_composable_subject_handle(recipient_entity_seed, zkc_profile, zkc_scope_id);
    assert(expected_handle == zkc_subject_handle, "ZKC subject handle mismatch");
    let proof_context = compute_zkc_spend_context(nf, zka_cm_recipient, settlement_context);
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
        "ZKC proof, VK, profile or spend context mismatch",
    );
}

// KDC A.6 derives a ZKA spending key from the shared entity seed. ZKA's
// address API accepts that spending key, not the seed itself.
fn recipient_address(entity_seed: Field) -> Field {
    derive_zka_address(derive_zka_spending_key(entity_seed))
}

struct SpendZkcBinding {
    nf: Field,
    zka_cm_recipient: Field,
    asset_id: Field,
    settlement_context: Field,
    zkc_composition_binding: Field,
    recipient_entity_seed: Field,
    amount: u128,
    recipient_randomness: Field,
    zkc_profile: u8,
    zkc_subject_handle: Field,
    zkc_scope_id: Field,
    zkc_vk_hash: Field,
    zkc_proof_digest: Field,
}

impl SpendZkcBinding {
    fn run(self) {
        main(
            self.nf,
            self.zka_cm_recipient,
            self.asset_id,
            self.settlement_context,
            self.zkc_composition_binding,
            self.recipient_entity_seed,
            self.amount,
            self.recipient_randomness,
            self.zkc_profile,
            self.zkc_subject_handle,
            self.zkc_scope_id,
            self.zkc_vk_hash,
            self.zkc_proof_digest,
        );
    }
}

fn fixture() -> SpendZkcBinding {
    // These four matching values are the canonical unrestricted-spend fixture
    // from zkm_spend_conjoined::kat_conjoined_public_inputs. Keeping this
    // companion on the same output lets the proving harness exercise the
    // settlement rule against two real proofs rather than two unrelated valid
    // statements.
    let recipient_entity_seed = 8888;
    let asset_id = 7;
    let amount: u128 = 400;
    let recipient_randomness = 7003;
    let recipient = recipient_address(recipient_entity_seed);
    let asset_cm = compute_zka_asset_commitment(asset_id);
    let zka_cm_recipient =
        compute_zka_note_commitment(asset_cm, amount as Field, recipient, recipient_randomness);
    let nf = 0x08baf96e623fdfcda647a9919dce6bd34134561705598bb2dbbdf839a27d7eec;
    let settlement_context = 0x5e77_1e3c;
    let zkc_profile = ZKC_PROFILE_SCOPED;
    let zkc_scope_id = 9001;
    let zkc_subject_handle =
        derive_zkc_composable_subject_handle(recipient_entity_seed, zkc_profile, zkc_scope_id);
    let zkc_vk_hash = 10001;
    let zkc_proof_digest = 11001;
    let proof_context = compute_zkc_spend_context(nf, zka_cm_recipient, settlement_context);
    let zkc_composition_binding = compute_zkc_composition_binding(
        zkc_vk_hash,
        zkc_proof_digest,
        proof_context,
        zkc_profile,
        zkc_subject_handle,
        zkc_scope_id,
    );
    SpendZkcBinding {
        nf,
        zka_cm_recipient,
        asset_id,
        settlement_context,
        zkc_composition_binding,
        recipient_entity_seed,
        amount,
        recipient_randomness,
        zkc_profile,
        zkc_subject_handle,
        zkc_scope_id,
        zkc_vk_hash,
        zkc_proof_digest,
    }
}

fn linkable_fixture() -> SpendZkcBinding {
    let mut f = fixture();
    f.zkc_profile = ZKC_PROFILE_LINKABLE;
    f.zkc_scope_id = 0;
    f.zkc_subject_handle = derive_zkc_composable_subject_handle(
        f.recipient_entity_seed,
        f.zkc_profile,
        f.zkc_scope_id,
    );
    let proof_context = compute_zkc_spend_context(f.nf, f.zka_cm_recipient, f.settlement_context);
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
fn test_scoped_holder_controls_recipient() {
    let f = fixture();
    assert(
        f.zka_cm_recipient == 0x2d720b87b17436a59885d6e1c7c409941eae3ab13e544b7b08c158ce497fac94,
        "recipient commitment drifted from the spend-conjoined KAT",
    );
    f.run();
}

// AFP-KDC v1.0.2 A.6 boundary vectors. These expected values are from
// the authenticated AFP-KDC conformance vectors. The zero vector
// tests KDC derivation only; main still rejects a zero entity seed.
#[test]
fn test_recipient_kdc_zero() {
    let seed: Field = 0;
    assert(
        recipient_address(seed)
            == 0x1e59072f0fac351c5c4e80a8291ec26d58ef4aaf766c8206cd7ca677b0a9b5a5,
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x26911baa3a91df3ae99b57264dd8ffc1a774b75adb6bc44f801eab9a28dbb85c,
    );
}

#[test]
fn test_recipient_kdc_one() {
    let seed: Field = 1;
    assert(
        recipient_address(seed)
            == 0x0f26d097b8cdb6e1a28dcb476c9ba0404139ccb92567f2ea3bc2136c70e00bfe,
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x1b5da79c042b6f60628ca40f9f36af41ba93a4e0706f18d63918ead501bded10,
    );
}

#[test]
fn test_recipient_kdc_r_minus_1() {
    let seed: Field = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
    assert(
        recipient_address(seed)
            == 0x2f5f49c1a110fc0afaf2757591deb20e1826e1790fb815eed0f371f255fdef01,
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x0f93ef96e2e9889be72f147c815effddd4836f6a03c133b9383eaa4c0237d9ae,
    );
}

#[test]
fn test_recipient_kdc_high_bit() {
    let seed: Field = 0x1f37631a3d9cbfac8f5f7492fcfd4f45af982f6f0c8d1edd783c14d81ffffffe;
    assert(
        recipient_address(seed)
            == 0x2cdbe57561dc37866f283823339e4551faffbfa407fc1147bc4db440b8adf826,
    );
    assert(
        derive_zkc_holder_commitment(seed)
            == 0x20bdb27ab52177af841502649fae65d8f7ad2456c92afa3392c75e40fd4854e3,
    );
}

#[test(should_fail_with = "ZKC holder does not control the ZKA recipient note")]
fn test_seed_used_as_spending_key_rejected() {
    let mut f = fixture();
    let old_address = derive_zka_address(f.recipient_entity_seed);
    let asset_cm = compute_zka_asset_commitment(f.asset_id);
    f.zka_cm_recipient = compute_zka_note_commitment(
        asset_cm,
        f.amount as Field,
        old_address,
        f.recipient_randomness,
    );
    f.run();
}

#[test(should_fail_with = "scoped ZKC presentation requires a non-zero scope")]
fn test_scoped_holder_zero_scope_rejected() {
    let mut f = fixture();
    f.zkc_scope_id = 0;
    // Rebuild the raw handle and binding without the guarded derivation helper.
    // Every other witness stays consistent, so only the zero-scope guard rejects it.
    f.zkc_subject_handle = zkm_lib::poseidon3(
        zkm_lib::DOMAIN_ZKC_PRESENTATION_SCOPE,
        zkm_lib::derive_zkc_credential_binding_key(f.recipient_entity_seed),
        0,
    );
    f.zkc_composition_binding = compute_zkc_composition_binding(
        f.zkc_vk_hash,
        f.zkc_proof_digest,
        compute_zkc_spend_context(f.nf, f.zka_cm_recipient, f.settlement_context),
        f.zkc_profile,
        f.zkc_subject_handle,
        f.zkc_scope_id,
    );
    f.run();
}

#[test]
fn test_linkable_holder_controls_recipient() {
    linkable_fixture().run();
}

#[test(should_fail_with = "ZKC holder does not control the ZKA recipient note")]
fn test_swapped_holder_rejected() {
    let mut f = fixture();
    f.recipient_entity_seed += 1;
    f.run();
}

#[test(should_fail_with = "ZKC holder does not control the ZKA recipient note")]
fn test_swapped_recipient_rejected() {
    let mut f = fixture();
    f.zka_cm_recipient += 1;
    f.run();
}

#[test(should_fail_with = "ZKC proof, VK, profile or spend context mismatch")]
fn test_swapped_context_rejected() {
    let mut f = fixture();
    f.settlement_context += 1;
    f.run();
}

#[test(should_fail)]
fn test_swapped_profile_rejected() {
    let mut f = fixture();
    f.zkc_profile = ZKC_PROFILE_LINKABLE;
    f.run();
}

#[test(should_fail_with = "ZKC proof, VK, profile or spend context mismatch")]
fn test_swapped_vk_rejected() {
    let mut f = fixture();
    f.zkc_vk_hash += 1;
    f.run();
}

#[test(should_fail_with = "ZKC proof, VK, profile or spend context mismatch")]
fn test_swapped_proof_rejected() {
    let mut f = fixture();
    f.zkc_proof_digest += 1;
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

fn emit_prover_toml(f: SpendZkcBinding) {
    let nf = f.nf;
    let zka_cm_recipient = f.zka_cm_recipient;
    let asset_id = f.asset_id;
    let settlement_context = f.settlement_context;
    let zkc_composition_binding = f.zkc_composition_binding;
    let recipient_entity_seed = f.recipient_entity_seed;
    let amount = f.amount;
    let recipient_randomness = f.recipient_randomness;
    let zkc_profile = f.zkc_profile;
    let zkc_subject_handle = f.zkc_subject_handle;
    let zkc_scope_id = f.zkc_scope_id;
    let zkc_vk_hash = f.zkc_vk_hash;
    let zkc_proof_digest = f.zkc_proof_digest;
    println(f"nf={nf}");
    println(f"zka_cm_recipient={zka_cm_recipient}");
    println(f"asset_id={asset_id}");
    println(f"settlement_context={settlement_context}");
    println(f"zkc_composition_binding={zkc_composition_binding}");
    println(f"recipient_entity_seed={recipient_entity_seed}");
    println(f"amount={amount}");
    println(f"recipient_randomness={recipient_randomness}");
    println(f"zkc_profile={zkc_profile}");
    println(f"zkc_subject_handle={zkc_subject_handle}");
    println(f"zkc_scope_id={zkc_scope_id}");
    println(f"zkc_vk_hash={zkc_vk_hash}");
    println(f"zkc_proof_digest={zkc_proof_digest}");
}

#[test]
fn emit_toml_spend_zkc_scoped() {
    emit_prover_toml(fixture());
}

#[test]
fn emit_toml_spend_zkc_linkable() {
    emit_prover_toml(linkable_fixture());
}
// ZKM ZKC recipient-control companion (`zkm:spend-zkc-binding:v1`).
//
// This proof settles nothing by itself. It opens the matched public ZKA
// recipient commitment and proves its spending identity and a separately
// verified scoped/linkable ZKC presentation derive from the same private KDC
// entity seed. A settlement layer must match nf, recipient commitment, asset
// and context against `zkm:spend-conjoined:v2`, recompute the inner-proof
// composition binding, verify every proof, and only then apply the spend's five
// state effects atomically. Anonymous v0.4 presentations require a
// predicate-specific shared-witness circuit and are rejected by this generic
// handle companion.
