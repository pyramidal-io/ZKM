// =============================================================================
// ZKACredential TXE tests
//
// Covers ZKA v0.6.0 SS5.2 context binding on disclosure proofs, per the
// canonical model in docs/adr/0001 (Option A): the disclosed hash is the RAW,
// context-INDEPENDENT artifact (byte-identical to the standalone circuit's
// public input [1]); the session context is a SEPARATE co-equal binding (a
// constrained argument; a separate CredNote field in disclose_to), never folded
// into the hash. Coverage:
//   - MODEL:    same mask + different context -> SAME raw hash (binding separate).
//   - MASK:     different mask -> different hash (disclosure correctness).
//   - REJECT:   context == 0 reverts at every entry point.
//   - DETERMINISM: same mask -> same raw hash.
//   - AGGREGATE: aggregate_disclosures == aggregate of the two raw halves;
//                context-independent in value.
//   - DISCLOSE_TO: delivers a note to the recipient (raw hash + context field).
//   - ISSUER:   bind_credential accepts only the pinned issuer's signature over
//               this holder, contract, chain and values; disclose_to notes never
//               count as credentials.
//
// All tests deploy a fresh ZKACredential, bind an issuer-signed credential for
// the caller, and drive the disclosure functions via the in-process TXE.
// =============================================================================

use crate::ZKACredential;
use aztec::{
    context::PublicContext,
    keys::getters::get_public_keys,
    protocol::{address::AztecAddress, storage::map::derive_storage_slot_in_map, traits::ToField},
    state_vars::{DelayedPublicMutable, StateVariable},
    test::helpers::test_environment::TestEnvironment,
};
use zka_aztec_lib::{issuance_digest, IssuerKey, verify_issuer_signature};

global CRED_DATA: Field = 0x1234;
global CRED_ATTRS: [Field; 4] = [11, 22, 33, 44];

// -----------------------------------------------------------------------------
// TEST-ONLY issuer keys and signatures from aztec/scripts/issuer_test_signatures.py.
// TXE cannot sign with an arbitrary secp256k1 key, so each signature is
// precomputed for the deterministic TXE chain id, version, contract address and
// holder commitment of its scenario. The contract address, and with it the
// app-siloed holder commitment, changes with ANY ZKACredential bytecode change,
// so contract edits stale these vectors. `signed` checks a signature against
// the live digest first and prints a `stale-issuer-vector` line; pipe the TXE
// output to `issuer_test_signatures.py apply` to rewrite the globals.
// -----------------------------------------------------------------------------

global ISSUER_KEY: IssuerKey = IssuerKey {
    x: [
        0x49, 0x41, 0xcc, 0xa4, 0xdd, 0x2f, 0x71, 0x88, 0x76, 0x9e, 0xe2, 0x56, 0xc4, 0x71, 0x12,
        0xd3, 0xb6, 0x6e, 0xe3, 0x5c, 0x3f, 0xbc, 0x61, 0xc4, 0xbd, 0xed, 0xf9, 0x0e, 0x34, 0x79,
        0xb9, 0x3b,
    ],
    y: [
        0x81, 0x72, 0xad, 0xc3, 0x03, 0x4c, 0x17, 0x27, 0x3a, 0xbb, 0xa1, 0x3d, 0xf3, 0xa0, 0x59,
        0xcf, 0x83, 0xb8, 0x62, 0xe6, 0x65, 0xee, 0xb0, 0xf9, 0xf8, 0xfd, 0x44, 0x54, 0xab, 0x43,
        0x23, 0x4f,
    ],
};

global UNTRUSTED_ISSUER_KEY: IssuerKey = IssuerKey {
    x: [
        0x19, 0x04, 0x61, 0x4c, 0x04, 0x01, 0xfd, 0x8f, 0x4e, 0xf7, 0x50, 0x13, 0xd5, 0xec, 0xcb,
        0x45, 0x3c, 0xf3, 0x84, 0x0c, 0x68, 0x4d, 0x5a, 0xc9, 0x2e, 0x40, 0x6f, 0x09, 0x60, 0xd0,
        0x66, 0x0f,
    ],
    y: [
        0x23, 0x92, 0x7d, 0x0a, 0x19, 0x3d, 0x84, 0x21, 0x2d, 0x95, 0xcb, 0x1e, 0x35, 0xf1, 0xe9,
        0x8a, 0xae, 0x64, 0xb0, 0x8f, 0xbc, 0x73, 0xf0, 0xbc, 0x95, 0x6a, 0x30, 0xb5, 0x9f, 0xd5,
        0xe9, 0x5f,
    ],
};

// Trusted key, setup()'s holder and contract, CRED_DATA / CRED_ATTRS.
global SIG_HOLDER: [u8; 64] = [
    0x4b, 0xfc, 0xf6, 0x4d, 0x57, 0xbf, 0x62, 0xe5, 0x3f, 0x77, 0xd2, 0x3b, 0xed, 0xb7, 0x8b, 0x2b,
    0x4a, 0xb8, 0x8e, 0xe7, 0x64, 0x14, 0xc4, 0x1b, 0x12, 0x73, 0xaa, 0x4e, 0xcb, 0x40, 0x6e, 0x45,
    0x3a, 0x9a, 0xcd, 0xa5, 0xc4, 0x0c, 0x57, 0xa9, 0x70, 0x41, 0xde, 0xd7, 0x80, 0xc3, 0x79, 0xfc,
    0x08, 0x80, 0xe9, 0x29, 0x78, 0x16, 0x2c, 0x84, 0x38, 0xdc, 0xda, 0x58, 0x6e, 0x21, 0x34, 0x68,
];
// Untrusted key over the same transcript as SIG_HOLDER.
global SIG_HOLDER_UNTRUSTED: [u8; 64] = [
    0x54, 0x06, 0x01, 0xc1, 0xe5, 0x62, 0xbb, 0xf2, 0x8c, 0xdc, 0x16, 0x2d, 0x11, 0x39, 0xda, 0xaf,
    0x11, 0xc0, 0x73, 0xa6, 0x9c, 0x19, 0x24, 0x7f, 0xb2, 0x60, 0xc1, 0x72, 0x71, 0x6c, 0x40, 0x47,
    0x60, 0x82, 0xc0, 0x90, 0x1d, 0x86, 0x22, 0x10, 0x8b, 0xb2, 0x16, 0xd2, 0xe7, 0xff, 0x92, 0x59,
    0x59, 0x73, 0xb0, 0x25, 0x89, 0x3d, 0xf1, 0xba, 0x71, 0x69, 0x19, 0xf8, 0x70, 0x2f, 0xfc, 0xb9,
];
// Trusted key, the third account (created after setup) and setup()'s contract.
global SIG_OTHER: [u8; 64] = [
    0x0e, 0xdb, 0x92, 0xbd, 0xe0, 0xcb, 0x09, 0x2e, 0xa4, 0x01, 0xcf, 0x57, 0xef, 0x80, 0x33, 0x54,
    0x9a, 0x48, 0xf7, 0x9d, 0x0e, 0xb7, 0xa0, 0x6f, 0x54, 0xdb, 0x17, 0x34, 0x75, 0xcd, 0xfa, 0xe9,
    0x12, 0x62, 0xe1, 0x6a, 0x4e, 0xe3, 0x32, 0x49, 0x0e, 0x3d, 0x0a, 0xb8, 0xf1, 0xf7, 0xcd, 0x13,
    0x50, 0x2a, 0xe2, 0xff, 0xdc, 0x70, 0xcc, 0xd9, 0xc0, 0xaa, 0xf3, 0xb9, 0x66, 0x5d, 0x44, 0x72,
];

// Derive `holder`'s credential commitment the way bind_credential does, from
// the holder's app-siloed nhk. The contract deliberately has no getter that
// returns cc next to an owner.
unconstrained fn holder_commitment(
    env: TestEnvironment,
    addr: AztecAddress,
    holder: AztecAddress,
) -> Field {
    env.private_context_at(addr, |context| {
        let nsk_app = context.request_nhk_app(get_public_keys(holder).npk_m_hash);
        zka_lib::derive_credential_commitment(zka_aztec_lib::derive_zka_cbk(nsk_app))
    })
}

// Return `signature` after checking that `key` signed the live issuance
// transcript of (`holder`, `addr`, CRED_DATA, CRED_ATTRS). `label` is
// "<global name> <key name>". A stale vector fails here, with its
// stale-issuer-vector line, instead of failing inside the contract.
unconstrained fn signed<let N: u32>(
    env: TestEnvironment,
    addr: AztecAddress,
    holder: AztecAddress,
    key: IssuerKey,
    label: str<N>,
    signature: [u8; 64],
) -> [u8; 64] {
    let cc = holder_commitment(env, addr, holder);
    let (chain, version) =
        env.private_context_at(addr, |context| (context.chain_id(), context.version()));
    let digest = issuance_digest(chain, version, addr, cc, CRED_DATA, CRED_ATTRS);
    if !verify_issuer_signature(key, signature, digest) {
        let a = addr.to_field();
        let d = CRED_DATA;
        let (a0, a1, a2, a3) = (CRED_ATTRS[0], CRED_ATTRS[1], CRED_ATTRS[2], CRED_ATTRS[3]);
        std::println(
            f"stale-issuer-vector {label} {chain} {version} {a} {cc} {d} {a0} {a1} {a2} {a3}",
        );
        assert(
            false,
            "stale TEST-ONLY issuer signature vector: pipe this output to aztec/scripts/issuer_test_signatures.py apply",
        );
    }
    signature
}

// Deploy a ZKACredential that pins ISSUER_KEY.
unconstrained fn deploy(env: &mut TestEnvironment, admin: AztecAddress) -> AztecAddress {
    let initializer_call = ZKACredential::interface().constructor(admin, ISSUER_KEY);
    env.deploy("ZKACredential").with_public_initializer(admin, initializer_call)
}

// Mask = 0b1010 -> attrs 0 (KYC) and 2 (source-of-funds).
global MASK_AC: Field = 0xa;
// Mask = 0b0101 -> attrs 1 (jurisdiction) and 3 (accreditation).
global MASK_BD: Field = 0x5;

global CTX_A: Field = 0xdeadbeef;
global CTX_B: Field = 0xfeedface;

// Arbitrary credential commitments for the revocation (Safeguard 3) tests.
global CC_X: Field = 0xc0ffee;
global CC_OTHER: Field = 0xbadf00d;

// Deploy a fresh ZKACredential with `admin` as admin and return
// (env, contract_addr, admin, holder). The holder binds an issuer-signed
// credential, so all disclosure functions can be exercised immediately.
unconstrained fn setup() -> (TestEnvironment, AztecAddress, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let admin = env.create_light_account();
    let holder = env.create_light_account();
    let contract_address = deploy(&mut env, admin);

    let signature = signed(
        env,
        contract_address,
        holder,
        ISSUER_KEY,
        "SIG_HOLDER trusted",
        SIG_HOLDER,
    );
    env.call_private(
        holder,
        ZKACredential::at(contract_address).bind_credential(CRED_DATA, CRED_ATTRS, signature),
    );

    (env, contract_address, admin, holder)
}

// -----------------------------------------------------------------------------
// SS5.2 MODEL (docs/adr/0001, Option A): the disclosed hash is the RAW,
// context-INDEPENDENT artifact; the same mask returns the SAME hash regardless
// of context. The session binding is carried separately (context is a
// constrained argument here; a separate note field in disclose_to), NOT folded
// into the hash. This is the property that makes the output byte-identical to
// the standalone circuit's public input [1] (cross-env equality).
// -----------------------------------------------------------------------------
#[test]
unconstrained fn prove_disclosure_raw_hash_is_context_independent() {
    let (env, addr, _admin, holder) = setup();

    let raw_a = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_AC, CTX_A));
    let raw_b = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_AC, CTX_B));

    assert(
        raw_a == raw_b,
        "ADR0001: same mask must return the SAME raw hash across contexts (binding is separate)",
    );
}

// MASK DEPENDENCE: the disclosed hash MUST depend on what is disclosed -- a
// different mask over the same credential yields a different hash. (This is the
// real disclosure-correctness property, distinct from context binding.)
#[test]
unconstrained fn prove_disclosure_different_mask_yields_different_output() {
    let (env, addr, _admin, holder) = setup();

    let raw_ac = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_AC, CTX_A));
    let raw_bd = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_BD, CTX_A));

    assert(raw_ac != raw_bd, "Different masks must produce different disclosed hashes");
}

// -----------------------------------------------------------------------------
// REJECT: a zero context must revert (replay protection at the boundary).
// -----------------------------------------------------------------------------
#[test(should_fail_with = "Context must be non-zero for replay protection")]
unconstrained fn prove_disclosure_zero_context_reverts() {
    let (env, addr, _admin, holder) = setup();

    let _ = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_AC, 0));
}

// -----------------------------------------------------------------------------
// DETERMINISM: same mask -> same raw output (regression guard; the disclosed
// hash is a pure function of (credential_data, attributes, mask)).
// -----------------------------------------------------------------------------
#[test]
unconstrained fn prove_disclosure_same_mask_is_deterministic() {
    let (env, addr, _admin, holder) = setup();

    let raw_a = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_AC, CTX_A));
    let raw_b = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_AC, CTX_A));

    assert(raw_a == raw_b, "Same mask must produce the same disclosed hash");
}

// -----------------------------------------------------------------------------
// The named-mask wrappers follow the same Option-A model: prove_kyc returns the
// raw KYC disclosure hash, context-independent (binding is via the argument).
// -----------------------------------------------------------------------------
#[test]
unconstrained fn prove_kyc_raw_hash_is_context_independent() {
    let (env, addr, _admin, holder) = setup();

    let kyc_a = env.call_private(holder, ZKACredential::at(addr).prove_kyc(CTX_A));
    let kyc_b = env.call_private(holder, ZKACredential::at(addr).prove_kyc(CTX_B));

    assert(kyc_a == kyc_b, "ADR0001: prove_kyc raw hash must be context-independent");
}

// A zero context is rejected by the named wrappers too (the assert lives in the
// shared _prove_disclosure helper, so every entry point inherits it).
#[test(should_fail_with = "Context must be non-zero for replay protection")]
unconstrained fn prove_kyc_zero_context_reverts() {
    let (env, addr, _admin, holder) = setup();

    let _ = env.call_private(holder, ZKACredential::at(addr).prove_kyc(0));
}

// -----------------------------------------------------------------------------
// AGGREGATE: aggregate_disclosures(mask_a, mask_b, ctx) == aggregate of the two
// RAW halves. The on-contract aggregation folds the two raw disclosed hashes via
// aggregate_disclosed_hashes, so a caller can reproduce the aggregate off-chain.
// -----------------------------------------------------------------------------
#[test]
unconstrained fn aggregate_disclosures_matches_combined_raw_halves() {
    let (env, addr, _admin, holder) = setup();

    let raw_a = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_AC, CTX_A));
    let raw_b = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_BD, CTX_A));
    let expected = zka_aztec_lib::aggregate_disclosed_hashes(raw_a, raw_b);

    let actual = env.call_private(
        holder,
        ZKACredential::at(addr).aggregate_disclosures(MASK_AC, MASK_BD, CTX_A),
    );

    assert(
        actual == expected,
        "aggregate_disclosures must equal aggregate(prove_disclosure(a,ctx), prove_disclosure(b,ctx))",
    );
}

// -----------------------------------------------------------------------------
// AGGREGATE (Option A): the aggregate of raw halves is context-INDEPENDENT --
// the same mask pair returns the same aggregate regardless of context (the
// session is bound by the context argument, not folded into the value).
// -----------------------------------------------------------------------------
#[test]
unconstrained fn aggregate_disclosures_raw_is_context_independent() {
    let (env, addr, _admin, holder) = setup();

    let agg_a = env.call_private(
        holder,
        ZKACredential::at(addr).aggregate_disclosures(MASK_AC, MASK_BD, CTX_A),
    );
    let agg_b = env.call_private(
        holder,
        ZKACredential::at(addr).aggregate_disclosures(MASK_AC, MASK_BD, CTX_B),
    );

    assert(agg_a == agg_b, "ADR0001: aggregate of raw halves must be context-independent");
}

// -----------------------------------------------------------------------------
// DISCLOSE_TO (Option A): a disclosure to a specific recipient delivers a
// CredNote carrying the raw disclosed hash + the session context (separate
// field). The recipient ends up with a credential note; the owner is unaffected.
// -----------------------------------------------------------------------------
#[test]
unconstrained fn disclose_to_delivers_note_to_recipient() {
    let (mut env, addr, _admin, holder) = setup();
    let recipient = env.create_light_account();

    // Precondition: recipient has no note yet.
    assert(
        !env.execute_utility(ZKACredential::at(addr).has_credential(recipient)),
        "recipient should start with no credential note",
    );

    env.call_private(holder, ZKACredential::at(addr).disclose_to(recipient, MASK_AC, CTX_A));

    // Recipient now holds the delivered disclosure note.
    assert(
        env.execute_utility(ZKACredential::at(addr).has_credential(recipient)),
        "recipient must receive the disclosure note",
    );
}

// disclose_to inherits the non-zero context guard (replay protection boundary).
#[test(should_fail_with = "Context must be non-zero for replay protection")]
unconstrained fn disclose_to_zero_context_reverts() {
    let (mut env, addr, _admin, holder) = setup();
    let recipient = env.create_light_account();

    env.call_private(holder, ZKACredential::at(addr).disclose_to(recipient, MASK_AC, 0));
}

// -----------------------------------------------------------------------------
// v0.6.0 SS1.6 Safeguard 3 + SS5.6 -- revocation is a public-accumulator write,
// never note destruction (Section 1.6 conformance review).
//
// Audit conclusion: `revoke` only emits the revocation nullifier for cc; there
// is NO code path from revoke (or any admin function) to a credential note's
// validity. Per
// SS5.6 the only consequence of revocation is counterparty refusal (a revoked
// credential fails verify_compliance / non-revocation checks) -- never note
// invalidation or freezing. These tests lock that in.
// -----------------------------------------------------------------------------

// Revoke flips ONLY the targeted accumulator bit; the holder's credential NOTE
// is untouched and unrelated commitments stay unrevoked.
#[test]
unconstrained fn revoke_is_accumulator_only_and_preserves_notes() {
    let (env, addr, admin, holder) = setup();

    // Preconditions: holder has a credential note; nothing is revoked yet.
    assert(
        env.execute_utility(ZKACredential::at(addr).has_credential(holder)),
        "holder should start with a credential note",
    );
    assert(
        !env.view_public(ZKACredential::at(addr).is_revoked(CC_X)),
        "CC_X should start unrevoked",
    );

    // Admin revokes CC_X.
    env.call_private(admin, ZKACredential::at(addr).revoke(CC_X));

    // The targeted accumulator bit is set...
    assert(env.view_public(ZKACredential::at(addr).is_revoked(CC_X)), "CC_X must be revoked");
    // ...but the holder's credential NOTE is untouched (Safeguard 3)...
    assert(
        env.execute_utility(ZKACredential::at(addr).has_credential(holder)),
        "Safeguard 3: revoke must NOT destroy the holder's credential note",
    );
    // ...and unrelated commitments remain unrevoked (revoke is targeted, not global).
    assert(
        !env.view_public(ZKACredential::at(addr).is_revoked(CC_OTHER)),
        "revoke must only affect the targeted commitment",
    );
}

// Revoke is admin-gated: a non-admin caller is rejected in the public admin
// check, so the only privileged function on the contract cannot be abused (and
// even if it could, it is confined to the accumulator -- see the test above).
#[test(should_fail_with = "Only admin can revoke credentials")]
unconstrained fn non_admin_revoke_reverts() {
    let (env, addr, _admin, holder) = setup();

    // `holder` is not the admin -> revoke must revert in _assert_admin.
    let _ = env.call_private(holder, ZKACredential::at(addr).revoke(CC_X));
}

// A repeat revoke is a no-op, not a duplicate-nullifier revert.
#[test]
unconstrained fn revoke_is_idempotent() {
    let (env, addr, admin, _holder) = setup();

    env.call_private(admin, ZKACredential::at(addr).revoke(CC_X));
    env.call_private(admin, ZKACredential::at(addr).revoke(CC_X));

    assert(env.view_public(ZKACredential::at(addr).is_revoked(CC_X)), "CC_X must stay revoked");
}

// revoke emits the separator-tagged inner nullifier, never the raw
// admin-chosen value, so the admin cannot reach another nullifier domain.
#[test]
unconstrained fn revoke_emits_tagged_nullifier_not_raw_commitment() {
    let (env, addr, admin, _holder) = setup();

    env.call_private(admin, ZKACredential::at(addr).revoke(CC_X));

    env.public_context_at(addr, |context| {
        assert(
            context.nullifier_exists_unsafe(zka_aztec_lib::revocation_nullifier(CC_X), addr),
            "revoke must emit revocation_nullifier(cc)",
        );
        assert(
            !context.nullifier_exists_unsafe(CC_X, addr),
            "revoke must not emit the raw commitment as a nullifier",
        );
    });
}

// A zero commitment is never a real holderCommitment; reject it.
#[test(should_fail_with = "Credential commitment must be non-zero")]
unconstrained fn revoke_zero_commitment_reverts() {
    let (env, addr, admin, _holder) = setup();

    env.call_private(admin, ZKACredential::at(addr).revoke(0));
}

// -----------------------------------------------------------------------------
// ZKA SS5.8 -- verify_compliance checks non-revocation in private and
// publishes only the owner address. The registry is a DelayedPublicMutable
// with a MAX_TX_LIFETIME delay, so a registration is visible after that delay.
// -----------------------------------------------------------------------------

// Mine an empty block one second past the registration delay.
unconstrained fn wait_for_delayed_changes(env: TestEnvironment) {
    env.advance_next_block_timestamp_by(crate::ZKACredential::COMPLIANCE_DELAY + 1);
    env.mine_block();
}

// Timestamp of change of `owner`'s scheduled compliance_set entry (0 if the
// entry was never scheduled).
unconstrained fn compliance_change_timestamp(
    env: TestEnvironment,
    addr: AztecAddress,
    owner: AztecAddress,
) -> u64 {
    env.public_context_at(addr, |context| {
        let slot = derive_storage_slot_in_map(
            ZKACredential::storage_layout().compliance_set.slot,
            owner.to_field(),
        );
        let entry: DelayedPublicMutable<bool, crate::ZKACredential::COMPLIANCE_DELAY, PublicContext> =
            StateVariable::new(context, slot);
        entry.get_scheduled_value().1
    })
}

#[test]
unconstrained fn verify_compliance_registers_after_delay() {
    let (env, addr, _admin, holder) = setup();

    env.call_private(holder, ZKACredential::at(addr).verify_compliance());
    assert(
        !env.view_public(ZKACredential::at(addr).is_compliant(holder)),
        "registration must not take effect before COMPLIANCE_DELAY",
    );

    wait_for_delayed_changes(env);
    assert(
        env.view_public(ZKACredential::at(addr).is_compliant(holder)),
        "registration must take effect after COMPLIANCE_DELAY",
    );
    // The private gate agrees with the public view.
    env.view_private(holder, ZKACredential::at(addr).assert_compliant(holder));
}

// The private non-revocation check rejects a revoked holder: once the
// revocation nullifier of the holder's own commitment is in the tree, the
// contract reverts before any public call is enqueued.
#[test(should_fail_with = "Credential has been revoked")]
unconstrained fn revoked_credential_cannot_register() {
    let (env, addr, admin, holder) = setup();

    let cc = holder_commitment(env, addr, holder);
    env.call_private(admin, ZKACredential::at(addr).revoke(cc));

    env.call_private(holder, ZKACredential::at(addr).verify_compliance());
}

// Safeguard 3 with the holder's REAL commitment: the revocation nullifier sits
// in the same silo as the CredNote nullifiers, yet revoking cc leaves the
// holder's credential note intact and usable for disclosure.
#[test]
unconstrained fn revoking_real_commitment_preserves_credential_note() {
    let (env, addr, admin, holder) = setup();

    let cc = holder_commitment(env, addr, holder);
    env.call_private(admin, ZKACredential::at(addr).revoke(cc));

    assert(env.view_public(ZKACredential::at(addr).is_revoked(cc)), "cc must be revoked");
    assert(
        env.execute_utility(ZKACredential::at(addr).has_credential(holder)),
        "Safeguard 3: revoking cc must NOT destroy the holder's credential note",
    );
    let _ = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_AC, CTX_A));
}

// Re-registration schedules nothing: the entry's timestamp of change stays put,
// so no pending change can shorten a gated transfer's expiration.
#[test]
unconstrained fn re_registration_does_not_reschedule() {
    let (env, addr, _admin, holder) = setup();

    env.call_private(holder, ZKACredential::at(addr).verify_compliance());
    let first = compliance_change_timestamp(env, addr, holder);
    assert(first != 0, "first registration must schedule a change");

    wait_for_delayed_changes(env);
    env.call_private(holder, ZKACredential::at(addr).verify_compliance());
    assert(
        compliance_change_timestamp(env, addr, holder) == first,
        "re-registration must not reschedule the entry",
    );
}

// Revocation is targeted: revoking an unrelated commitment does not block the
// holder's registration.
#[test]
unconstrained fn unrelated_revocation_does_not_block_registration() {
    let (env, addr, admin, holder) = setup();

    env.call_private(admin, ZKACredential::at(addr).revoke(CC_OTHER));
    env.call_private(holder, ZKACredential::at(addr).verify_compliance());

    wait_for_delayed_changes(env);
    assert(
        env.view_public(ZKACredential::at(addr).is_compliant(holder)),
        "an unrelated revocation must not block registration",
    );
}

// The private gate rejects an address that never registered.
#[test(should_fail_with = "Recipient is not compliant")]
unconstrained fn assert_compliant_rejects_unregistered() {
    let (env, addr, admin, _holder) = setup();

    env.view_private(admin, ZKACredential::at(addr).assert_compliant(admin));
}

// -----------------------------------------------------------------------------
// Issuer authentication. bind_credential stores a credential only with the
// pinned issuer's signature over (chain, version, this contract, the caller's
// own holderCommitment, credential_data, attributes). A holder cannot assert
// its own attributes, and no other note counts as a credential, so a
// compliance registration is evidence that the pinned issuer issued one.
// -----------------------------------------------------------------------------

// The pinned key is the issuer trust policy; deploying without one fails.
#[test(should_fail_with = "Issuer key must be set")]
unconstrained fn constructor_rejects_unset_issuer_key() {
    let mut env = TestEnvironment::new();
    let admin = env.create_light_account();
    let unset = IssuerKey { x: [0; 32], y: [0; 32] };
    let initializer_call = ZKACredential::interface().constructor(admin, unset);
    let _ = env.deploy("ZKACredential").with_public_initializer(admin, initializer_call);
}

// A self-asserted credential (no issuer signature) is refused.
#[test(should_fail_with = "Credential is not signed by the pinned issuer")]
unconstrained fn self_asserted_credential_is_refused() {
    let (mut env, addr, _admin, _holder) = setup();
    let other = env.create_light_account();

    env.call_private(other, ZKACredential::at(addr).bind_credential(CRED_DATA, CRED_ATTRS, [0; 64]));
}

// A valid signature by a key other than the pinned one is refused.
#[test(should_fail_with = "Credential is not signed by the pinned issuer")]
unconstrained fn untrusted_issuer_signature_is_refused() {
    let (env, addr, _admin, holder) = setup();
    let signature = signed(
        env,
        addr,
        holder,
        UNTRUSTED_ISSUER_KEY,
        "SIG_HOLDER_UNTRUSTED untrusted",
        SIG_HOLDER_UNTRUSTED,
    );

    env.call_private(
        holder,
        ZKACredential::at(addr).bind_credential(CRED_DATA, CRED_ATTRS, signature),
    );
}

// The signature binds the attributes: the holder cannot raise one.
#[test(should_fail_with = "Credential is not signed by the pinned issuer")]
unconstrained fn altered_attributes_are_refused() {
    let (env, addr, _admin, holder) = setup();
    let signature = signed(
        env,
        addr,
        holder,
        ISSUER_KEY,
        "SIG_HOLDER trusted",
        SIG_HOLDER,
    );

    env.call_private(
        holder,
        ZKACredential::at(addr).bind_credential(CRED_DATA, [99, 22, 33, 44], signature),
    );
}

// The signature binds credential_data.
#[test(should_fail_with = "Credential is not signed by the pinned issuer")]
unconstrained fn altered_credential_data_is_refused() {
    let (env, addr, _admin, holder) = setup();
    let signature = signed(
        env,
        addr,
        holder,
        ISSUER_KEY,
        "SIG_HOLDER trusted",
        SIG_HOLDER,
    );

    env.call_private(holder, ZKACredential::at(addr).bind_credential(0x9999, CRED_ATTRS, signature));
}

// The signature binds the holder: another account cannot reuse it, because the
// contract derives the commitment from the caller's own key.
#[test(should_fail_with = "Credential is not signed by the pinned issuer")]
unconstrained fn signature_for_another_holder_is_refused() {
    let (mut env, addr, _admin, holder) = setup();
    let other = env.create_light_account();
    let signature = signed(
        env,
        addr,
        holder,
        ISSUER_KEY,
        "SIG_HOLDER trusted",
        SIG_HOLDER,
    );

    env.call_private(
        other,
        ZKACredential::at(addr).bind_credential(CRED_DATA, CRED_ATTRS, signature),
    );
}

// The signature binds the contract instance: a second deployment that pins the
// same issuer refuses a signature made for the first.
#[test(should_fail_with = "Credential is not signed by the pinned issuer")]
unconstrained fn signature_for_another_contract_is_refused() {
    let (mut env, addr, admin, holder) = setup();
    let signature = signed(
        env,
        addr,
        holder,
        ISSUER_KEY,
        "SIG_HOLDER trusted",
        SIG_HOLDER,
    );
    let addr2 = deploy(&mut env, admin);

    env.call_private(
        holder,
        ZKACredential::at(addr2).bind_credential(CRED_DATA, CRED_ATTRS, signature),
    );
}

// The requirement's negative path end to end: an account whose only attempt was
// a self-asserted bind holds no credential, so it cannot register compliant.
#[test(should_fail_with = "No credential found for caller")]
unconstrained fn account_without_issued_credential_cannot_register() {
    let (mut env, addr, _admin, _holder) = setup();
    let other = env.create_light_account();

    assert(
        !env.execute_utility(ZKACredential::at(addr).has_credential(other)),
        "an unissued account holds no credential note",
    );
    env.call_private(other, ZKACredential::at(addr).verify_compliance());
}

// A disclosure note is not a credential: the recipient of disclose_to holds a
// note, but it carries the discloser's commitment and a non-zero context, so it
// cannot register the recipient as compliant.
#[test(should_fail_with = "No credential found for caller")]
unconstrained fn disclosure_note_is_not_a_credential() {
    let (mut env, addr, _admin, holder) = setup();
    let other = env.create_light_account();

    env.call_private(holder, ZKACredential::at(addr).disclose_to(other, MASK_AC, CTX_A));
    assert(
        env.execute_utility(ZKACredential::at(addr).has_credential(other)),
        "the recipient holds the disclosure note",
    );
    env.call_private(other, ZKACredential::at(addr).verify_compliance());
}

// A disclosure note sent to a holder before it binds cannot shadow the holder's
// own issued credential: the constrained note select skips it.
#[test]
unconstrained fn foreign_disclosure_note_does_not_shadow_credential() {
    let (mut env, addr, _admin, holder) = setup();
    let other = env.create_light_account();

    env.call_private(holder, ZKACredential::at(addr).disclose_to(other, MASK_AC, CTX_A));
    let signature = signed(env, addr, other, ISSUER_KEY, "SIG_OTHER trusted", SIG_OTHER);
    env.call_private(
        other,
        ZKACredential::at(addr).bind_credential(CRED_DATA, CRED_ATTRS, signature),
    );
    env.call_private(other, ZKACredential::at(addr).verify_compliance());

    wait_for_delayed_changes(env);
    assert(
        env.view_public(ZKACredential::at(addr).is_compliant(other)),
        "the holder's own issued credential must register",
    );
}

// A holder's disclosure to itself carries its own commitment but a non-zero
// context; disclosures keep using the issued originator note.
#[test]
unconstrained fn self_disclosure_note_does_not_replace_credential() {
    let (env, addr, _admin, holder) = setup();

    let before = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_BD, CTX_A));
    env.call_private(holder, ZKACredential::at(addr).disclose_to(holder, MASK_AC, CTX_A));
    let after = env.call_private(holder, ZKACredential::at(addr).prove_disclosure(MASK_BD, CTX_B));

    assert(before == after, "disclosures must use the issued credential, not a disclosure note");
    assert(
        before
            == zka_aztec_lib::compute_disclosed_hash(
                CRED_DATA,
                CRED_ATTRS,
                [false, true, false, true],
            ),
        "the disclosure must be over the issuer-signed values",
    );
}
