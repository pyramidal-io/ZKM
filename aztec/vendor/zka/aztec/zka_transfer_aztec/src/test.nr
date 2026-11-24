// =============================================================================
// ZKATransfer TXE tests
//
// Coverage for the value-conservation invariant plus authenticated deposit/transfer behavior,
// exercised through the v5 Test eXecution Environment (TXE).
// =============================================================================

use crate::compliance_config::ComplianceConfig;
use crate::ZKATransfer;
use aztec::{
    context::PublicContext,
    keys::getters::get_public_keys,
    protocol::{address::{AztecAddress, EthAddress}, constants::MAX_TX_LIFETIME, traits::ToField},
    state_vars::{DelayedPublicMutable, StateVariable},
    test::helpers::{authwit::add_private_authwit_from_call, test_environment::TestEnvironment},
};
use zka_authwit_test_proxy::AuthwitTestProxy;
use zka_aztec_lib::{issuance_digest, IssuerKey, verify_issuer_signature};
use zka_credential_aztec::ZKACredential;

global ASSET_X: Field = 0x1111;
global ASSET_Y: Field = 0x2222;

// Test L1 portal address (the immutable withdrawal settlement portal, docs/adr/0002).
global TEST_PORTAL: EthAddress = EthAddress::from_field(0xbeefbeef);

// Credential payload for the compliance tests. The credential commitment is
// derived inside bind_credential from the caller's OWN app-siloed key, and the
// pinned issuer must sign it together with these values.
global CRED_DATA: Field = 0x1234;
global CRED_ATTRS: [Field; 4] = [1, 2, 3, 4];

// TEST-ONLY issuer key and signatures from aztec/scripts/issuer_test_signatures.py
// (see zka_credential_aztec/src/test.nr). Each signature is precomputed for its
// scenario's deterministic TXE credential contract and recipient; `bind_issued`
// prints a stale-issuer-vector line if one goes stale (see the credential tests).
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

// The first credential contract and the second light account. Both
// setup_compliance() and compliance_config_changes_are_delayed_and_compose
// deploy and create them in that position, so their transcripts are equal.
global SIG_RECIPIENT: [u8; 64] = [
    0xae, 0xb1, 0x29, 0x35, 0x6d, 0x8a, 0x39, 0x54, 0xe2, 0xd4, 0x5d, 0x36, 0xd6, 0xfe, 0x1c, 0xef,
    0x2a, 0x8f, 0x9b, 0x17, 0xa6, 0xa8, 0xf6, 0x93, 0xa1, 0x94, 0xd0, 0xc8, 0x1a, 0x7e, 0x03, 0x61,
    0x60, 0x3e, 0xfb, 0xf9, 0x9e, 0x71, 0x6f, 0xb4, 0x90, 0xbc, 0xca, 0x90, 0x3b, 0x39, 0xba, 0x12,
    0xfc, 0x30, 0x8f, 0x8b, 0x84, 0xd5, 0x6b, 0x95, 0x57, 0xf0, 0xd6, 0x61, 0xf7, 0x9f, 0xa3, 0x93,
];
// Aztec v5 computeSecretHash(Fr(0x123456)) is
// 0x1e3cf2b3d167833b6e447285a470612b27e13f01739b5325d9821594f54cda04.
// TestEnvironment.send_l1_to_l2_message applies that production derivation.
global CLAIM_SECRET: Field = 0x123456;

// Deploy a fresh ZKATransfer with `owner` as admin, returning (env, addr, owner, recipient).
unconstrained fn setup() -> (TestEnvironment, AztecAddress, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    let recipient = env.create_light_account();

    let initializer_call = ZKATransfer::interface().constructor(owner, TEST_PORTAL, ASSET_X);
    let contract_address =
        env.deploy("ZKATransfer").with_public_initializer(owner, initializer_call);

    (env, contract_address, owner, recipient)
}

/// Seed the TXE's real L1->L2 message tree with the message the portal would
/// send, returning the protocol leaf index consumed by `claim_private`.
unconstrained fn seed_deposit_message(
    env: TestEnvironment,
    transfer_addr: AztecAddress,
    beneficiary: AztecAddress,
    amount: u128,
    secret: Field,
) -> Field {
    let content = crate::deposit::deposit_content_hash(beneficiary.to_field(), ASSET_X, amount);
    env.send_l1_to_l2_message(content, secret, TEST_PORTAL, transfer_addr)
}

unconstrained fn claim_note(
    env: TestEnvironment,
    transfer_addr: AztecAddress,
    caller: AztecAddress,
    beneficiary: AztecAddress,
    amount: u128,
    secret: Field,
) -> Field {
    let leaf_index = seed_deposit_message(env, transfer_addr, beneficiary, amount, secret);
    env.call_private(
        caller,
        ZKATransfer::at(transfer_addr).claim_private(beneficiary, amount, secret, leaf_index),
    );
    leaf_index
}

#[test]
fn deposit_content_hash_matches_l1_golden() {
    let golden: Field = 0x0087ee5a621afb4fde01701656cff070640af03e3b4bc551975c6e3168dcb6bb;
    assert(
        crate::deposit::deposit_content_hash(0xbeef, ASSET_X, 1000) == golden,
        "L2 deposit content must equal ZKAAztecPortal.depositContentHash",
    );
}

// -----------------------------------------------------------------------------
// Authenticated L1->L2 deposit claims (docs/adr/0005).
// -----------------------------------------------------------------------------

// Match the pinned TXE's message-lookup rejection, not a generic oracle error:
// an unavailable oracle or broken setup must not satisfy a negative claim test.
// These are TXE simulation checks, not proof-verification evidence.

#[test]
unconstrained fn claim_private_consumes_message_and_mints_bound_note() {
    let (env, addr, owner, recipient) = setup();

    let _ = claim_note(env, addr, owner, recipient, 100, CLAIM_SECRET);

    assert(balance_of(env, addr, recipient, ASSET_X) == 100, "beneficiary receives deposit");
    assert(balance_of(env, addr, owner, ASSET_X) == 0, "caller receives nothing");
}

// Possession of the committed secret is required. A different preimage cannot
// produce a membership witness for the seeded Inbox message.
#[test(should_fail_with = "No L1 to L2 message found for message hash")]
unconstrained fn claim_private_rejects_wrong_secret() {
    let (env, addr, owner, recipient) = setup();
    let leaf_index = seed_deposit_message(env, addr, recipient, 100, CLAIM_SECRET);

    env.call_private(
        owner,
        ZKATransfer::at(addr).claim_private(recipient, 100, CLAIM_SECRET + 1, leaf_index),
    );
}

// The message content binds the amount; changing it cannot consume the seeded
// message and therefore cannot mint an over- or under-valued note.
#[test(should_fail_with = "No L1 to L2 message found for message hash")]
unconstrained fn claim_private_rejects_wrong_amount() {
    let (env, addr, owner, recipient) = setup();
    let leaf_index = seed_deposit_message(env, addr, recipient, 100, CLAIM_SECRET);

    env.call_private(
        owner,
        ZKATransfer::at(addr).claim_private(recipient, 101, CLAIM_SECRET, leaf_index),
    );
}

// The message content binds the beneficiary. Replacing the recipient selects a
// different message and cannot redirect the escrowed value.
#[test(should_fail_with = "No L1 to L2 message found for message hash")]
unconstrained fn claim_private_rejects_redirected_beneficiary() {
    let (env, addr, owner, recipient) = setup();
    let leaf_index = seed_deposit_message(env, addr, recipient, 100, CLAIM_SECRET);

    env.call_private(
        owner,
        ZKATransfer::at(addr).claim_private(owner, 100, CLAIM_SECRET, leaf_index),
    );
}

// The contract's immutable asset participates in the content hash. A message
// produced for another asset cannot mint this contract's ZKA note.
#[test(should_fail_with = "No L1 to L2 message found for message hash")]
unconstrained fn claim_private_rejects_message_for_other_asset() {
    let (env, addr, owner, recipient) = setup();
    let wrong_content = crate::deposit::deposit_content_hash(recipient.to_field(), ASSET_Y, 100);
    let leaf_index = env.send_l1_to_l2_message(wrong_content, CLAIM_SECRET, TEST_PORTAL, addr);

    env.call_private(
        owner,
        ZKATransfer::at(addr).claim_private(recipient, 100, CLAIM_SECRET, leaf_index),
    );
}

// The Inbox envelope binds the L1 sender. A correctly formed message from any
// portal other than the immutable deployment portal cannot be consumed.
#[test(should_fail_with = "No L1 to L2 message found for message hash")]
unconstrained fn claim_private_rejects_message_from_other_portal() {
    let (env, addr, owner, recipient) = setup();
    let content = crate::deposit::deposit_content_hash(recipient.to_field(), ASSET_X, 100);
    let wrong_portal = EthAddress::from_field(0xdeadbeef);
    let leaf_index = env.send_l1_to_l2_message(content, CLAIM_SECRET, wrong_portal, addr);

    env.call_private(
        owner,
        ZKATransfer::at(addr).claim_private(recipient, 100, CLAIM_SECRET, leaf_index),
    );
}

// The Aztec protocol emits the L1->L2 message nullifier on consumption. A
// second claim of the same leaf/secret must fail. The pinned TXE rejects it
// during message lookup once the first claim has emitted its nullifier.
#[test(should_fail_with = "No non-nullified L1 to L2 message found for message hash")]
unconstrained fn claim_private_consumes_message_once_only() {
    let (env, addr, owner, recipient) = setup();
    let leaf_index = claim_note(env, addr, owner, recipient, 100, CLAIM_SECRET);

    env.call_private(
        owner,
        ZKATransfer::at(addr).claim_private(recipient, 100, CLAIM_SECRET, leaf_index),
    );
}

// Even if a third party obtains enough claim data to submit first, the content
// fixes the note owner. Front-running can only deliver the intended note sooner;
// it cannot capture or redirect value.
#[test]
unconstrained fn claim_private_front_runner_cannot_capture_note() {
    let (env, addr, beneficiary, front_runner) = setup();
    let leaf_index = seed_deposit_message(env, addr, beneficiary, 100, CLAIM_SECRET);

    env.call_private(
        front_runner,
        ZKATransfer::at(addr).claim_private(beneficiary, 100, CLAIM_SECRET, leaf_index),
    );

    assert(balance_of(env, addr, beneficiary, ASSET_X) == 100, "note stays bound to beneficiary");
    assert(balance_of(env, addr, front_runner, ASSET_X) == 0, "front-runner captures nothing");
}

unconstrained fn balance_of(
    env: TestEnvironment,
    addr: AztecAddress,
    owner: AztecAddress,
    asset: Field,
) -> Field {
    env.execute_utility(ZKATransfer::at(addr).get_balance(owner, asset))
}

// -----------------------------------------------------------------------------
// Authwit-gated delegated transfers
//
// Private-note delegation must remain a nested call: the holder originates the
// transaction (so the TXE can discover and spend the holder's notes), while the
// proxy is `msg_sender` at ZKATransfer and is therefore the caller bound into
// the authwit inner hash. `add_private_authwit_from_call` asks the TXE to create
// a Schnorr signature with the holder account's key for the standard outer
// message hash. The holder's account contract then verifies that authwit during
// the nested call; this is not an authwit-check skip.
// -----------------------------------------------------------------------------

unconstrained fn setup_delegated_transfer() -> (TestEnvironment, AztecAddress, AztecAddress, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    // A full contract account is required because transfer_from verifies the
    // holder's private authwit through verify_private_authwit.
    let holder = env.create_contract_account();
    let recipient = env.create_light_account();

    let initializer_call = ZKATransfer::interface().constructor(holder, TEST_PORTAL, ASSET_X);
    let transfer_addr = env.deploy("ZKATransfer").with_public_initializer(holder, initializer_call);
    let proxy = env.deploy("@zka_authwit_test_proxy/AuthwitTestProxy").without_initializer();

    (env, transfer_addr, holder, recipient, proxy)
}

/// Execute `call` through the designated proxy. The holder stays the top-level
/// transaction sender so its note secrets are available, but ZKATransfer sees
/// `proxy` as `msg_sender` and must validate the holder's authwit.
unconstrained fn call_transfer_from_via_proxy(
    env: TestEnvironment,
    holder: AztecAddress,
    proxy: AztecAddress,
    call: aztec::context::PrivateCall<13, 5, ()>,
) {
    env.call_private(
        holder,
        AuthwitTestProxy::at(proxy).forward_private_5(
            call.target_contract,
            call.selector,
            call.args,
        ),
    );
}

#[test]
unconstrained fn transfer_from_debits_authorizing_holder_and_returns_change() {
    let (env, transfer_addr, holder, recipient, proxy) = setup_delegated_transfer();
    let _ = claim_note(env, transfer_addr, holder, holder, 100, CLAIM_SECRET);
    let _ = claim_note(env, transfer_addr, holder, holder, 50, CLAIM_SECRET);

    let call = ZKATransfer::at(transfer_addr).transfer_from(holder, recipient, ASSET_X, 40, 1);
    add_private_authwit_from_call(env, holder, proxy, call);
    call_transfer_from_via_proxy(env, holder, proxy, call);

    assert(
        balance_of(env, transfer_addr, holder, ASSET_X) == 110,
        "delegated transfer must debit the holder and return all change",
    );
    assert(
        balance_of(env, transfer_addr, recipient, ASSET_X) == 40,
        "delegated transfer must credit the requested recipient",
    );
}

// Reusing the exact authorization tuple emits the same authwit nullifier. The
// rollup must reject the second transaction even though the holder still has
// enough value to perform the transfer again.
#[test(should_fail_with = "failed with duplicate nullifiers")]
unconstrained fn transfer_from_rejects_replayed_authwit_nullifier() {
    let (env, transfer_addr, holder, recipient, proxy) = setup_delegated_transfer();
    let _ = claim_note(env, transfer_addr, holder, holder, 100, CLAIM_SECRET);

    let call = ZKATransfer::at(transfer_addr).transfer_from(holder, recipient, ASSET_X, 20, 7);
    add_private_authwit_from_call(env, holder, proxy, call);
    call_transfer_from_via_proxy(env, holder, proxy, call);
    call_transfer_from_via_proxy(env, holder, proxy, call);
}

#[test(should_fail_with = "Unknown auth witness for message hash")]
unconstrained fn transfer_from_rejects_delegation_without_holder_authwit() {
    let (env, transfer_addr, holder, recipient, proxy) = setup_delegated_transfer();
    let _ = claim_note(env, transfer_addr, holder, holder, 100, CLAIM_SECRET);

    let call = ZKATransfer::at(transfer_addr).transfer_from(holder, recipient, ASSET_X, 20, 6);
    call_transfer_from_via_proxy(env, holder, proxy, call);
}

#[test]
unconstrained fn transfer_from_accepts_distinct_authorized_nonces() {
    let (env, transfer_addr, holder, recipient, proxy) = setup_delegated_transfer();
    let _ = claim_note(env, transfer_addr, holder, holder, 100, CLAIM_SECRET);

    let first = ZKATransfer::at(transfer_addr).transfer_from(holder, recipient, ASSET_X, 20, 7);
    let second = ZKATransfer::at(transfer_addr).transfer_from(holder, recipient, ASSET_X, 20, 8);
    add_private_authwit_from_call(env, holder, proxy, first);
    add_private_authwit_from_call(env, holder, proxy, second);

    call_transfer_from_via_proxy(env, holder, proxy, first);
    call_transfer_from_via_proxy(env, holder, proxy, second);

    assert(balance_of(env, transfer_addr, holder, ASSET_X) == 60, "holder keeps 60");
    assert(
        balance_of(env, transfer_addr, recipient, ASSET_X) == 40,
        "fresh nonces authorize otherwise-identical transfers",
    );
}

// The outer authwit hash includes the consumer contract address. An authwit for
// instance A therefore cannot authorize the same selector and arguments on B.
#[test(should_fail_with = "Unknown auth witness for message hash")]
unconstrained fn transfer_from_rejects_authwit_for_different_consumer_instance() {
    let (mut env, transfer_a, holder, recipient, proxy) = setup_delegated_transfer();
    let _ = claim_note(env, transfer_a, holder, holder, 100, CLAIM_SECRET);

    let initializer_call = ZKATransfer::interface().constructor(holder, TEST_PORTAL, ASSET_X);
    let transfer_b = env.deploy("ZKATransfer").with_public_initializer(holder, initializer_call);
    // Fund B as well, so the only failing condition below is that A's signed
    // outer hash commits to A as consumer while B requests a signature for B.
    let _ = claim_note(env, transfer_b, holder, holder, 100, CLAIM_SECRET);

    let call_a = ZKATransfer::at(transfer_a).transfer_from(holder, recipient, ASSET_X, 20, 9);
    let call_b = ZKATransfer::at(transfer_b).transfer_from(holder, recipient, ASSET_X, 20, 9);
    add_private_authwit_from_call(env, holder, proxy, call_a);
    call_transfer_from_via_proxy(env, holder, proxy, call_b);
}

#[test]
unconstrained fn transfer_from_self_call_accepts_zero_nonce_without_authwit() {
    let (env, transfer_addr, holder, recipient) = setup();
    let _ = claim_note(env, transfer_addr, holder, holder, 100, CLAIM_SECRET);

    env.call_private(
        holder,
        ZKATransfer::at(transfer_addr).transfer_from(holder, recipient, ASSET_X, 40, 0),
    );

    assert(balance_of(env, transfer_addr, holder, ASSET_X) == 60, "holder keeps change");
    assert(balance_of(env, transfer_addr, recipient, ASSET_X) == 40, "recipient receives value");
}

#[test(should_fail_with = "Assertion failed: Invalid authwit nonce. When 'from' and 'msg_sender' are the same, 'authwit_nonce' must be zero")]
unconstrained fn transfer_from_self_call_rejects_nonzero_nonce() {
    let (env, transfer_addr, holder, recipient) = setup();
    let _ = claim_note(env, transfer_addr, holder, holder, 100, CLAIM_SECRET);

    env.call_private(
        holder,
        ZKATransfer::at(transfer_addr).transfer_from(holder, recipient, ASSET_X, 40, 1),
    );
}

// -----------------------------------------------------------------------------
// Value conservation across multiple notes.
//
// Owner holds 3 notes of asset X: 100, 50, 30 (total 180). Transfer 40 of X to
// recipient. After the transfer:
//   owner    == 140  (180 - 40, with all popped notes' value conserved as change)
//   recipient ==  40
// -----------------------------------------------------------------------------
#[test]
unconstrained fn transfer_conserves_value_across_multiple_notes() {
    let (env, addr, owner, recipient) = setup();

    // Seed three authenticated L1 deposits for the owner.
    let _ = claim_note(env, addr, owner, owner, 100, CLAIM_SECRET);
    let _ = claim_note(env, addr, owner, owner, 50, CLAIM_SECRET);
    let _ = claim_note(env, addr, owner, owner, 30, CLAIM_SECRET);

    assert(balance_of(env, addr, owner, ASSET_X) == 180, "owner should start with 180");

    // Transfer 40 of X to the recipient.
    env.call_private(owner, ZKATransfer::at(addr).transfer(recipient, ASSET_X, 40));

    assert(
        balance_of(env, addr, owner, ASSET_X) == 140,
        "owner balance must conserve value: 180 - 40 = 140 (not 60)",
    );
    assert(balance_of(env, addr, recipient, ASSET_X) == 40, "recipient must receive exactly 40");
}

// A single note that exactly covers the amount leaves zero change.
#[test]
unconstrained fn transfer_exact_amount_leaves_no_change() {
    let (env, addr, owner, recipient) = setup();

    let _ = claim_note(env, addr, owner, owner, 40, CLAIM_SECRET);
    env.call_private(owner, ZKATransfer::at(addr).transfer(recipient, ASSET_X, 40));

    assert(balance_of(env, addr, owner, ASSET_X) == 0, "owner should have 0 left");
    assert(balance_of(env, addr, recipient, ASSET_X) == 40, "recipient should have 40");
}

// Spending more than the owner holds must revert.
#[test(should_fail_with = "insufficient balance")]
unconstrained fn transfer_more_than_balance_fails() {
    let (env, addr, owner, recipient) = setup();

    let _ = claim_note(env, addr, owner, owner, 100, CLAIM_SECRET);
    let _ = claim_note(env, addr, owner, owner, 50, CLAIM_SECRET);

    // 100 + 50 = 150 < 200 -> revert.
    env.call_private(owner, ZKATransfer::at(addr).transfer(recipient, ASSET_X, 200));
}

// Withdraw also conserves value across multiple notes.
#[test]
unconstrained fn withdraw_conserves_value_across_multiple_notes() {
    let (env, addr, owner, _recipient) = setup();

    let _ = claim_note(env, addr, owner, owner, 100, CLAIM_SECRET);
    let _ = claim_note(env, addr, owner, owner, 50, CLAIM_SECRET);
    let _ = claim_note(env, addr, owner, owner, 30, CLAIM_SECRET);

    // Withdraw 40; external_recipient is a non-zero L1 address placeholder.
    env.call_private(owner, ZKATransfer::at(addr).withdraw(40, ASSET_X, 0xabcd));

    assert(
        balance_of(env, addr, owner, ASSET_X) == 140,
        "withdraw must conserve change: 180 - 40 = 140",
    );
}

// A recipient that does not fit in a 20-byte L1 address must revert BEFORE any
// note is burned. Without the bound, `_spend` would burn the notes and the
// resulting L2->L1 message could never be consumed on L1 (`abi.encode(address)`
// zero-pads the top 12 bytes, so no address argument reproduces the content
// hash) -- the burned value would be permanently unrecoverable.
#[test(should_fail_with = "call to assert_max_bit_size")]
unconstrained fn withdraw_to_oversized_recipient_reverts() {
    let (env, addr, owner, _recipient) = setup();

    let _ = claim_note(env, addr, owner, owner, 100, CLAIM_SECRET);

    // 2^160: one bit too wide for an L1 address.
    env.call_private(
        owner,
        ZKATransfer::at(addr).withdraw(40, ASSET_X, 0x10000000000000000000000000000000000000000),
    );
}

// The notes must survive a rejected oversized-recipient withdrawal: the bound is
// asserted before `_spend`, so the sender's balance is untouched.
#[test]
unconstrained fn rejected_oversized_withdraw_burns_no_notes() {
    let (env, addr, owner, _recipient) = setup();

    let _ = claim_note(env, addr, owner, owner, 100, CLAIM_SECRET);

    // The largest VALID L1 address (2^160 - 1) must still be accepted, proving
    // the bound rejects only genuinely unrepresentable recipients.
    env.call_private(
        owner,
        ZKATransfer::at(addr).withdraw(40, ASSET_X, 0xffffffffffffffffffffffffffffffffffffffff),
    );

    assert(
        balance_of(env, addr, owner, ASSET_X) == 60,
        "max-address withdraw must still settle: 100 - 40 = 60",
    );
}

// -----------------------------------------------------------------------------
// Compliance gate
//
// The transfer contract holds NO local compliance registry; the configured
// ZKACredential contract is the single source of truth. A recipient can become
// compliant only through a credential proof. These tests exercise the
// authenticated flow end-to-end through the TXE.
//
// NOTE: these tests deploy TWO contracts (ZKATransfer + ZKACredential) and drive
// the private cross-contract gate (assert_compliant), so they require the Aztec
// sandbox/TXE oracle to EXECUTE (the hard-gated `txe-tests` CI job). They
// typecheck/compile under `nargo check --workspace` (the local gate).
//
// The compliance config and the compliance registry are DelayedPublicMutable
// with a MAX_TX_LIFETIME delay (ZKA SS5.8 private gate), so every scheduled
// change needs `wait_for_delayed_changes` before a private read sees it.
// -----------------------------------------------------------------------------

// Mine an empty block one second past the delay, so that every change
// scheduled in an earlier block is current for the next private read.
unconstrained fn wait_for_delayed_changes(env: TestEnvironment) {
    env.advance_next_block_timestamp_by(MAX_TX_LIFETIME + 1);
    env.mine_block();
}

// Bind the issuer-signed credential `signature` for `recipient`. The signature
// is first checked against the live issuance transcript, so a stale vector
// fails here with its stale-issuer-vector line.
unconstrained fn bind_issued(
    env: TestEnvironment,
    credential_addr: AztecAddress,
    recipient: AztecAddress,
    signature: [u8; 64],
) {
    let (chain, version, cc) = env.private_context_at(credential_addr, |context| {
        let nsk_app = context.request_nhk_app(get_public_keys(recipient).npk_m_hash);
        let cc = zka_lib::derive_credential_commitment(zka_aztec_lib::derive_zka_cbk(nsk_app));
        (context.chain_id(), context.version(), cc)
    });
    let digest = issuance_digest(chain, version, credential_addr, cc, CRED_DATA, CRED_ATTRS);
    if !verify_issuer_signature(ISSUER_KEY, signature, digest) {
        let a = credential_addr.to_field();
        let d = CRED_DATA;
        let (a0, a1, a2, a3) = (CRED_ATTRS[0], CRED_ATTRS[1], CRED_ATTRS[2], CRED_ATTRS[3]);
        std::println(
            f"stale-issuer-vector SIG_RECIPIENT trusted {chain} {version} {a} {cc} {d} {a0} {a1} {a2} {a3}",
        );
        assert(
            false,
            "stale TEST-ONLY issuer signature vector: pipe this output to aztec/scripts/issuer_test_signatures.py apply",
        );
    }
    env.call_private(
        recipient,
        ZKACredential::at(credential_addr).bind_credential(CRED_DATA, CRED_ATTRS, signature),
    );
}

// Deploy a ZKACredential that pins ISSUER_KEY, with `admin` as admin.
unconstrained fn deploy_credential(env: &mut TestEnvironment, admin: AztecAddress) -> AztecAddress {
    let cred_init = ZKACredential::interface().constructor(admin, ISSUER_KEY);
    env.deploy("@zka_credential_aztec/ZKACredential").with_public_initializer(admin, cred_init)
}

// Bind an issuer-signed credential for `recipient`, register it as compliant,
// and wait for the registration to take effect.
unconstrained fn register_compliant(
    env: TestEnvironment,
    credential_addr: AztecAddress,
    recipient: AztecAddress,
    signature: [u8; 64],
) {
    bind_issued(env, credential_addr, recipient, signature);
    env.call_private(recipient, ZKACredential::at(credential_addr).verify_compliance());
    wait_for_delayed_changes(env);
}

// Deploy a ZKATransfer + ZKACredential pair, wire the transfer contract to the
// credential contract, and enable compliance (effective on return). Returns
// (env, transfer_addr, credential_addr, admin, recipient).
unconstrained fn setup_compliance() -> (TestEnvironment, AztecAddress, AztecAddress, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let admin = env.create_light_account();
    let recipient = env.create_light_account();

    // Deploy the transfer contract (this crate) with `admin` as admin.
    let transfer_init = ZKATransfer::interface().constructor(admin, TEST_PORTAL, ASSET_X);
    let transfer_addr = env.deploy("ZKATransfer").with_public_initializer(admin, transfer_init);

    // Deploy the credential contract (dependency crate) with `admin` as admin.
    let credential_addr = deploy_credential(&mut env, admin);

    // Wire the transfer gate to the credential contract and turn on compliance.
    env.call_public(admin, ZKATransfer::at(transfer_addr).set_credential_contract(credential_addr));
    env.call_public(admin, ZKATransfer::at(transfer_addr).enable_compliance(true));
    wait_for_delayed_changes(env);

    (env, transfer_addr, credential_addr, admin, recipient)
}

// A credential-verified recipient passes the compliance gate: after the
// recipient binds a credential and calls verify_compliance() on the credential
// contract (scheduling itself into the credential's compliance_set), the
// transfer gate's private assert_compliant(recipient) call passes and the
// compliance-gated transfer succeeds.
#[test]
unconstrained fn compliant_recipient_passes_gate() {
    let (env, transfer_addr, credential_addr, admin, recipient) = setup_compliance();

    // Recipient self-registers compliance via an issuer-signed credential.
    register_compliant(env, credential_addr, recipient, SIG_RECIPIENT);

    // Cross-contract view should now report the recipient as compliant.
    let compliant =
        env.view_public(ZKATransfer::at(transfer_addr).is_recipient_compliant(recipient));
    assert(compliant, "recipient should be compliant after verify_compliance");

    // Fund the admin and perform a compliance-gated transfer to the recipient.
    let _ = claim_note(env, transfer_addr, admin, admin, 100, CLAIM_SECRET);
    env.call_private(
        admin,
        ZKATransfer::at(transfer_addr).transfer_with_compliance(recipient, ASSET_X, 40),
    );

    assert(
        balance_of(env, transfer_addr, recipient, ASSET_X) == 40,
        "compliant recipient must receive 40",
    );
    assert(
        balance_of(env, transfer_addr, admin, ASSET_X) == 60,
        "admin balance must be 60 after transfer",
    );
}

// A NON-verified recipient causes transfer_with_compliance to revert. There is
// no function anywhere to mark `recipient` compliant without a credential proof,
// so the private assert_compliant call fails with "Recipient is not compliant".
// This is the core security property.
#[test(should_fail_with = "Recipient is not compliant")]
unconstrained fn non_verified_recipient_reverts() {
    let (env, transfer_addr, _credential_addr, admin, recipient) = setup_compliance();

    // Recipient never proved a credential -> not in the credential compliance set.
    let _ = claim_note(env, transfer_addr, admin, admin, 100, CLAIM_SECRET);
    env.call_private(
        admin,
        ZKATransfer::at(transfer_addr).transfer_with_compliance(recipient, ASSET_X, 40),
    );
}

// Misconfiguration guard: if compliance is enabled but no credential contract is
// configured (zero address), the gate reverts rather than silently passing.
#[test(should_fail_with = "Compliance enabled but credential contract is unset")]
unconstrained fn enabled_without_credential_contract_reverts() {
    let mut env = TestEnvironment::new();
    let admin = env.create_light_account();
    let recipient = env.create_light_account();

    let transfer_init = ZKATransfer::interface().constructor(admin, TEST_PORTAL, ASSET_X);
    let transfer_addr = env.deploy("ZKATransfer").with_public_initializer(admin, transfer_init);

    // Enable compliance WITHOUT ever setting a credential contract.
    env.call_public(admin, ZKATransfer::at(transfer_addr).enable_compliance(true));
    wait_for_delayed_changes(env);

    let _ = claim_note(env, transfer_addr, admin, admin, 100, CLAIM_SECRET);
    env.call_private(
        admin,
        ZKATransfer::at(transfer_addr).transfer_with_compliance(recipient, ASSET_X, 40),
    );
}

// A registration is not visible to the gate until COMPLIANCE_DELAY has
// passed: the gate reads the CURRENT value of a DelayedPublicMutable.
#[test(should_fail_with = "Recipient is not compliant")]
unconstrained fn registration_is_not_effective_before_delay() {
    let (env, transfer_addr, credential_addr, admin, recipient) = setup_compliance();

    bind_issued(env, credential_addr, recipient, SIG_RECIPIENT);
    env.call_private(recipient, ZKACredential::at(credential_addr).verify_compliance());

    // No wait: the scheduled registration is still pending.
    let _ = claim_note(env, transfer_addr, admin, admin, 100, CLAIM_SECRET);
    env.call_private(
        admin,
        ZKATransfer::at(transfer_addr).transfer_with_compliance(recipient, ASSET_X, 40),
    );
}

// Admin config changes take effect only after COMPLIANCE_CONFIG_DELAY, and the
// two setters compose: enable_compliance keeps the scheduled credential
// contract, and a later set_credential_contract keeps the scheduled flag.
#[test]
unconstrained fn compliance_config_changes_are_delayed_and_compose() {
    let mut env = TestEnvironment::new();
    let admin = env.create_light_account();

    let transfer_init = ZKATransfer::interface().constructor(admin, TEST_PORTAL, ASSET_X);
    let transfer_addr = env.deploy("ZKATransfer").with_public_initializer(admin, transfer_init);
    let credential_addr = deploy_credential(&mut env, admin);

    env.call_public(admin, ZKATransfer::at(transfer_addr).set_credential_contract(credential_addr));
    env.call_public(admin, ZKATransfer::at(transfer_addr).enable_compliance(true));
    assert(
        !env.view_public(ZKATransfer::at(transfer_addr).is_compliance_enabled()),
        "enable_compliance must not take effect before the delay",
    );

    wait_for_delayed_changes(env);
    assert(
        env.view_public(ZKATransfer::at(transfer_addr).is_compliance_enabled()),
        "enable_compliance must take effect after the delay",
    );

    // A recipient registered with the configured contract is reported compliant,
    // which proves enable_compliance did not clear the credential contract.
    let recipient = env.create_light_account();
    register_compliant(env, credential_addr, recipient, SIG_RECIPIENT);
    assert(
        env.view_public(ZKATransfer::at(transfer_addr).is_recipient_compliant(recipient)),
        "the scheduled credential contract must survive enable_compliance",
    );

    // The other order: swap to a second credential contract while enabled.
    // While the swap is pending the gate still answers from the old contract;
    // after the delay the flag is still set and the new contract answers.
    let credential2_addr = deploy_credential(&mut env, admin);
    env.call_public(admin, ZKATransfer::at(transfer_addr).set_credential_contract(credential2_addr));
    assert(
        env.view_public(ZKATransfer::at(transfer_addr).is_recipient_compliant(recipient)),
        "a pending swap must still gate on the old credential contract",
    );

    wait_for_delayed_changes(env);
    assert(
        env.view_public(ZKATransfer::at(transfer_addr).is_compliance_enabled()),
        "set_credential_contract must keep the scheduled flag",
    );
    assert(
        !env.view_public(ZKATransfer::at(transfer_addr).is_recipient_compliant(recipient)),
        "after the swap the new credential contract must answer",
    );
}

// Timestamp of change of the scheduled compliance config (0 if never scheduled).
unconstrained fn config_change_timestamp(env: TestEnvironment, transfer_addr: AztecAddress) -> u64 {
    env.public_context_at(transfer_addr, |context| {
        let config: DelayedPublicMutable<ComplianceConfig, crate::ZKATransfer::COMPLIANCE_CONFIG_DELAY, PublicContext> = StateVariable::new(
            context,
            ZKATransfer::storage_layout().compliance_config.slot,
        );
        config.get_scheduled_value().1
    })
}

// A setter call that would not change the scheduled config schedules nothing,
// so a repeat call cannot reopen the pending window that marks gated transfers.
#[test]
unconstrained fn no_op_config_change_is_not_scheduled() {
    let (env, transfer_addr, credential_addr, admin, _recipient) = setup_compliance();

    let before = config_change_timestamp(env, transfer_addr);
    assert(before != 0, "setup must have scheduled the config");

    env.call_public(admin, ZKATransfer::at(transfer_addr).enable_compliance(true));
    env.call_public(admin, ZKATransfer::at(transfer_addr).set_credential_contract(credential_addr));
    assert(
        config_change_timestamp(env, transfer_addr) == before,
        "a no-op config change must not be scheduled",
    );
}

// A compliance-gated transfer still passes, without waiting, for a recipient
// who calls verify_compliance again. (That re-registration schedules nothing
// is asserted directly in zka_credential_aztec's re_registration_does_not_reschedule.)
#[test]
unconstrained fn re_registration_keeps_recipient_compliant() {
    let (env, transfer_addr, credential_addr, admin, recipient) = setup_compliance();

    register_compliant(env, credential_addr, recipient, SIG_RECIPIENT);
    env.call_private(recipient, ZKACredential::at(credential_addr).verify_compliance());

    // No wait: the entry was already true and no new change is pending.
    let _ = claim_note(env, transfer_addr, admin, admin, 100, CLAIM_SECRET);
    env.call_private(
        admin,
        ZKATransfer::at(transfer_addr).transfer_with_compliance(recipient, ASSET_X, 40),
    );
    assert(
        balance_of(env, transfer_addr, recipient, ASSET_X) == 40,
        "re-registered recipient must receive 40",
    );
}

// -----------------------------------------------------------------------------
// v0.6.0 SS1.6 Freedom Safeguards 3 & 5 -- regression guards
// (Section 1.6 conformance review)
//
// Audit conclusion: NONE of the admin/compliance functions affect ZKA note
// validity. They gate only the OPT-IN transfer_with_compliance interaction.
// Plain transfer and withdraw are never gated, so admin compliance toggles can
// never freeze custody (Safeguard 3) or block exit (Safeguard 5). The
// credential contract's revoke emits a revocation nullifier that yields only
// counterparty refusal, never note destruction (SS5.6). These tests lock those
// invariants in so a future change cannot silently regress them. They use
// `setup_compliance()` (compliance ENABLED, credential contract wired) and a
// holder who has NEVER proved a credential -- i.e. is NOT compliant.
// -----------------------------------------------------------------------------

// SAFEGUARD 5 (unconditional exit): a non-compliant holder can withdraw even
// while compliance is enabled. Exit MUST NOT be gated by any compliance check.
#[test]
unconstrained fn withdraw_is_unconditional_even_with_compliance_enabled() {
    let (env, transfer_addr, _credential_addr, _admin, holder) = setup_compliance();

    let _ = claim_note(env, transfer_addr, holder, holder, 100, CLAIM_SECRET);
    // holder is not compliant and compliance is enabled -> withdraw must STILL pass.
    env.call_private(holder, ZKATransfer::at(transfer_addr).withdraw(40, ASSET_X, 0xabcd));

    assert(
        balance_of(env, transfer_addr, holder, ASSET_X) == 60,
        "Safeguard 5: withdraw must be unconditional (100 - 40 = 60) under compliance",
    );
}

// SAFEGUARD 3 (no admin freeze of custody): plain transfer is never gated, so a
// holder can move value to a NON-compliant recipient even while compliance is
// enabled. Only transfer_with_compliance consults the gate.
#[test]
unconstrained fn plain_transfer_unaffected_by_compliance_mode() {
    let (env, transfer_addr, _credential_addr, admin, recipient) = setup_compliance();

    let _ = claim_note(env, transfer_addr, admin, admin, 100, CLAIM_SECRET);
    // recipient is NOT compliant, yet a PLAIN transfer (not the _with_compliance
    // variant) must succeed -- admin enabling compliance cannot freeze it.
    env.call_private(admin, ZKATransfer::at(transfer_addr).transfer(recipient, ASSET_X, 40));

    assert(balance_of(env, transfer_addr, admin, ASSET_X) == 60, "sender keeps 60");
    assert(
        balance_of(env, transfer_addr, recipient, ASSET_X) == 40,
        "Safeguard 3: plain transfer to a non-compliant recipient must succeed under compliance",
    );
}

// SAFEGUARDS 3 & 5 (custody is never impaired): a non-compliant holder can
// reclaim 100% of their value via withdraw while compliance is enabled. There
// is no admin/compliance state that can render funds inaccessible.
#[test]
unconstrained fn holder_can_fully_exit_under_compliance() {
    let (env, transfer_addr, _credential_addr, _admin, holder) = setup_compliance();

    let _ = claim_note(env, transfer_addr, holder, holder, 100, CLAIM_SECRET);
    let _ = claim_note(env, transfer_addr, holder, holder, 50, CLAIM_SECRET);
    // Reclaim the entire balance; compliance mode cannot block full exit.
    env.call_private(holder, ZKATransfer::at(transfer_addr).withdraw(150, ASSET_X, 0xabcd));

    assert(
        balance_of(env, transfer_addr, holder, ASSET_X) == 0,
        "Safeguards 3&5: a non-compliant holder must be able to fully exit (150 -> 0)",
    );
}
