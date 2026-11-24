// =============================================================================
// ZKMMandate TXE tests
//
// Coverage for the five non-SPEND §4.2 transition kinds + the SPEND leg,
// exercised through the V6 Test eXecution Environment (TXE): cap conservation,
// rebind rules, the per-mandate policy delegation gate, the §5 spend ceiling,
// and the (root_id, remaining_cap) consume selector.
// =============================================================================

use crate::{ZKM_SPEND_RECEIPT_DOMAIN, ZKMMandate::ZKMSpendReceiptV1};
use crate::ZKMMandate;
use aztec::{
    authwit::auth::compute_authwit_message_hash_from_call,
    event::{event_interface::{compute_private_event_commitment, EventInterface}, EventSelector},
    protocol::{
        address::{AztecAddress, EthAddress},
        hash::sha256_to_field,
        traits::{Serialize, ToField},
    },
    test::helpers::{authwit::add_private_authwit_from_call, test_environment::TestEnvironment},
};
use std::field::bn254::decompose;
use zka_transfer_aztec::ZKATransfer;
use zkm_lib::{compute_policy_hash_v2, StandardPolicyV2};

// Test-only access to the real pinned TXE discovery oracle. Its signature and
// bounds match aztec-nr v6.0.0 test/helpers/txe_oracles.nr; the helper there is
// pub(crate), so this wrapper exposes no contract or production oracle surface.
#[oracle(aztec_txe_getPrivateEvents)]
unconstrained fn receipt_private_events(
    selector: EventSelector,
    contract_address: AztecAddress,
    scope: AztecAddress,
) -> BoundedVec<BoundedVec<Field, 10>, 5> {}

global SETTLEMENT_CONTEXT: Field = 0x5e771e3c;
// Independently reconstructed native root KATs: issuance key 991, randomness
// 13 and 14. Principal authority is deliberately distinct from Aztec accounts.
global ISSUANCE_KEY: Field = 991;
global ISSUANCE_RANDOMNESS: Field = 13;
global ROOT_A: Field = 0x1c4157221a5e964701eefa2d15ecdb5d1df85210832e4d298dd26ae73d688d77;
global ROOT_B: Field = 0x287ccda4e98f468c4f009e63a03eac640129e405a447435120ea0f3e51a5c518;
global ASSET: Field = 7;
global ASSET_OTHER: Field = 8;
// zkm_lib::compute_zka_asset_commitment(ASSET), pinned by the cross-env KAT.
global ZKA_ASSET: Field = 0x18086bfe7fca938736950d593f909fad0896bffbeb9f8929c5082aa969e457ce;
global TEST_PORTAL: EthAddress = EthAddress::from_field(0xbeefbeef);
global CLAIM_SECRET: Field = 0x123456;
// Far-future expiry (u64-bounded). The §4.3-6 temporal-validity substitution
// (set_expiration_timestamp) is exercised implicitly by every call here: an
// expiry at/below the TXE block timestamp would make the tx unincludable.
global EXPIRY: Field = 100000000000;

// V2 policy fixture: per-spend ceiling 500, unrestricted recipients,
// delegation permitted down to depth 3.
global POLICY_MPS: Field = 500;
global POLICY_DEPTH_LIMIT: Field = 3;
global POLICY_BLINDING: Field = 0x77;

unconstrained fn v2_policy_hash(depth_limit: Field) -> Field {
    compute_policy_hash_v2(
        StandardPolicyV2 {
            version: 2,
            max_per_spend: 500,
            recipient_restricted: 0,
            recipient_set_root: 0,
            depth_limit: depth_limit as u8,
            policy_blinding: POLICY_BLINDING,
        },
    )
}

// Deploy a fresh real ZKATransfer and bind a ZKMMandate deployment to it.
unconstrained fn setup() -> (TestEnvironment, AztecAddress, AztecAddress, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    // The nested ZKA call verifies the holder's private authwit against its
    // account contract, so spend tests require a full contract account.
    let holder = env.create_contract_account();
    let delegate = env.create_light_account();

    let zka_initializer = ZKATransfer::interface().constructor(holder, TEST_PORTAL, ZKA_ASSET);
    let zka_addr = env.deploy("@zka_transfer_aztec/ZKATransfer").with_public_initializer(
        holder,
        zka_initializer,
    );
    let initializer_call = ZKMMandate::interface().constructor(SETTLEMENT_CONTEXT, zka_addr);
    let contract_address =
        env.deploy("ZKMMandate").with_public_initializer(holder, initializer_call);

    (env, contract_address, zka_addr, holder, delegate)
}

// Deploy two same-code ZKA instances and pin ZKM to the second. The first is a
// decoy used to prove that the authwit outer consumer (the ZKA target address)
// cannot be substituted independently of ZKM's PublicImmutable target.
unconstrained fn setup_with_decoy_zka() -> (TestEnvironment, AztecAddress, AztecAddress, AztecAddress, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let holder = env.create_contract_account();
    let recipient = env.create_light_account();

    let decoy_initializer = ZKATransfer::interface().constructor(holder, TEST_PORTAL, ZKA_ASSET);
    let decoy_zka = env.deploy("@zka_transfer_aztec/ZKATransfer").with_public_initializer(
        holder,
        decoy_initializer,
    );
    let pinned_initializer = ZKATransfer::interface().constructor(holder, TEST_PORTAL, ZKA_ASSET);
    let pinned_zka = env.deploy("@zka_transfer_aztec/ZKATransfer").with_public_initializer(
        holder,
        pinned_initializer,
    );
    let zkm_initializer = ZKMMandate::interface().constructor(SETTLEMENT_CONTEXT, pinned_zka);
    let zkm_addr = env.deploy("ZKMMandate").with_public_initializer(holder, zkm_initializer);

    (env, zkm_addr, decoy_zka, pinned_zka, holder, recipient)
}

fn canonical_be_bytes_32(x: Field) -> [u8; 32] {
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

fn deposit_content_hash(beneficiary: Field, asset: Field, amount: u128) -> Field {
    let selector: [u8; 4] = [0x42, 0x67, 0x6e, 0x57];
    let beneficiary_bytes = canonical_be_bytes_32(beneficiary);
    let asset_bytes = canonical_be_bytes_32(asset);
    let amount_bytes = canonical_be_bytes_32(amount as Field);
    let mut hash_bytes: [u8; 100] = [0; 100];
    for i in 0..4 {
        hash_bytes[i] = selector[i];
    }
    for i in 0..32 {
        hash_bytes[i + 4] = beneficiary_bytes[i];
        hash_bytes[i + 36] = asset_bytes[i];
        hash_bytes[i + 68] = amount_bytes[i];
    }
    sha256_to_field(hash_bytes)
}

unconstrained fn fund_holder(
    env: TestEnvironment,
    zka_addr: AztecAddress,
    holder: AztecAddress,
    amount: u128,
    secret: Field,
) {
    let content = deposit_content_hash(holder.to_field(), ZKA_ASSET, amount);
    let leaf = env.send_l1_to_l2_message(content, secret, TEST_PORTAL, zka_addr);
    env.call_private(holder, ZKATransfer::at(zka_addr).claim_private(holder, amount, secret, leaf));
}

unconstrained fn authorize_bound_spend(
    env: TestEnvironment,
    zkm_addr: AztecAddress,
    zka_addr: AztecAddress,
    holder: AztecAddress,
    recipient: AztecAddress,
    amount: Field,
    authwit_nonce: Field,
) {
    let zka_call = ZKATransfer::at(zka_addr).transfer_from(
        holder,
        recipient,
        ZKA_ASSET,
        amount,
        authwit_nonce,
    );
    add_private_authwit_from_call(env, holder, zkm_addr, zka_call);
}

unconstrained fn count_of(
    env: TestEnvironment,
    addr: AztecAddress,
    owner: AztecAddress,
    root_id: Field,
) -> Field {
    env.execute_utility(ZKMMandate::at(addr).get_mandate_count(owner, root_id))
}

unconstrained fn total_of(
    env: TestEnvironment,
    addr: AztecAddress,
    owner: AztecAddress,
    root_id: Field,
) -> Field {
    env.execute_utility(ZKMMandate::at(addr).get_total_cap(owner, root_id))
}

unconstrained fn zka_balance_of(
    env: TestEnvironment,
    zka_addr: AztecAddress,
    owner: AztecAddress,
) -> Field {
    env.execute_utility(ZKATransfer::at(zka_addr).get_balance(owner, ZKA_ASSET))
}

// Issue a 1000-cap ROOT_A mandate to `holder` under the standard v2 policy
// (delegation permitted to depth 3).
unconstrained fn issue_standard(env: TestEnvironment, addr: AztecAddress, holder: AztecAddress) {
    let ph = v2_policy_hash(POLICY_DEPTH_LIMIT);
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            ph,
        ),
    );
}

unconstrained fn issue_standard_for_asset(
    env: TestEnvironment,
    addr: AztecAddress,
    holder: AztecAddress,
    asset: Field,
) {
    let ph = v2_policy_hash(POLICY_DEPTH_LIMIT);
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            asset,
            1000,
            EXPIRY,
            ph,
        ),
    );
}

unconstrained fn spend_standard(
    env: TestEnvironment,
    addr: AztecAddress,
    holder: AztecAddress,
    recipient: AztecAddress,
    in_cap: Field,
    amount: Field,
    authwit_nonce: Field,
) {
    env.call_private(
        holder,
        ZKMMandate::at(addr).spend_authorize(
            ROOT_A,
            in_cap,
            recipient,
            amount,
            authwit_nonce,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );
}

// -----------------------------------------------------------------------------
// Issuance
// -----------------------------------------------------------------------------

#[test]
unconstrained fn issue_creates_a_depth_zero_mandate() {
    let (env, addr, _zka, holder, _delegate) = setup();
    issue_standard(env, addr, holder);

    assert(count_of(env, addr, holder, ROOT_A) == 1, "holder should hold one mandate");
    assert(total_of(env, addr, holder, ROOT_A) == 1000, "remaining cap should be 1000");
}

#[test(should_fail_with = "asset_id must be non-zero")]
unconstrained fn issue_rejects_zero_asset_sentinel() {
    let (env, addr, _zka, holder, _delegate) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            0,
            1000,
            EXPIRY,
            33,
        ),
    );
}

#[test(should_fail_with = "policy_hash must be non-zero")]
unconstrained fn issue_rejects_zero_policy_sentinel() {
    let (env, addr, _zka, holder, _delegate) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            0,
        ),
    );
}

#[test]
unconstrained fn issue_binds_a_distinct_recipient_controller() {
    let (env, addr, _zka, principal, recipient) = setup();
    env.call_private(
        principal,
        ZKMMandate::at(addr).issue(
            recipient,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            v2_policy_hash(POLICY_DEPTH_LIMIT),
        ),
    );
    assert(count_of(env, addr, principal, ROOT_A) == 0);
    assert(total_of(env, addr, recipient, ROOT_A) == 1000);
    // The recipient's actual privacy keys, not the issuance caller's account,
    // control the note. This is ownership, not a delegate possession proof.
    env.call_private(recipient, ZKMMandate::at(addr).retire(ROOT_A, 1000));
    assert(count_of(env, addr, recipient, ROOT_A) == 0);
}

#[test(should_fail_with = "Mandate note not found")]
unconstrained fn issue_does_not_give_the_principal_the_recipients_note() {
    let (env, addr, _zka, principal, recipient) = setup();
    env.call_private(
        principal,
        ZKMMandate::at(addr).issue(
            recipient,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            v2_policy_hash(POLICY_DEPTH_LIMIT),
        ),
    );
    env.call_private(principal, ZKMMandate::at(addr).retire(ROOT_A, 1000));
}

#[test]
unconstrained fn issue_accepts_a_fresh_ceremony_after_retirement() {
    let (env, addr, _zka, holder, _recipient) = setup();
    issue_standard(env, addr, holder);
    env.call_private(holder, ZKMMandate::at(addr).retire(ROOT_A, 1000));
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_B,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS + 1,
            SETTLEMENT_CONTEXT,
            ASSET,
            700,
            EXPIRY,
            v2_policy_hash(POLICY_DEPTH_LIMIT),
        ),
    );
    assert(count_of(env, addr, holder, ROOT_A) == 0);
    assert(total_of(env, addr, holder, ROOT_B) == 700);
}

#[test(should_fail_with = "root_id must match principal issuance authority")]
unconstrained fn issue_rejects_another_principals_root() {
    let (env, addr, _zka, holder, _recipient) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY + 1,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            33,
        ),
    );
}

#[test(should_fail_with = "root_id must match principal issuance authority")]
unconstrained fn issue_rejects_substituted_issuance_randomness() {
    let (env, addr, _zka, holder, _recipient) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS + 1,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            33,
        ),
    );
}

#[test(should_fail_with = "principal issuance key must be non-zero")]
unconstrained fn issue_rejects_zero_principal_authority() {
    let (env, addr, _zka, holder, _recipient) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            0,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            33,
        ),
    );
}

#[test(should_fail_with = "root_id must be non-zero")]
unconstrained fn issue_rejects_zero_root_sentinel() {
    let (env, addr, _zka, holder, _recipient) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            0,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            33,
        ),
    );
}

#[test(should_fail_with = "cap must be non-zero")]
unconstrained fn issue_retains_the_aztec_zero_cap_tightening() {
    let (env, addr, _zka, holder, _recipient) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            0,
            EXPIRY,
            33,
        ),
    );
}

#[test(should_fail_with = "expiry must be non-zero")]
unconstrained fn issue_rejects_zero_expiry() {
    let (env, addr, _zka, holder, _recipient) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            0,
            33,
        ),
    );
}

#[test(should_fail_with = "recipient must be non-zero")]
unconstrained fn issue_rejects_zero_recipient_controller() {
    let (env, addr, _zka, holder, _recipient) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            AztecAddress::zero(),
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            33,
        ),
    );
}

#[test(should_fail_with = "issuance context must match the deployment")]
unconstrained fn issue_rejects_substituted_context() {
    let (env, addr, _zka, holder, _recipient) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT + 1,
            ASSET,
            1000,
            EXPIRY,
            33,
        ),
    );
}

#[test(should_fail_with = "issuance context must match the deployment")]
unconstrained fn issue_rejects_the_original_context_on_another_deployment() {
    let (mut env, _addr, zka, holder, _recipient) = setup();
    let initializer = ZKMMandate::interface().constructor(SETTLEMENT_CONTEXT + 1, zka);
    let other = env.deploy("ZKMMandate").with_public_initializer(holder, initializer);
    env.call_private(
        holder,
        ZKMMandate::at(other).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            33,
        ),
    );
}

#[test(should_fail_with = "value exceeds u128 range")]
unconstrained fn issue_rejects_cap_truncation() {
    let (env, addr, _zka, holder, _recipient) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            0x100000000000000000000000000000000,
            EXPIRY,
            33,
        ),
    );
}

#[test(should_fail_with = "value exceeds u64 range")]
unconstrained fn issue_rejects_expiry_truncation() {
    let (env, addr, _zka, holder, _recipient) = setup();
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            0x10000000000000000,
            33,
        ),
    );
}

// TXE enforces duplicate-nullifier rejection for these cases, but these are
// simulation tests, not kernel proof or isolated-network acceptance evidence.
// Each repeats the same private root ceremony, which must remain single-use
// regardless of fields, recipient, or whether the original note still exists.
#[test(should_fail_with = "failed with duplicate nullifiers")]
unconstrained fn issue_rejects_exact_replay() {
    let (env, addr, _zka, holder, _recipient) = setup();
    issue_standard(env, addr, holder);
    issue_standard(env, addr, holder);
}

#[test(should_fail_with = "failed with duplicate nullifiers")]
unconstrained fn issue_rejects_cap_substitution_under_an_issued_root() {
    let (env, addr, _zka, holder, _recipient) = setup();
    issue_standard(env, addr, holder);
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1001,
            EXPIRY,
            v2_policy_hash(POLICY_DEPTH_LIMIT),
        ),
    );
}

#[test(should_fail_with = "failed with duplicate nullifiers")]
unconstrained fn issue_rejects_expiry_substitution_under_an_issued_root() {
    let (env, addr, _zka, holder, _recipient) = setup();
    issue_standard(env, addr, holder);
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY + 1,
            v2_policy_hash(POLICY_DEPTH_LIMIT),
        ),
    );
}

#[test(should_fail_with = "failed with duplicate nullifiers")]
unconstrained fn issue_rejects_policy_substitution_under_an_issued_root() {
    let (env, addr, _zka, holder, _recipient) = setup();
    issue_standard(env, addr, holder);
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            v2_policy_hash(POLICY_DEPTH_LIMIT) + 1,
        ),
    );
}

#[test(should_fail_with = "failed with duplicate nullifiers")]
unconstrained fn issue_rejects_asset_substitution_under_an_issued_root() {
    let (env, addr, _zka, holder, _recipient) = setup();
    issue_standard(env, addr, holder);
    issue_standard_for_asset(env, addr, holder, ASSET_OTHER);
}

#[test(should_fail_with = "failed with duplicate nullifiers")]
unconstrained fn issue_rejects_recipient_substitution_under_an_issued_root() {
    let (env, addr, _zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    env.call_private(
        recipient,
        ZKMMandate::at(addr).issue(
            recipient,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            v2_policy_hash(POLICY_DEPTH_LIMIT),
        ),
    );
}

#[test(should_fail_with = "failed with duplicate nullifiers")]
unconstrained fn issue_rejects_historical_replay_after_retirement() {
    let (env, addr, _zka, holder, _recipient) = setup();
    issue_standard(env, addr, holder);
    env.call_private(holder, ZKMMandate::at(addr).retire(ROOT_A, 1000));
    assert(count_of(env, addr, holder, ROOT_A) == 0);
    issue_standard(env, addr, holder);
}

// -----------------------------------------------------------------------------
// SPLIT (kind 1)
// -----------------------------------------------------------------------------

#[test]
unconstrained fn split_conserves_the_cap_across_two_children() {
    let (env, addr, _zka, holder, _delegate) = setup();
    issue_standard(env, addr, holder);

    env.call_private(holder, ZKMMandate::at(addr).split(ROOT_A, 1000, 600, 400));

    assert(count_of(env, addr, holder, ROOT_A) == 2, "split must yield two children");
    assert(total_of(env, addr, holder, ROOT_A) == 1000, "split must conserve total cap");
}

#[test(should_fail_with = "split must conserve the cap exactly")]
unconstrained fn split_that_creates_authority_reverts() {
    let (env, addr, _zka, holder, _delegate) = setup();
    issue_standard(env, addr, holder);

    // 600 + 500 = 1100 != 1000: authority creation must be impossible.
    env.call_private(holder, ZKMMandate::at(addr).split(ROOT_A, 1000, 600, 500));
}

#[test]
unconstrained fn split_children_are_independently_consumable() {
    let (env, addr, _zka, holder, _delegate) = setup();
    issue_standard(env, addr, holder);

    env.call_private(holder, ZKMMandate::at(addr).split(ROOT_A, 1000, 600, 400));
    // Consume ONLY the 400-cap child (the (root_id, remaining_cap) selector).
    env.call_private(holder, ZKMMandate::at(addr).retire(ROOT_A, 400));

    assert(count_of(env, addr, holder, ROOT_A) == 1, "one child should remain");
    assert(total_of(env, addr, holder, ROOT_A) == 600, "the 600-cap child should remain");
}

// -----------------------------------------------------------------------------
// RETIRE (kind 2)
// -----------------------------------------------------------------------------

#[test]
unconstrained fn retire_destroys_authority_without_successors() {
    let (env, addr, _zka, holder, _delegate) = setup();
    issue_standard(env, addr, holder);

    env.call_private(holder, ZKMMandate::at(addr).retire(ROOT_A, 1000));

    assert(count_of(env, addr, holder, ROOT_A) == 0, "retire must leave no successor");
    assert(total_of(env, addr, holder, ROOT_A) == 0, "retire must destroy the cap");
}

#[test]
unconstrained fn retire_leaves_other_roots_untouched() {
    let (env, addr, _zka, holder, _delegate) = setup();
    let ph = v2_policy_hash(POLICY_DEPTH_LIMIT);
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            ph,
        ),
    );
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_B,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS + 1,
            SETTLEMENT_CONTEXT,
            ASSET,
            700,
            EXPIRY,
            ph,
        ),
    );

    env.call_private(holder, ZKMMandate::at(addr).retire(ROOT_A, 1000));

    assert(total_of(env, addr, holder, ROOT_A) == 0, "ROOT_A must be gone");
    assert(total_of(env, addr, holder, ROOT_B) == 700, "ROOT_B must be untouched");
}

#[test(should_fail_with = "Mandate note not found")]
unconstrained fn consuming_a_missing_mandate_reverts() {
    let (env, addr, _zka, holder, _delegate) = setup();
    issue_standard(env, addr, holder);

    // Wrong in_cap selector: no (ROOT_A, 999) note exists.
    env.call_private(holder, ZKMMandate::at(addr).retire(ROOT_A, 999));
}

// -----------------------------------------------------------------------------
// DELEGATE_FULL (kind 3)
// -----------------------------------------------------------------------------

#[test]
unconstrained fn delegate_full_rebinds_the_whole_cap_to_the_delegate() {
    let (env, addr, _zka, holder, delegate) = setup();
    issue_standard(env, addr, holder);

    env.call_private(
        holder,
        ZKMMandate::at(addr).delegate_full(
            ROOT_A,
            1000,
            delegate,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );

    assert(count_of(env, addr, holder, ROOT_A) == 0, "delegator must retain nothing");
    assert(count_of(env, addr, delegate, ROOT_A) == 1, "delegate must hold the successor");
    assert(total_of(env, addr, delegate, ROOT_A) == 1000, "full cap must rebind");
}

#[test]
unconstrained fn delegate_can_consume_the_delegated_mandate() {
    let (env, addr, _zka, holder, delegate) = setup();
    issue_standard(env, addr, holder);

    env.call_private(
        holder,
        ZKMMandate::at(addr).delegate_full(
            ROOT_A,
            1000,
            delegate,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );
    // The §6 possession property, platform-carried: the delegate (and only the
    // delegate) can now transition the successor.
    env.call_private(delegate, ZKMMandate::at(addr).retire(ROOT_A, 1000));

    assert(count_of(env, addr, delegate, ROOT_A) == 0, "delegate consumed the successor");
}

#[test(should_fail_with = "delegation exceeds the policy depth limit")]
unconstrained fn delegation_forbidden_by_v2_zero_depth_limit() {
    let (env, addr, _zka, holder, delegate) = setup();
    // depth_limit = 0 forbids delegation outright (§6): a delegated successor's
    // depth is always >= 1.
    let ph = v2_policy_hash(0);
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            ph,
        ),
    );

    env.call_private(
        holder,
        ZKMMandate::at(addr).delegate_full(
            ROOT_A,
            1000,
            delegate,
            2,
            POLICY_MPS,
            0,
            0,
            0,
            POLICY_BLINDING,
        ),
    );
}

#[test(should_fail_with = "rebind target must differ from the current holder")]
unconstrained fn delegate_to_self_reverts() {
    let (env, addr, _zka, holder, _delegate) = setup();
    issue_standard(env, addr, holder);

    env.call_private(
        holder,
        ZKMMandate::at(addr).delegate_full(
            ROOT_A,
            1000,
            holder,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );
}

#[test(should_fail_with = "policy opening mismatch")]
unconstrained fn delegate_with_a_wrong_policy_opening_reverts() {
    let (env, addr, _zka, holder, delegate) = setup();
    issue_standard(env, addr, holder);

    // Wrong blinding: the opening does not match the committed policy_hash.
    env.call_private(
        holder,
        ZKMMandate::at(addr).delegate_full(
            ROOT_A,
            1000,
            delegate,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            0xdead,
        ),
    );
}

// -----------------------------------------------------------------------------
// DELEGATE_PARTIAL (kind 4)
// -----------------------------------------------------------------------------

#[test]
unconstrained fn delegate_partial_splits_authority_between_delegate_and_holder() {
    let (env, addr, _zka, holder, delegate) = setup();
    issue_standard(env, addr, holder);

    env.call_private(
        holder,
        ZKMMandate::at(addr).delegate_partial(
            ROOT_A,
            1000,
            delegate,
            300,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );

    assert(total_of(env, addr, delegate, ROOT_A) == 300, "delegate share must be 300");
    assert(total_of(env, addr, holder, ROOT_A) == 700, "retained share must be 700");
    assert(count_of(env, addr, holder, ROOT_A) == 1, "holder keeps exactly one successor");
}

#[test(should_fail_with = "delegated cap exceeds the remaining cap")]
unconstrained fn delegate_partial_cannot_exceed_the_cap() {
    let (env, addr, _zka, holder, delegate) = setup();
    issue_standard(env, addr, holder);

    env.call_private(
        holder,
        ZKMMandate::at(addr).delegate_partial(
            ROOT_A,
            1000,
            delegate,
            1200,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );
}

// -----------------------------------------------------------------------------
// ROTATE (kind 5)
// -----------------------------------------------------------------------------

#[test]
unconstrained fn rotate_hands_the_full_cap_to_the_new_address() {
    let (env, addr, _zka, holder, delegate) = setup();
    issue_standard(env, addr, holder);

    env.call_private(holder, ZKMMandate::at(addr).rotate(ROOT_A, 1000, delegate));

    assert(count_of(env, addr, holder, ROOT_A) == 0, "old address must retain nothing");
    assert(total_of(env, addr, delegate, ROOT_A) == 1000, "full cap must move");
}

#[test]
unconstrained fn rotate_is_not_policy_gated() {
    let (env, addr, _zka, holder, delegate) = setup();
    // Even a v2 policy with depth_limit = 0 (delegation forbidden) permits
    // ROTATE: it is the §6 unrestricted clean handoff at the same depth, not a
    // delegation.
    let ph = v2_policy_hash(0);
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            ph,
        ),
    );

    env.call_private(holder, ZKMMandate::at(addr).rotate(ROOT_A, 1000, delegate));

    assert(
        total_of(env, addr, delegate, ROOT_A) == 1000,
        "rotate must succeed under depth_limit 0",
    );
}

#[test(should_fail_with = "rebind target must differ from the current holder")]
unconstrained fn rotate_to_self_reverts() {
    let (env, addr, _zka, holder, _delegate) = setup();
    issue_standard(env, addr, holder);

    env.call_private(holder, ZKMMandate::at(addr).rotate(ROOT_A, 1000, holder));
}

// -----------------------------------------------------------------------------
// SPEND authorization (kind 0 leg)
// -----------------------------------------------------------------------------

#[test]
unconstrained fn spend_authorize_reduces_the_cap_by_the_amount() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 500, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 200, 1);

    env.call_private(
        holder,
        ZKMMandate::at(addr).spend_authorize(
            ROOT_A,
            1000,
            recipient,
            200,
            1,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );

    assert(count_of(env, addr, holder, ROOT_A) == 1, "one successor mandate must remain");
    assert(total_of(env, addr, holder, ROOT_A) == 800, "cap must drop to 1000 - 200 = 800");
    assert(zka_balance_of(env, zka, holder) == 300, "holder must retain 300 ZKA units");
    assert(zka_balance_of(env, zka, recipient) == 200, "recipient must receive exactly 200");
}

#[test]
unconstrained fn repeated_spends_draw_down_the_same_mandate_lineage() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 500, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 200, 1);
    authorize_bound_spend(env, addr, zka, holder, recipient, 300, 2);

    env.call_private(
        holder,
        ZKMMandate::at(addr).spend_authorize(
            ROOT_A,
            1000,
            recipient,
            200,
            1,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );
    env.call_private(
        holder,
        ZKMMandate::at(addr).spend_authorize(
            ROOT_A,
            800,
            recipient,
            300,
            2,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );

    assert(total_of(env, addr, holder, ROOT_A) == 500, "1000 - 200 - 300 = 500");
    assert(zka_balance_of(env, zka, holder) == 0, "both bound spends must debit all 500 units");
    assert(zka_balance_of(env, zka, recipient) == 500, "recipient must receive 200 + 300");
}

// -----------------------------------------------------------------------------
// Conjoined-call binding matrix
//
// Each rejection below has an accepting counterpart with an otherwise
// identical fixture. The amount pair changes only `amount` (60 -> 61), the
// asset pair changes only the issued mandate's `asset_id` (7 -> 8), the replay
// pair changes only the second nonce (7 -> 8), and the consumer pair changes
// only the ZKA target whose outer authwit hash is signed (pinned -> decoy).
//
// `should_fail_with` checks the named failure path, including failures after
// ZKM stages its successor and enters ZKA. It aborts the TXE test: assertions
// after a rejected call cannot inspect rollback state. The manual local-node
// binding suite separately checks balances/cap after caught rejections.
// -----------------------------------------------------------------------------

#[test]
unconstrained fn spend_accepts_the_exact_bound_amount_tuple() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 11);

    spend_standard(env, addr, holder, recipient, 1000, 60, 11);

    assert(total_of(env, addr, holder, ROOT_A) == 940, "exact amount tuple must reduce cap by 60");
    assert(zka_balance_of(env, zka, recipient) == 60, "exact amount tuple must transfer 60");
}

#[test(should_fail_with = "Unknown auth witness for message hash")]
unconstrained fn spend_rejects_an_authorized_amount_differing_by_exactly_one() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    // The only difference from the accepting counterpart is the constrained
    // spend amount below: this witness authorizes 60, while ZKM requests 61.
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 11);

    spend_standard(env, addr, holder, recipient, 1000, 61, 11);
}

#[test]
unconstrained fn spend_accepts_the_exact_bound_asset_tuple() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard_for_asset(env, addr, holder, ASSET);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 12);

    spend_standard(env, addr, holder, recipient, 1000, 60, 12);

    assert(total_of(env, addr, holder, ROOT_A) == 940, "exact asset tuple must reduce cap by 60");
    assert(zka_balance_of(env, zka, recipient) == 60, "exact asset tuple must transfer asset 7");
}

#[test(should_fail_with = "Unknown auth witness for message hash")]
unconstrained fn spend_rejects_a_transfer_for_a_different_mandate_asset() {
    let (env, addr, zka, holder, recipient) = setup();
    // The only difference from the accepting counterpart is asset_id 8. The
    // funded ZKA note and authwit still name asset 7, while the adapter must
    // project the constrained mandate asset to asset 8's commitment.
    issue_standard_for_asset(env, addr, holder, ASSET_OTHER);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 12);

    spend_standard(env, addr, holder, recipient, 1000, 60, 12);
}

#[test]
unconstrained fn spend_accepts_a_fresh_nonce_for_an_otherwise_identical_second_call() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 20, 7);
    authorize_bound_spend(env, addr, zka, holder, recipient, 20, 8);

    spend_standard(env, addr, holder, recipient, 1000, 20, 7);
    spend_standard(env, addr, holder, recipient, 980, 20, 8);

    assert(total_of(env, addr, holder, ROOT_A) == 960, "two fresh authwits must reduce cap by 40");
    assert(zka_balance_of(env, zka, recipient) == 40, "two fresh authwits must transfer 40 total");
}

#[test(should_fail_with = "failed with duplicate nullifiers")]
unconstrained fn spend_rejects_reuse_of_the_same_authwit_nonce() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 20, 7);
    authorize_bound_spend(env, addr, zka, holder, recipient, 20, 8);

    spend_standard(env, addr, holder, recipient, 1000, 20, 7);
    // The only difference from the accepting counterpart is reuse of nonce 7
    // instead of the fresh nonce 8, reproducing the authwit nullifier exactly.
    spend_standard(env, addr, holder, recipient, 980, 20, 7);
}

#[test]
unconstrained fn spend_accepts_an_authwit_for_the_immutable_zka_consumer() {
    let (env, addr, _decoy_zka, pinned_zka, holder, recipient) = setup_with_decoy_zka();
    issue_standard(env, addr, holder);
    fund_holder(env, pinned_zka, holder, 100, CLAIM_SECRET);
    assert(
        env.view_public(ZKMMandate::at(addr).get_zka_transfer()) == pinned_zka,
        "ZKM must expose the pinned ZKA instance",
    );
    authorize_bound_spend(env, addr, pinned_zka, holder, recipient, 60, 13);

    spend_standard(env, addr, holder, recipient, 1000, 60, 13);

    assert(
        zka_balance_of(env, pinned_zka, recipient) == 60,
        "pinned ZKA must receive the exact call",
    );
}

#[test(should_fail_with = "Unknown auth witness for message hash")]
unconstrained fn spend_rejects_an_authwit_for_a_different_zka_consumer() {
    let (env, addr, decoy_zka, pinned_zka, holder, recipient) = setup_with_decoy_zka();
    issue_standard(env, addr, holder);
    fund_holder(env, pinned_zka, holder, 100, CLAIM_SECRET);
    assert(
        env.view_public(ZKMMandate::at(addr).get_zka_transfer()) == pinned_zka,
        "ZKM must remain pinned to the non-decoy ZKA instance",
    );
    // Same caller, selector, arguments and nonce as the accepting counterpart;
    // only the signed outer consumer changes from pinned_zka to decoy_zka.
    authorize_bound_spend(env, addr, decoy_zka, holder, recipient, 60, 13);

    spend_standard(env, addr, holder, recipient, 1000, 60, 13);
}

#[test]
unconstrained fn ordinary_owner_direct_transfer_does_not_consume_a_mandate() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);

    // Owner-direct ZKA remains available independently of mandate selection.
    // authorize_once permits a direct holder transfer_from only with nonce 0.
    env.call_private(holder, ZKATransfer::at(zka).transfer_from(holder, recipient, ZKA_ASSET, 60, 0));

    assert(
        total_of(env, addr, holder, ROOT_A) == 1000,
        "owner-direct transfer must not consume authority",
    );
    assert(zka_balance_of(env, zka, holder) == 40, "owner-direct transfer must debit exactly 60");
    assert(zka_balance_of(env, zka, recipient) == 60, "owner-direct recipient must receive 60");
}

#[test(should_fail_with = "Invalid authwit nonce")]
unconstrained fn direct_transfer_cannot_reuse_a_zkm_selected_authwit() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 21);

    // Same from/to/asset/value/nonce as the enrolled nested call. A top-level
    // holder call changes msg_sender from ZKM to the holder and must reject
    // its nonzero delegated nonce, rather than spending without the mandate.
    env.call_private(
        holder,
        ZKATransfer::at(zka).transfer_from(holder, recipient, ZKA_ASSET, 60, 21),
    );
}

#[test(should_fail_with = "Unknown auth witness for message hash")]
unconstrained fn spend_rejects_a_substituted_recipient() {
    let (mut env, addr, zka, holder, recipient) = setup();
    let substituted = env.create_light_account();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 22);

    // Change only the recipient in the nested transfer tuple.
    spend_standard(env, addr, holder, substituted, 1000, 60, 22);
}

#[test(should_fail_with = "Mandate note not found")]
unconstrained fn spend_cannot_consume_a_mandate_from_another_context_deployment() {
    let (mut env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    let other_initializer = ZKMMandate::interface().constructor(SETTLEMENT_CONTEXT + 1, zka);
    let other_addr = env.deploy("ZKMMandate").with_public_initializer(holder, other_initializer);
    authorize_bound_spend(env, other_addr, zka, holder, recipient, 60, 23);

    // The matching root/cap exists only in the original deployment's note
    // silo. There is no public API for injecting a malformed domain opening.
    spend_standard(env, other_addr, holder, recipient, 1000, 60, 23);
}

#[test(should_fail_with = "Unknown auth witness for message hash")]
unconstrained fn spend_rejects_an_authwit_for_another_context_deployment() {
    let (mut env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    let other_initializer = ZKMMandate::interface().constructor(SETTLEMENT_CONTEXT + 1, zka);
    let other_addr = env.deploy("ZKMMandate").with_public_initializer(holder, other_initializer);
    let ph = v2_policy_hash(POLICY_DEPTH_LIMIT);
    env.call_private(
        holder,
        ZKMMandate::at(other_addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT + 1,
            ASSET,
            1000,
            EXPIRY,
            ph,
        ),
    );
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 24);

    // Both contexts contain a fixture mandate. The signed caller is still
    // addr, so changing only the consuming deployment must not reuse it.
    spend_standard(env, other_addr, holder, recipient, 1000, 60, 24);
}

#[test(should_fail_with = "insufficient balance")]
unconstrained fn spend_rejects_late_nested_zka_insufficient_funds() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 50, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 25);

    // ZKM has consumed its input and staged a successor before this nested
    // ZKA failure, which occurs after ZKA has selected its funded value note.
    // TXE establishes rejection here; it cannot inspect post-failure state.
    spend_standard(env, addr, holder, recipient, 1000, 60, 25);
}

#[test(should_fail_with = "Spend amount must be non-zero")]
unconstrained fn spend_rejects_zero_amount_like_the_rev13_reference() {
    let (env, addr, _zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);

    spend_standard(env, addr, holder, recipient, 1000, 0, 26);
}

#[test]
unconstrained fn full_drain_spend_preserves_a_live_zero_cap_successor() {
    let (env, addr, zka, holder, recipient) = setup();
    let ph = v2_policy_hash(POLICY_DEPTH_LIMIT);
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            60,
            EXPIRY,
            ph,
        ),
    );
    fund_holder(env, zka, holder, 60, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 27);

    spend_standard(env, addr, holder, recipient, 60, 60, 27);

    assert(
        count_of(env, addr, holder, ROOT_A) == 1,
        "full drain must retain one successor mandate",
    );
    assert(total_of(env, addr, holder, ROOT_A) == 0, "full drain successor must have zero cap");
    assert(zka_balance_of(env, zka, holder) == 0, "full note value must be spent");
    assert(
        zka_balance_of(env, zka, recipient) == 60,
        "recipient must receive the full positive value",
    );
    env.call_private(holder, ZKMMandate::at(addr).retire(ROOT_A, 0));
    assert(count_of(env, addr, holder, ROOT_A) == 0, "zero-cap successor must remain consumable");
}

unconstrained fn spend_receipted_standard(
    env: TestEnvironment,
    addr: AztecAddress,
    holder: AztecAddress,
    recipient: AztecAddress,
    amount: Field,
    authwit_nonce: Field,
    interaction_context: Field,
) {
    env.call_private(
        holder,
        ZKMMandate::at(addr).spend_authorize_receipted(
            ROOT_A,
            1000,
            recipient,
            amount,
            authwit_nonce,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
            interaction_context,
        ),
    );
}

#[test]
unconstrained fn receipted_spend_binds_the_emitted_body_to_the_actual_nested_call() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 28);
    let transfer_call = ZKATransfer::at(zka).transfer_from(holder, recipient, ZKA_ASSET, 60, 28);
    let (chain_id, version) =
        env.utility_context(|context| (context.chain_id(), context.version()));
    let expected_hash = compute_authwit_message_hash_from_call(
        addr,
        transfer_call.target_contract,
        chain_id,
        version,
        transfer_call.selector,
        transfer_call.args,
    );

    spend_receipted_standard(env, addr, holder, recipient, 60, 28, 28);

    let events = receipt_private_events(ZKMSpendReceiptV1::get_event_type_id(), addr, recipient);
    assert_eq(events.len(), 1);
    let expected = ZKMSpendReceiptV1 {
        receipt_domain: ZKM_SPEND_RECEIPT_DOMAIN,
        receipt_version: 1,
        interaction_context: 28,
        settlement_context: SETTLEMENT_CONTEXT,
        zkm_instance: addr.to_field(),
        zka_instance: zka.to_field(),
        transfer_message_hash: expected_hash,
    };
    assert_eq(events.get(0), BoundedVec::from_array(expected.serialize()));
    assert_eq(
        receipt_private_events(ZKMSpendReceiptV1::get_event_type_id(), addr, holder).len(),
        0,
    );
    assert(total_of(env, addr, holder, ROOT_A) == 940, "receipted spend must reduce the cap once");
    assert(zka_balance_of(env, zka, holder) == 40, "receipted spend must debit exactly 60");
    assert(zka_balance_of(env, zka, recipient) == 60, "receipted spend must deliver exactly 60");
}

#[test]
unconstrained fn legacy_spend_does_not_publish_a_receipted_entrypoint_event() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 100, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 30);

    spend_standard(env, addr, holder, recipient, 1000, 60, 30);

    assert_eq(
        receipt_private_events(ZKMSpendReceiptV1::get_event_type_id(), addr, recipient).len(),
        0,
    );
    assert(
        zka_balance_of(env, zka, recipient) == 60,
        "ordinary legacy conjoined spend still succeeds",
    );
}

#[test(should_fail_with = "receipt interaction context must be non-zero")]
unconstrained fn receipted_spend_rejects_zero_interaction_context() {
    let (env, addr, _zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    spend_receipted_standard(env, addr, holder, recipient, 60, 28, 0);
}

#[test(should_fail_with = "receipt context must equal authwit nonce")]
unconstrained fn receipted_spend_rejects_a_context_different_from_the_authorized_nonce() {
    let (env, addr, _zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    spend_receipted_standard(env, addr, holder, recipient, 60, 28, 29);
}

#[test(should_fail_with = "insufficient balance")]
unconstrained fn receipted_spend_rejects_late_nested_insufficient_funds() {
    let (env, addr, zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);
    fund_holder(env, zka, holder, 50, CLAIM_SECRET);
    authorize_bound_spend(env, addr, zka, holder, recipient, 60, 29);
    // Rejection reaches the nested value-note check. should_fail cannot inspect
    // subsequent state or claim that a failed transaction was mined.
    spend_receipted_standard(env, addr, holder, recipient, 60, 29, 29);
}

#[test]
unconstrained fn receipt_event_serialization_and_commitment_match_the_official_sdk_kat() {
    let event = ZKMSpendReceiptV1 {
        receipt_domain: ZKM_SPEND_RECEIPT_DOMAIN,
        receipt_version: 1,
        interaction_context: 9,
        settlement_context: 11,
        zkm_instance: 13,
        zka_instance: 15,
        transfer_message_hash: 17,
    };
    assert_eq(event.serialize(), [ZKM_SPEND_RECEIPT_DOMAIN, 1, 9, 11, 13, 15, 17]);
    assert_eq(ZKMSpendReceiptV1::get_event_type_id().to_field(), 0x6f5fed4f);
    // Independently reconstructed with SDK computePrivateEventCommitment in
    // benchmarks/consumer_profile.test.ts, using this exact serialized body.
    assert_eq(
        compute_private_event_commitment(event, 19),
        0x128c75352cbc851f8c06033754409fa659d277b9e4280cfc5640478ad9e581d0,
    );
}

#[test(should_fail_with = "spend amount exceeds the policy per-spend ceiling")]
unconstrained fn spend_over_the_policy_ceiling_reverts() {
    let (env, addr, _zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);

    // 600 > max_per_spend 500, though well under the 1000 cap.
    env.call_private(
        holder,
        ZKMMandate::at(addr).spend_authorize(
            ROOT_A,
            1000,
            recipient,
            600,
            1,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );
}

#[test(should_fail_with = "spend amount exceeds the remaining cap")]
unconstrained fn spend_over_the_remaining_cap_reverts() {
    let (env, addr, _zka, holder, recipient) = setup();
    let ph = v2_policy_hash(POLICY_DEPTH_LIMIT);
    // Cap 100 under a 500-ceiling policy: the cap is the binding constraint.
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            100,
            EXPIRY,
            ph,
        ),
    );

    env.call_private(
        holder,
        ZKMMandate::at(addr).spend_authorize(
            ROOT_A,
            100,
            recipient,
            200,
            1,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            POLICY_BLINDING,
        ),
    );
}

#[test(should_fail_with = "policy opening mismatch")]
unconstrained fn spend_with_a_wrong_policy_opening_reverts() {
    let (env, addr, _zka, holder, recipient) = setup();
    issue_standard(env, addr, holder);

    env.call_private(
        holder,
        ZKMMandate::at(addr).spend_authorize(
            ROOT_A,
            1000,
            recipient,
            200,
            1,
            2,
            POLICY_MPS,
            0,
            0,
            POLICY_DEPTH_LIMIT,
            0xdead,
        ),
    );
}

// -----------------------------------------------------------------------------
// Depth budget across a delegation chain
// -----------------------------------------------------------------------------

#[test(should_fail_with = "delegation exceeds the policy depth limit")]
unconstrained fn a_delegation_chain_exhausts_the_policy_depth_budget() {
    let (env, addr, _zka, holder, delegate) = setup();
    // depth_limit = 1: exactly one delegation hop is permitted.
    let ph = v2_policy_hash(1);
    env.call_private(
        holder,
        ZKMMandate::at(addr).issue(
            holder,
            ROOT_A,
            ISSUANCE_KEY,
            ISSUANCE_RANDOMNESS,
            SETTLEMENT_CONTEXT,
            ASSET,
            1000,
            EXPIRY,
            ph,
        ),
    );

    // Hop 1 (depth 0 -> 1): permitted.
    env.call_private(
        holder,
        ZKMMandate::at(addr).delegate_full(
            ROOT_A,
            1000,
            delegate,
            2,
            POLICY_MPS,
            0,
            0,
            1,
            POLICY_BLINDING,
        ),
    );
    // Hop 2 (depth 1 -> 2): exceeds depth_limit 1 -> must revert.
    env.call_private(
        delegate,
        ZKMMandate::at(addr).delegate_full(
            ROOT_A,
            1000,
            holder,
            2,
            POLICY_MPS,
            0,
            0,
            1,
            POLICY_BLINDING,
        ),
    );
}
