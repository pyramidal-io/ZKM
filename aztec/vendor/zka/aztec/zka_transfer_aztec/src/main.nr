// =============================================================================
// ZKA Transfer Contract (Aztec.nr) -- aztec-nr v6.0.0
//
// Wraps ZKA's single-asset private transfer as an Aztec contract with
// optional compliance-gated receiving.
//
// Core transfer operations:
//   claim_private(recipient, amount, secret, leaf)   -- Claim an escrowed L1 deposit
//   transfer(to, asset_commitment, value)            -- Transfer to new owner
//   transfer_from(from, to, asset, value, nonce)     -- Holder-authorized transfer
//   withdraw(amount, asset_commitment, recipient_l1) -- Exit shielded pool
//
// Compliance-gated transfers:
//   transfer_with_compliance(to, asset, value)       -- Requires recipient compliance
//   enable_compliance(enabled)                       -- Admin: toggle compliance mode
//   set_credential_contract(address)                 -- Admin: set credential contract
//
// COMPLIANCE FLOW (authenticated; no open registration):
//   The transfer contract holds NO local compliance registry. The configured
//   ZKACredential contract is the single source of truth for who is compliant.
//     1. A recipient self-registers by calling ZKACredential.verify_compliance(),
//        which proves they hold a valid credential (commitment derived from
//        THEIR OWN nhk; non-revocation is checked at verification time) and
//        writes their address into the
//        credential contract's compliance_set. There is NO function -- here or
//        on the credential contract -- to mark an address compliant without that
//        credential proof.
//     2. transfer_with_compliance checks compliance IN PRIVATE: it reads the
//        compliance config (a DelayedPublicMutable) and, when compliance is
//        enabled, makes a private static call to
//        ZKACredential::at(credential_contract).assert_compliant(recipient),
//        which reverts if the recipient is not compliant. If compliance is
//        enabled but credential_contract is unset (zero address), the gate
//        reverts as a misconfiguration rather than silently passing.
//   PUBLIC OUTPUTS (ZKA SS5.8): the gated transfer enqueues no public call, so
//   it publishes neither the recipient nor the fact that the gate ran. With no
//   pending change, the private reads cap the tx expiration at
//   anchor + MAX_TX_LIFETIME - 1, the same cap the kernel's contract-update
//   horizon puts on every private call, so a gated transfer's expiration
//   equals a plain transfer's. While an admin config change is pending, gated
//   transfers instead expire just before its public timestamp of change: that
//   reveals this ZKATransfer instance's gated-transfer class (not the
//   recipient) until the change takes effect. The admin controls that window;
//   the setters skip no-op changes so that a repeat call does not reopen it.
//   Admin config changes take effect after COMPLIANCE_CONFIG_DELAY, including
//   an emergency disable or a swap away from a faulty credential contract.
//   The sender's PXE must have the configured ZKACredential registered, since
//   the gate runs as a private call in the sender's PXE.
// All ZKANote hashes match the standalone zka_transfer circuit via zka_lib
// delegation (see zka_aztec_lib).
//
// v0.6.0 SS1.6 SAFEGUARDS 3 & 5 CONFORMANCE (reviewed):
//   Safeguard 3 (no admin path over note validity): the admin functions
//   (set_credential_contract, enable_compliance) gate ONLY the opt-in
//   transfer_with_compliance interaction. claim_private, transfer, and withdraw
//   carry no admin or compliance check, so no admin/governance/emergency key can
//   invalidate, freeze, redirect, or force-transfer a note. A failed recipient
//   compliance check reverts the whole tx atomically -- the sender simply keeps
//   their notes (counterparty refusal, never fund loss). There are no pausable
//   or upgradeable paths.
//   Safeguard 5 (unconditional exit): withdraw takes no compliance, credential,
//   or admin input and is callable regardless of compliance_enabled -- exit to
//   self-custody is never gated. Likewise plain transfer is never gated, so a
//   holder always retains full custody.
//   Locked in by the Safeguard 3/5 tests in src/test.nr
//   (withdraw_is_unconditional_*, plain_transfer_unaffected_*,
//   holder_can_fully_exit_*).
//
// VALUE-CONSERVATION INVARIANT (Critical: value loss on multi-note spends):
//   The failure mode this guards against: popping up to
//   MAX_NOTE_HASH_READ_REQUESTS_PER_CALL of the sender's notes with an
//   UNFILTERED NoteGetterOptions::new() (nullifying notes of every asset), then
//   re-creating change for only the SINGLE matched note -- silently destroying
//   the value of every other popped note. transfer, transfer_with_compliance,
//   and withdraw therefore:
//     1. Asset-scope the selection with .select(asset_commitment, EQ, ...) so
//        only the requested asset's notes are nullified.
//     2. Sum `value` over ALL popped notes (`total`), assert
//        total >= amount, and re-insert a SINGLE change note for
//        (total - amount) back to the sender. No popped value is left
//        unaccounted, and multiple notes can fund one transfer.
// =============================================================================

mod compliance_config;
mod conservation;
mod deposit;
mod test;
mod withdrawal;

use aztec::macros::aztec;

#[aztec]
pub contract ZKATransfer {
    use aztec::{
        macros::{
            functions::{authorize_once, external, initializer, internal, only_self, view},
            storage::storage,
        },
        messages::delivery::MessageDelivery,
        note::{note_getter_options::{NoteGetterOptions, SortOrder}, note_interface::NoteProperties},
        protocol::{
            address::{AztecAddress, EthAddress},
            constants::{MAX_NOTE_HASH_READ_REQUESTS_PER_CALL, MAX_TX_LIFETIME},
            traits::ToField,
        },
        state_vars::{DelayedPublicMutable, Owned, PrivateSet, PublicImmutable, PublicMutable},
        utils::comparison::Comparator,
    };

    use zka_aztec_lib::ZKANote;

    // Cross-contract handle for the compliance source of truth. The transfer
    // gate calls ZKACredential::assert_compliant(recipient) privately instead of
    // reading a local registry, so the only way to become compliant is to prove a
    // credential to the credential contract (see file header). This is a one-way
    // coupling: ZKACredential does NOT depend on this contract, so there is no
    // circular dependency.
    use zka_credential_aztec::ZKACredential;

    use crate::compliance_config::ComplianceConfig;
    use crate::conservation::{assert_fits_u128, conserved_change};

    // Delay before an admin compliance-config change takes effect. Equal to
    // MAX_TX_LIFETIME so that the private config read caps the tx expiration
    // no lower than the kernel already does (see file header, PUBLIC OUTPUTS).
    pub global COMPLIANCE_CONFIG_DELAY: u64 = MAX_TX_LIFETIME;

    // Maximum number of the sender's notes consumed by a single spend. Bounded by
    // the protocol per-call read-request limit. A compile-time constant so
    // `set_limit` can constrain the pop loop.
    //
    // CONSEQUENCE: if a sender holds more than MAX_SPEND_NOTES notes of one asset,
    // `pop_notes` returns only the first MAX_SPEND_NOTES (largest first, via the
    // DESC sort in `_spend`), so a transfer that would need more notes to be
    // funded reverts with "insufficient balance". This is a liveness/UX limit
    // only -- it is atomic, so NO value is lost; the sender can consolidate notes
    // and retry.
    global MAX_SPEND_NOTES: u32 = MAX_NOTE_HASH_READ_REQUESTS_PER_CALL;

    // =========================================================================
    // Storage
    // =========================================================================

    #[storage]
    struct Storage<Context> {
        // Admin address (can configure compliance).
        admin: PublicMutable<AztecAddress, Context>,
        // Per-owner private note set. `notes.at(owner)` yields that owner's
        // PrivateSet<ZKANote>.
        notes: Owned<PrivateSet<ZKANote, Context>, Context>,
        // Whether compliance-gated receiving is enabled, and the ZKACredential
        // contract that answers the gate. Readable in private; admin changes
        // take effect after COMPLIANCE_CONFIG_DELAY.
        compliance_config: DelayedPublicMutable<ComplianceConfig, COMPLIANCE_CONFIG_DELAY, Context>,
        // L1 portal that settles withdrawals (the Outbox-consuming ZKAAztecPortal;
        // see docs/adr/0002). IMMUTABLE by design: it is set once at deployment and
        // can NEVER be changed -- an admin-settable portal could redirect every
        // future exit to an attacker (a direct SS1.6 Safeguard-3 violation). Making
        // it PublicImmutable means no admin/governance path can redirect, gate, or
        // freeze a withdrawal (Safeguards 3 & 5).
        portal: PublicImmutable<EthAddress, Context>,
        // The single ZKA asset backed by the paired L1 portal. Deposit claims
        // read this immutable rather than accepting an asset from the caller,
        // so a message for one escrowed asset cannot mint another.
        asset_commitment: PublicImmutable<Field, Context>,
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    /// `portal` is the L1 ZKAAztecPortal that will consume this contract's L2->L1
    /// withdrawal messages and release the underlying asset. It is stored
    /// immutably (docs/adr/0002): there is intentionally NO setter, so exit can
    /// never be redirected or gated post-deploy.
    #[external("public")]
    #[initializer]
    fn constructor(admin: AztecAddress, portal: EthAddress, asset_commitment: Field) {
        assert(!portal.is_zero(), "Portal must be non-zero");
        assert(asset_commitment != 0, "Asset commitment must be non-zero");
        self.storage.admin.write(admin);
        // compliance_config starts at its zero value: disabled, no contract.
        self.storage.portal.initialize(portal);
        self.storage.asset_commitment.initialize(asset_commitment);
    }

    // =========================================================================
    // Admin Functions
    // =========================================================================

    /// Set the credential contract address used for compliance verification.
    /// Takes effect after COMPLIANCE_CONFIG_DELAY. Builds on the last
    /// SCHEDULED config, so two admin calls in one delay window compose.
    #[external("public")]
    fn set_credential_contract(credential_contract: AztecAddress) {
        assert(
            self.msg_sender() == self.storage.admin.read(),
            "Only admin can set credential contract",
        );
        let (config, _) = self.storage.compliance_config.get_scheduled_value();
        self.internal._schedule_config(
            config,
            ComplianceConfig { enabled: config.enabled, credential_contract },
        );
    }

    /// Enable or disable compliance-gated receiving. When enabled,
    /// transfer_with_compliance requires recipients to be registered compliant.
    /// Takes effect after COMPLIANCE_CONFIG_DELAY.
    #[external("public")]
    fn enable_compliance(enabled: bool) {
        assert(self.msg_sender() == self.storage.admin.read(), "Only admin can toggle compliance");
        let (config, _) = self.storage.compliance_config.get_scheduled_value();
        self.internal._schedule_config(
            config,
            ComplianceConfig { enabled, credential_contract: config.credential_contract },
        );
    }

    /// Schedule `next` unless it equals the last scheduled config. A no-op
    /// change would still open a pending window that marks gated transfers.
    #[internal("public")]
    fn _schedule_config(scheduled: ComplianceConfig, next: ComplianceConfig) {
        if next != scheduled {
            self.storage.compliance_config.schedule_value_change(next);
        }
    }

    // NOTE: there is intentionally NO register_compliant_recipient here. The
    // pre-fix contract exposed an unauthenticated public registration that let
    // anyone mark any address compliant, trivially bypassing the transfer gate.
    // Compliance is now authenticated end-to-end by the credential contract: a
    // recipient self-registers via ZKACredential.verify_compliance() (a credential
    // proof), and the gate below calls ZKACredential.assert_compliant privately.

    // =========================================================================
    // Deposit claim -- authenticate L1 escrow and create its bound ZKA note
    // =========================================================================

    /// Consume exactly one L1 portal message and mint its private ZKA note.
    ///
    /// `consume_l1_to_l2_message` verifies the secret preimage and message-tree
    /// membership, then emits the protocol message nullifier. The content hash
    /// binds `beneficiary`, the immutable asset, and `amount`; the note is sent
    /// to that beneficiary regardless of who submits the claim transaction.
    #[external("private")]
    fn claim_private(
        beneficiary: AztecAddress,
        amount: u128,
        claim_secret: Field,
        message_leaf_index: Field,
    ) {
        assert(!beneficiary.is_zero(), "Beneficiary must be non-zero");
        assert(amount != 0, "Deposit amount must be non-zero");

        let asset_commitment = self.storage.asset_commitment.read();
        let content =
            crate::deposit::deposit_content_hash(beneficiary.to_field(), asset_commitment, amount);
        let portal = self.storage.portal.read();
        self.context.consume_l1_to_l2_message(content, [claim_secret], portal, message_leaf_index);

        let note = ZKANote::new(asset_commitment, amount as Field);
        self.storage.notes.at(beneficiary).insert(note).deliver(
            MessageDelivery::onchain_constrained(),
        );
    }

    // =========================================================================
    // Transfer -- Move value from sender to recipient (no compliance check)
    // =========================================================================

    #[external("private")]
    fn transfer(to: AztecAddress, asset_commitment: Field, value: Field) {
        let from = self.msg_sender();
        assert(value != 0, "Transfer value must be non-zero");

        let change = self.internal._spend(from, asset_commitment, value);

        // Output note to the recipient.
        let output_note = ZKANote::new(asset_commitment, value);
        self.storage.notes.at(to).insert(output_note).deliver(MessageDelivery::onchain_constrained());

        // Single change note back to the sender (only if non-zero).
        self.internal._return_change(from, asset_commitment, change);
    }

    // =========================================================================
    // Delegated transfer -- standard single-use holder authorization. The macro
    // checks the full call before spending; direct holder calls require nonce 0.
    // Keep external last so authorize_once is expanded into the prologue.
    // =========================================================================

    #[authorize_once("from", "authwit_nonce")]
    #[external("private")]
    fn transfer_from(
        from: AztecAddress,
        to: AztecAddress,
        asset_commitment: Field,
        value: Field,
        authwit_nonce: Field,
    ) {
        assert(value != 0, "Transfer value must be non-zero");

        let change = self.internal._spend(from, asset_commitment, value);

        // Output note to the recipient.
        let output_note = ZKANote::new(asset_commitment, value);
        self.storage.notes.at(to).insert(output_note).deliver(MessageDelivery::onchain_constrained());

        // Single change note back to the sender (only if non-zero).
        self.internal._return_change(from, asset_commitment, change);
    }

    // =========================================================================
    // Transfer With Compliance -- compliance-gated transfer
    //
    // Identical private spend logic to `transfer`, but additionally checks the
    // recipient's compliance in private when compliance is enabled. No public
    // call is enqueued, so the recipient is not published.
    //
    // The credential contract's compliance_set is the single source of truth:
    // an address is compliant there ONLY if it proved a valid, non-revoked
    // credential via verify_compliance(). There is no local registry and no way
    // to mark an address compliant without that credential proof.
    //
    // MISCONFIGURATION GUARD: if compliance is enabled but no credential
    // contract has been configured (zero address), we REVERT rather than
    // silently passing -- a compliance-enabled transfer with no compliance
    // oracle is a misconfiguration, not an open door.
    // =========================================================================

    #[external("private")]
    fn transfer_with_compliance(to: AztecAddress, asset_commitment: Field, value: Field) {
        let from = self.msg_sender();
        assert(value != 0, "Transfer value must be non-zero");

        let config = self.storage.compliance_config.get_current_value();
        if config.enabled {
            assert(
                !config.credential_contract.is_zero(),
                "Compliance enabled but credential contract is unset",
            );
            self.view(ZKACredential::at(config.credential_contract).assert_compliant(to));
        }

        let change = self.internal._spend(from, asset_commitment, value);

        let output_note = ZKANote::new(asset_commitment, value);
        self.storage.notes.at(to).insert(output_note).deliver(MessageDelivery::onchain_constrained());

        self.internal._return_change(from, asset_commitment, change);
    }

    // =========================================================================
    // Withdraw -- Exit the shielded pool (L2 -> L1 settlement, docs/adr/0002)
    //
    // Burns `amount` of the sender's notes for `asset_commitment` (with full
    // value conservation: change is returned), then enqueues the public phase
    // that emits the L2->L1 message to the immutable L1 portal.
    //
    // SAFEGUARD 5 (unconditional exit): withdraw takes NO compliance, credential,
    // or admin input and is callable regardless of compliance state. The only
    // settlement-related state is the IMMUTABLE `portal` address (no admin path
    // can redirect/gate it). `external_recipient` is the L1 recipient address
    // (20-byte address, right-aligned in the Field).
    // =========================================================================

    #[external("private")]
    fn withdraw(amount: Field, asset_commitment: Field, external_recipient: Field) {
        let from = self.msg_sender();
        assert(amount != 0, "Withdrawal amount must be non-zero");
        assert(external_recipient != 0, "External recipient must be non-zero");
        // Bound the recipient to a 20-byte L1 address BEFORE any note is burned.
        // A wider recipient yields an L2->L1 message the portal can never
        // consume (see assert_fits_u160), so the burn must not happen at all.
        crate::withdrawal::assert_fits_u160(external_recipient);

        let change = self.internal._spend(from, asset_commitment, amount);
        self.internal._return_change(from, asset_commitment, change);

        self.enqueue_self._process_withdrawal(external_recipient, amount);
    }

    /// Public internal: emit the L2->L1 withdrawal message to the immutable L1
    /// portal (docs/adr/0002). The message content is
    ///   sha256_to_field( selector("withdraw(address,uint256)")
    ///                     ++ recipient_be(32) ++ amount_be(32) )
    /// which the L1 ZKAAztecPortal reconstructs and `outbox.consume`s before
    /// releasing the underlying asset to `external_recipient`. The Aztec rollup
    /// is the prover here -- there is no L1 proof verification on this path (that
    /// is the separate, verifier-based ZKABridgeEthereum cross-env model).
    #[external("public")]
    #[only_self]
    fn _process_withdrawal(external_recipient: Field, amount: Field) {
        assert(amount != 0, "Withdrawal amount must be non-zero");
        assert(external_recipient != 0, "External recipient must be non-zero");
        // Defense in depth: the private `withdraw` already bounds this, but the
        // message is CONSTRUCTED here, so the encoding's own precondition is
        // restated at the point of use.
        crate::withdrawal::assert_fits_u160(external_recipient);

        let portal = self.storage.portal.read();
        let content = crate::withdrawal::withdraw_content_hash(external_recipient, amount);
        self.context.message_portal(portal, content);
    }

    // =========================================================================
    // Private spend helpers (value-conservation core)
    // =========================================================================

    /// Pop ALL of `from`'s notes for `asset_commitment` (asset-scoped so notes
    /// of other assets are never nullified), sum their value, assert the total
    /// covers `amount`, and return the change (total - amount).
    ///
    /// This is the heart of the value-conservation fix: every popped note's
    /// value is accounted for in `total`, so none is silently destroyed.
    #[internal("private")]
    fn _spend(from: AztecAddress, asset_commitment: Field, amount: Field) -> Field {
        // Bound the spend amount before any u128 cast (a bare cast truncates
        // silently -- see assert_fits_u128).
        assert_fits_u128(amount);

        // Asset-scoped, and sorted largest-first (DESC) so the fewest notes are
        // consumed -- minimizing spurious "insufficient balance" reverts when
        // the owner holds more than MAX_SPEND_NOTES notes of this asset (matches
        // canonical balance_set.nr). set_limit bounds the pop loop.
        let options = NoteGetterOptions::new()
            .select(ZKANote::properties().asset_commitment, Comparator.EQ, asset_commitment)
            .sort(ZKANote::properties().value, SortOrder.DESC)
            .set_limit(MAX_SPEND_NOTES);
        let notes = self.storage.notes.at(from).pop_notes(options);
        assert(notes.len() > 0, "No notes available for this asset");

        // Collect the value of EVERY popped note. Each value is range-checked
        // BEFORE the u128 cast: `value as u128` does NOT range-check (it
        // silently truncates under beta.21), so an unbounded note value could
        // otherwise wrap and destroy value. We iterate to the compile-time
        // limit (cheaper constraints) and guard with `i < notes.len()`.
        let mut values: [u128; MAX_SPEND_NOTES] = [0; MAX_SPEND_NOTES];
        for i in 0..MAX_SPEND_NOTES {
            if i < notes.len() {
                let note_value = notes.get_unchecked(i).value;
                assert_fits_u128(note_value);
                values[i] = note_value as u128;
            }
        }

        // Delegate conservation arithmetic to the pure, unit-tested helper:
        // change = (sum of ALL popped values) - amount, asserting the total
        // covers `amount`. No popped value is left unaccounted.
        conserved_change(values, notes.len(), amount as u128) as Field
    }

    /// Re-insert a single change note for `change` back to `owner`, but only if
    /// `change` is non-zero (avoids emitting useless zero-value notes).
    #[internal("private")]
    fn _return_change(owner: AztecAddress, asset_commitment: Field, change: Field) {
        if change != 0 {
            let change_note = ZKANote::new(asset_commitment, change);
            self.storage.notes.at(owner).insert(change_note).deliver(
                MessageDelivery::onchain_constrained(),
            );
        }
    }

    // =========================================================================
    // View / Utility Functions
    // =========================================================================

    /// Check if compliance-gated receiving is enabled (public state).
    #[external("public")]
    #[view]
    fn is_compliance_enabled() -> pub bool {
        self.storage.compliance_config.get_current_value().enabled
    }

    /// Check if a recipient is compliant, by reading the configured credential
    /// contract CROSS-CONTRACT (the same source of truth the transfer gate uses).
    /// Returns false when no credential contract is configured (zero address),
    /// since no recipient can be compliant without a compliance oracle.
    /// A public call: use it for monitoring, not inside a private flow, as its
    /// argument is published.
    #[external("public")]
    #[view]
    fn is_recipient_compliant(recipient: AztecAddress) -> pub bool {
        let credential_contract =
            self.storage.compliance_config.get_current_value().credential_contract;
        if credential_contract.is_zero() {
            false
        } else {
            self.view(ZKACredential::at(credential_contract).is_compliant(recipient))
        }
    }

    /// Get an owner's private balance for a given asset (utility / off-chain).
    #[external("utility")]
    unconstrained fn get_balance(owner: AztecAddress, asset_commitment: Field) -> pub Field {
        let options = aztec::note::note_viewer_options::NoteViewerOptions::new();
        let notes = self.storage.notes.at(owner).view_notes(options);
        let mut balance: Field = 0;
        for i in 0..notes.len() {
            let note = notes.get_unchecked(i);
            if note.asset_commitment == asset_commitment {
                balance += note.value;
            }
        }
        balance
    }
}
