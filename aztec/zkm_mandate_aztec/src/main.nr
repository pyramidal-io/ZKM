// NOT FOR DEPLOYMENT. This is a measurement artifact; it MUST NOT be deployed
// as an authorization surface anywhere real.
//
// Remaining authorization blockers:
//   Revocation is absent as a capability: there is no accumulator, root
//   history, insertion path, or check, so a revoked lineage would transition
//   freely. See NOT PORTED and `_consume` below. This contract has no
//   revocation sink, so nothing can be revoked by it.
// Issuance proves private root-preimage authority; this is the base §3
// self-issued principal role, not external identity or ZKC admission. Production
// qualification, revocation and recipient possession companions remain absent.
//
// =============================================================================
// ZKM Mandate Contract (Aztec.nr) -- Aztec 6.0.0
//
// Expresses the ZKM v2 mandate lifecycle (docs/zkm_specification.md §3-§6) as
// an Aztec-native contract: mandates are private notes; the five non-SPEND
// §4.2 transition kinds (the mandate-only VK's accepted set) are private
// functions; SPEND — §4.2's sixth kind — is a private authorization call
// conjoined with a nested, holder-authwitnessed ZKA transfer in ONE Aztec
// transaction via the kernel call stack (ZKA spec §8.4 / §5.8 pattern).
//
// Transition functions (all #[external("private")], all private-only):
//   issue(recipient, root_id, issuance_key, issuance_randomness, context,
//         asset_id, cap, expiry, policy_hash)                     -- depth 0
//   split(root_id, in_cap, out1_cap, out2_cap)                     -- kind 1
//   retire(root_id, in_cap)                                        -- kind 2
//   delegate_full(root_id, in_cap, delegate, <policy opening>)     -- kind 3
//   delegate_partial(root_id, in_cap, delegate, delegate_cap, <policy opening>) -- kind 4
//   rotate(root_id, in_cap, new_holder)                            -- kind 5
//   spend_authorize(root_id, in_cap, to, amount, authwit_nonce, <policy>) -- kind 0
//
// PLATFORM SUBSTITUTIONS (vs the standalone reference circuits; each is the
// same class of substitution the ZKA Aztec profile documents):
//   - Mandate-tree membership + `mandate_root` recency  -> the protocol note
//     hash tree + kernel read requests (no in-contract Merkle proof).
//   - `nf` + the shared per-context nullifier set       -> protocol nullifier
//     tree; nullifiers derived from the owner's app-siloed keys, NOT
//     zkm_lib's H(DOMAIN, hns, cm, ctx) (see zkm_aztec_lib header).
//   - `current_time` verifier substitution (§4.3-6)     -> context
//     .set_expiration_timestamp(expiry - 1): the rollup refuses to include
//     the transition in any block with timestamp >= expiry, i.e.
//     `current_time < expiry` enforced by the protocol rather than by a
//     public-input convention. PRIVACY COST (named, not free): the tx's
//     expiration timestamp is PUBLIC. The kernel takes the minimum of all
//     set values, and the protocol separately bounds inclusion to ~24h past
//     the anchor block — so the exact expiry is revealed only when it lies
//     inside that window — but since successors inherit `expiry` verbatim,
//     a revealed near-term expiry is a lineage-stable correlator across the
//     delegation subtree (the same §4.6 breach class that got `policy_hash`
//     removed from the reference public vector). The reference circuits
//     keep `expiry` fully private. A deployment-grade profile should
//     coarsen the value (e.g. bucket expiries) instead of passing the
//     exact timestamp; this benchmark passes it exactly.
//   - `settlement_context` public input                 -> PublicImmutable
//     deployment binding, read (privately) and asserted equal to the
//     committed settlement_domain on every consumed mandate.
//   - Holder key + holder-sk derivation                 -> Aztec note
//     ownership (the owner's keys gate nullification); rebinds deliver the
//     successor note to the new owner's address. This gives EXCLUSIVITY
//     (nobody but the target's key-holder can consume the successor) — it
//     does NOT establish that the delegate actually CONTROLS the target
//     address, which is what the §5/§6 possession companion proofs exist
//     for. The §6 delegate-key burn hazard survives the port: a delegator
//     can rebind the full cap to a well-formed address whose keys nobody
//     holds, and DELEGATE is consumptive, so that authority is gone. The
//     only guard here is `_assert_rebinds` (non-zero, != holder) — exactly
//     the check the reference deems insufficient without the companion.
//     Successor-commitment distinctness (§4.3-3: `cm_out_1 != cm_out_2`,
//     `cm != cm_in`) is carried by PROTOCOL NONCE-UNIQUING — every note
//     hash is uniquified with (first nullifier in tx, note index in tx)
//     before insertion — NOT by note randomness, which aztec-nr draws from
//     an unconstrained oracle and which a malicious wallet could reuse.
//
// DELIBERATE TIGHTENING vs the reference (this contract is STRICTER):
//   - `issue` rejects a zero `cap`; the reference issuance statement permits
//     it (`noir/zkm_issuance` test_issuance_of_zero_cap_is_legal — 0 is a
//     legitimate cap value, NOT an absent-field sentinel; §3's zero-sentinel
//     rule deliberately omits `remaining_cap`). Refusing to mint a
//     born-dead mandate cannot make any reference-legal lineage unreachable,
//     since SPLIT can still produce a zero-cap note.
// Positive spends match the rev-13 standalone reference: `spend_authorize`
// and `noir/zkm_spend_conjoined` both reject `amount == 0`. This is no longer
// an Aztec-specific tightening. ZKA's platform-substituted change-note path
// remains different: it omits zero-value ZKA change notes, while standalone
// rev-13 spends always publish both nonzero output commitments.
//
// SUCCESSOR caps, by contrast, may be ZERO here — matching the reference,
// which permits `split(cap, 0, cap)` (test_split_with_zero_side) and
// *requires* a zero-cap successor when a SPEND drains the mandate (a SPEND
// publishing `cm_out_1 = 0` would be "a RETIRE wearing a SPEND's public
// vector"). A zero-cap note is retirable, rotatable, splittable and
// delegable; only `spend_authorize` refuses it (`amount != 0` and
// `amount <= remaining_cap` are jointly unsatisfiable at cap 0). Its only
// extra work is delivering the zero-cap note, which the holder can retire.
// Keep zero-cap successors to support full-drain SPEND and the valid SPLIT
// cases allowed by §4.3-1.
//
// NOT PORTED (documented, deliberately):
//   - The §7.1 depth-254 revocation exclusion accumulator. A private-only
//     transition cannot read mutable public revocation state without either
//     an enqueued public phase (an unmeasured marginal bound of roughly
//     +120k mana, not the gross public-phase total) or a DelayedPublicMutable
//     read (plausibly +0 mana because it adds no transaction effects under the
//     committed model). See docs/benchmarks/zkm_aztec_bench.md §§5 and 1;
//     mapping ZKM revocation onto Aztec state is design work outside this
//     benchmark's scope. Transitions here therefore meter the UNREVOKED path.
//   - §4.3-3 policy NARROWING on successors (this contract preserves
//     policy_hash across every successor, a legal instance of the statement;
//     narrowing changes no note/nullifier counts, so its mana cost is zero by
//     construction -- only proving wall-clock would move, and that is
//     dominated by the kernel stack). The same applies to successor EXPIRY
//     narrowing: the reference permits `expiry <= input.expiry` per
//     successor; `_deliver_successor` hard-inherits the input's expiry, so
//     tightening is unexpressible here (also mana-invisible).
//   - The recipient-allowlist (restricted-policy) spend path; spend_authorize
//     enforces the unrestricted-policy predicate (the EVM benchmark's
//     canonical SPEND-unrestricted class; the EVM harness measured identical
//     settlement gas for both). CONSEQUENCE worth naming: nothing stops a
//     restricted-policy mandate from being issued, split, retired, rotated,
//     or delegated on this deployment (those paths never inspect
//     `recipient_restricted`), but spend_authorize will always refuse it —
//     restricted authority created here is permanently unspendable until the
//     allowlist leg is ported.
//
// CONJOINED SPEND (the §5 spend-conjoined analog): the holder's one top-level
// spend_authorize call computes the ZKA asset commitment from the consumed
// mandate note, reuses the constrained amount wire as the transfer value, and
// invokes the deployment-pinned ZKATransfer.transfer_from as a nested private
// call. The holder's standard single-use authwit authorizes that exact nested
// tuple; the mandate nullifier and ZKA authwit nullifier provide the two
// independent replay barriers. Amount remains private and no bespoke ZKM
// transaction identity is introduced. The restricted-recipient path remains
// deliberately unported, so recipient membership is not yet proven here.
// =============================================================================

mod test;

use aztec::macros::aztec as aztec_contract;

// Application receipt data only: no mandate opening, cap or authority secret.
// Exact UTF-8 zkm/aztec/spend/receipt/v1, right-aligned in one canonical field.
pub global ZKM_SPEND_RECEIPT_DOMAIN: Field = 0x7a6b6d2f617a7465632f7370656e642f726563656970742f7631;
#[aztec_contract]
pub contract ZKMMandate {
    use aztec::{
        macros::{
            events::event,
            functions::{external, initializer, internal, view},
            storage::storage,
        },
        messages::delivery::MessageDelivery,
        note::{note_getter_options::NoteGetterOptions, note_interface::NoteProperties},
        protocol::{address::AztecAddress, traits::ToField},
        state_vars::{Owned, PrivateSet, PublicImmutable},
        utils::comparison::Comparator,
    };

    use crate::ZKM_SPEND_RECEIPT_DOMAIN;
    use aztec::authwit::auth::compute_authwit_message_hash_from_call;
    use zka_transfer_aztec::ZKATransfer;
    use zkm_aztec_lib::{
        assert_fits_u128, assert_fits_u64, assert_fits_u8, compute_issuance_nullifier,
        ZKMMandateNote,
    };
    use zkm_lib::{delegated_depth, StandardPolicyV2};

    #[event]
    pub struct ZKMSpendReceiptV1 {
        pub receipt_domain: Field,
        pub receipt_version: Field,
        pub interaction_context: Field,
        pub settlement_context: Field,
        pub zkm_instance: Field,
        pub zka_instance: Field,
        pub transfer_message_hash: Field,
    }

    // =========================================================================
    // Storage
    // =========================================================================

    #[storage]
    struct Storage<Context> {
        // Per-owner private mandate note set. `mandates.at(owner)` yields that
        // owner's PrivateSet<ZKMMandateNote>.
        mandates: Owned<PrivateSet<ZKMMandateNote, Context>, Context>,
        // The deployment's settlement context (§5). IMMUTABLE by design: a
        // mandate is issued FOR a settlement domain; this contract instance IS
        // one settlement domain, and no admin path may re-point it. Committed
        // into every note's settlement_domain slot and re-asserted on every
        // consume (mirroring verify_input_mandate's authority binding).
        settlement_context: PublicImmutable<Field, Context>,
        // The sole ZKA settlement target this mandate deployment may invoke.
        // Keeping it immutable prevents a wallet or administrator from routing
        // an authorized mandate spend through an impostor transfer contract.
        zka_transfer: PublicImmutable<AztecAddress, Context>,
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    #[external("public")]
    #[initializer]
    fn constructor(settlement_context: Field, zka_transfer: AztecAddress) {
        assert(settlement_context != 0, "Settlement context must be non-zero");
        assert(!zka_transfer.is_zero(), "ZKA transfer address must be non-zero");
        self.storage.settlement_context.initialize(settlement_context);
        self.storage.zka_transfer.initialize(zka_transfer);
    }

    // =========================================================================
    // Issue -- create a root mandate note (depth 0)
    //
    // Principal authority is private preimage knowledge, exactly the base §3
    // statement. The principal need not be the recipient or msg_sender; no
    // external identity, credential or recipient possession claim follows.
    // The kernel binds this call's witnesses to the actual inserted note,
    // including its owner, fields and framework-generated randomness.
    //
    // PLATFORM TIGHTENING: one original issuance per root ceremony per
    // deployment. Fresh grants MUST use fresh issuance_randomness. A separate
    // persistent nullifier prevents re-minting even after the origin is spent
    // or retired, and cannot be evaded by changing recipient or note fields.
    // It uses the private preimage, not the revocation-disclosed root_id.
    // Protocol note nonce-uniquing alone would permit duplicate authority.
    // =========================================================================

    #[external("private")]
    fn issue(
        recipient: AztecAddress,
        root_id: Field,
        principal_issuance_key: Field,
        issuance_randomness: Field,
        settlement_context: Field,
        asset_id: Field,
        cap: Field,
        expiry: Field,
        policy_hash: Field,
    ) {
        assert(principal_issuance_key != 0, "principal issuance key must be non-zero");
        assert(!recipient.is_zero(), "recipient must be non-zero");
        assert(root_id != 0, "root_id must be non-zero");
        assert(
            root_id
                == zkm_lib::compute_mandate_root_id(principal_issuance_key, issuance_randomness),
            "root_id must match principal issuance authority",
        );
        assert(asset_id != 0, "asset_id must be non-zero (zero is the reserved sentinel)");
        assert(policy_hash != 0, "policy_hash must be non-zero (zero is the reserved sentinel)");
        assert(cap != 0, "cap must be non-zero");
        assert(expiry != 0, "expiry must be non-zero");
        assert_fits_u128(cap);
        assert_fits_u64(expiry);

        let settlement_domain = self.storage.settlement_context.read();
        assert(
            settlement_context == settlement_domain,
            "issuance context must match the deployment",
        );
        // Safety: a separate domain prevents collision with note/authwit
        // nullifiers; the kernel contract-silos it. Do not include mutable
        // mandate fields here: doing so would permit re-issuing the same root.
        let issuance_nullifier = compute_issuance_nullifier(
            principal_issuance_key,
            issuance_randomness,
            settlement_domain,
        );
        assert(issuance_nullifier != 0, "issuance nullifier must be non-zero");
        self.context.push_nullifier_unsafe(issuance_nullifier);
        let note = ZKMMandateNote::new(
            root_id,
            settlement_domain,
            asset_id,
            cap,
            expiry,
            policy_hash,
            0, // depth 0 at issuance (§3)
        );
        self.storage.mandates.at(recipient).insert(note).deliver(
            MessageDelivery::onchain_constrained(),
        );
    }

    // =========================================================================
    // SPLIT (kind 1) -- two children, same holder, same depth (§4.3-1)
    // =========================================================================

    #[external("private")]
    fn split(root_id: Field, in_cap: Field, out1_cap: Field, out2_cap: Field) {
        let owner = self.msg_sender();
        let note = self.internal._consume(owner, root_id, in_cap);

        // Cap conservation: out1 + out2 == in (u128 arithmetic; each side
        // bounded, so the add cannot silently wrap).
        assert_fits_u128(out1_cap);
        assert_fits_u128(out2_cap);
        assert(
            (out1_cap as u128) + (out2_cap as u128) == (note.remaining_cap as u128),
            "split must conserve the cap exactly",
        );

        // Two successors to the same holder at the same depth, policy and
        // expiry preserved. Distinctness (§4.3-3) is carried by protocol
        // nonce-uniquing of note hashes (see the header).
        self.internal._deliver_successor(owner, note, out1_cap, note.depth);
        self.internal._deliver_successor(owner, note, out2_cap, note.depth);
    }

    // =========================================================================
    // RETIRE (kind 2) -- destroy remaining authority; no successors (§4.3-1)
    // =========================================================================

    #[external("private")]
    fn retire(root_id: Field, in_cap: Field) {
        let owner = self.msg_sender();
        let _note = self.internal._consume(owner, root_id, in_cap);
        // Authority destroyed, never spent: no successor notes.
    }

    // =========================================================================
    // DELEGATE_FULL (kind 3) -- one child at the delegate's address, depth+1;
    // delegator retains nothing (§6)
    // =========================================================================

    #[external("private")]
    fn delegate_full(
        root_id: Field,
        in_cap: Field,
        delegate: AztecAddress,
        policy_version: Field,
        policy_max_per_spend: Field,
        policy_recipient_restricted: Field,
        policy_recipient_set_root: Field,
        policy_depth_limit: Field,
        policy_blinding: Field,
    ) {
        let owner = self.msg_sender();
        let note = self.internal._consume(owner, root_id, in_cap);

        self.internal._assert_rebinds(owner, delegate);

        // Depth budget: +1 with the VK-baked DEPTH_MAX ceiling (zkm_lib), then
        // the per-mandate policy delegation gate (§6): opens the committed
        // policy; v1 permits, v2 asserts successor_depth <= depth_limit.
        let out_depth = delegated_depth(note.depth as u8);
        let policy = self.internal._policy_carrier(
            policy_version,
            policy_max_per_spend,
            policy_recipient_restricted,
            policy_recipient_set_root,
            policy_depth_limit,
            policy_blinding,
        );
        zkm_lib::assert_policy_permits_delegation(policy, note.policy_hash, out_depth);

        // Full cap rebinds to the delegate; nothing retained.
        self.internal._deliver_successor(delegate, note, note.remaining_cap, out_depth as Field);
    }

    // =========================================================================
    // DELEGATE_PARTIAL (kind 4) -- a SPLIT where exactly ONE successor rebinds:
    // successor 1 to the delegate at depth+1, successor 2 retained by the
    // delegator at unchanged depth (§6)
    // =========================================================================

    #[external("private")]
    fn delegate_partial(
        root_id: Field,
        in_cap: Field,
        delegate: AztecAddress,
        delegate_cap: Field,
        policy_version: Field,
        policy_max_per_spend: Field,
        policy_recipient_restricted: Field,
        policy_recipient_set_root: Field,
        policy_depth_limit: Field,
        policy_blinding: Field,
    ) {
        let owner = self.msg_sender();
        let note = self.internal._consume(owner, root_id, in_cap);

        self.internal._assert_rebinds(owner, delegate);

        // Cap conservation across the two successors.
        assert_fits_u128(delegate_cap);
        assert(
            (delegate_cap as u128) <= (note.remaining_cap as u128),
            "delegated cap exceeds the remaining cap",
        );
        let retained_cap = note.remaining_cap - delegate_cap;

        let out_depth = delegated_depth(note.depth as u8);
        let policy = self.internal._policy_carrier(
            policy_version,
            policy_max_per_spend,
            policy_recipient_restricted,
            policy_recipient_set_root,
            policy_depth_limit,
            policy_blinding,
        );
        zkm_lib::assert_policy_permits_delegation(policy, note.policy_hash, out_depth);

        // Successor 1: the delegate's share at depth+1. Successor 2: the
        // retained share back to the delegator at unchanged depth.
        self.internal._deliver_successor(delegate, note, delegate_cap, out_depth as Field);
        self.internal._deliver_successor(owner, note, retained_cap, note.depth);
    }

    // =========================================================================
    // ROTATE (kind 5) -- one child, full cap, new address, SAME depth; no
    // policy gate, no depth budget (§6: unrestricted clean handoff)
    // =========================================================================

    #[external("private")]
    fn rotate(root_id: Field, in_cap: Field, new_holder: AztecAddress) {
        let owner = self.msg_sender();
        let note = self.internal._consume(owner, root_id, in_cap);

        self.internal._assert_rebinds(owner, new_holder);

        // Full cap to the new address at unchanged depth.
        self.internal._deliver_successor(new_holder, note, note.remaining_cap, note.depth);
    }

    // =========================================================================
    // SPEND authorization (kind 0 leg of the spend-conjoined form)
    //
    // Consumes the mandate, enforces the §4.3-2 cap bound and the §5 policy
    // ceiling (unrestricted path), and re-issues the successor mandate with
    // remaining_cap - amount, then invokes the pinned ZKA transfer as a nested
    // private call. The asset commitment and transfer value are computed from
    // wires constrained by this circuit; the wallet can no longer choose a
    // mismatched sibling-call tuple.
    // =========================================================================

    #[external("private")]
    fn spend_authorize(
        root_id: Field,
        in_cap: Field,
        to: AztecAddress,
        amount: Field,
        authwit_nonce: Field,
        policy_version: Field,
        policy_max_per_spend: Field,
        policy_recipient_restricted: Field,
        policy_recipient_set_root: Field,
        policy_depth_limit: Field,
        policy_blinding: Field,
    ) {
        // Retained benchmark entry point. Consumer receipt discovery selects
        // spend_authorize_receipted and cannot infer an event from this call.
        let _message_hash = self.internal._authorize_spend(
            root_id,
            in_cap,
            to,
            amount,
            authwit_nonce,
            policy_version,
            policy_max_per_spend,
            policy_recipient_restricted,
            policy_recipient_set_root,
            policy_depth_limit,
            policy_blinding,
        );
    }

    /// Reference consumer entry point: authorize and transfer in one kernel
    /// call stack, then publish a recipient-encrypted composition receipt.
    /// The measurement-only restrictions in the contract header still apply.
    #[external("private")]
    fn spend_authorize_receipted(
        root_id: Field,
        in_cap: Field,
        to: AztecAddress,
        amount: Field,
        authwit_nonce: Field,
        policy_version: Field,
        policy_max_per_spend: Field,
        policy_recipient_restricted: Field,
        policy_recipient_set_root: Field,
        policy_depth_limit: Field,
        policy_blinding: Field,
        interaction_context: Field,
    ) {
        assert(interaction_context != 0, "receipt interaction context must be non-zero");
        assert(authwit_nonce == interaction_context, "receipt context must equal authwit nonce");
        let transfer_message_hash = self.internal._authorize_spend(
            root_id,
            in_cap,
            to,
            amount,
            authwit_nonce,
            policy_version,
            policy_max_per_spend,
            policy_recipient_restricted,
            policy_recipient_set_root,
            policy_depth_limit,
            policy_blinding,
        );
        // This constrained private event is reachable only after the exact
        // nested ZKA transfer returns successfully. The kernel siloes its
        // commitment to this contract and includes it atomically with effects.
        self
            .emit(
                ZKMSpendReceiptV1 {
                    receipt_domain: ZKM_SPEND_RECEIPT_DOMAIN,
                    receipt_version: 1,
                    interaction_context,
                    settlement_context: self.storage.settlement_context.read(),
                    zkm_instance: self.address.to_field(),
                    zka_instance: self.storage.zka_transfer.read().to_field(),
                    transfer_message_hash,
                },
            )
            .deliver_to(to, MessageDelivery::onchain_constrained());
    }

    #[internal("private")]
    fn _authorize_spend(
        root_id: Field,
        in_cap: Field,
        to: AztecAddress,
        amount: Field,
        authwit_nonce: Field,
        policy_version: Field,
        policy_max_per_spend: Field,
        policy_recipient_restricted: Field,
        policy_recipient_set_root: Field,
        policy_depth_limit: Field,
        policy_blinding: Field,
    ) -> Field {
        let owner = self.msg_sender();
        let note = self.internal._consume(owner, root_id, in_cap);

        // §4.3-2: the spend amount is bounded by the remaining cap.
        assert(amount != 0, "Spend amount must be non-zero");
        assert_fits_u128(amount);
        assert(
            (amount as u128) <= (note.remaining_cap as u128),
            "spend amount exceeds the remaining cap",
        );

        // §5 policy ceiling, unrestricted path: open the committed policy and
        // enforce the per-spend ceiling. The recipient-allowlist (restricted)
        // path is deliberately unported (file header).
        let policy = self.internal._policy_carrier(
            policy_version,
            policy_max_per_spend,
            policy_recipient_restricted,
            policy_recipient_set_root,
            policy_depth_limit,
            policy_blinding,
        );
        zkm_lib::assert_policy_opens(policy, note.policy_hash);
        assert(
            policy.recipient_restricted == 0,
            "restricted-recipient policies are not supported by this contract",
        );
        assert(
            (amount as u128) <= policy.max_per_spend,
            "spend amount exceeds the policy per-spend ceiling",
        );

        // Successor mandate: remaining authority back to the holder, same
        // depth, policy and expiry preserved (§4.3 SPEND row).
        let successor_cap = note.remaining_cap - amount;
        self.internal._deliver_successor(owner, note, successor_cap, note.depth);

        let asset_commitment = zkm_lib::compute_zka_asset_commitment(note.asset_id);
        let zka_transfer = self.storage.zka_transfer.read();
        let transfer_call = ZKATransfer::at(zka_transfer).transfer_from(
            owner,
            to,
            asset_commitment,
            amount,
            authwit_nonce,
        );
        // Derive the receipt binding from the SAME generated call object that
        // is executed below. No caller-supplied digest can choose another tuple.
        let transfer_message_hash = compute_authwit_message_hash_from_call(
            self.address,
            transfer_call.target_contract,
            self.context.chain_id(),
            self.context.version(),
            transfer_call.selector,
            transfer_call.args,
        );
        self.call(transfer_call);
        transfer_message_hash
    }

    // =========================================================================
    // Private internals
    // =========================================================================

    /// Pop exactly ONE of `owner`'s mandate notes matching (root_id,
    /// remaining_cap), enforce the shared input-side bindings, and return it.
    /// The ordering mirrors `verify_input_mandate` for settlement binding,
    /// sentinels, and temporal validity, but deliberately omits its intervening
    /// non-revocation step as disclosed in the contract-level NOT PORTED list.
    ///
    /// Selection by (root_id, remaining_cap) disambiguates siblings that share
    /// a root_id (e.g. SPLIT children); the benchmark state plans keep that
    /// pair unique per owner. The popped note's fields are constrained by the
    /// kernel's note-read machinery (membership) and the NoteHash scheme
    /// (commitment preimage), so asserting over them is sound.
    #[internal("private")]
    fn _consume(owner: AztecAddress, root_id: Field, in_cap: Field) -> ZKMMandateNote {
        let options = NoteGetterOptions::new()
            .select(ZKMMandateNote::properties().root_id, Comparator.EQ, root_id)
            .select(ZKMMandateNote::properties().remaining_cap, Comparator.EQ, in_cap)
            .set_limit(1);
        let notes = self.storage.mandates.at(owner).pop_notes(options);
        assert(notes.len() == 1, "Mandate note not found");
        let note = notes.get(0);

        // Authority binding (§5): the committed settlement_domain must equal
        // THIS deployment's settlement context. Every note this contract
        // creates satisfies it by construction; the assert mirrors
        // verify_input_mandate's ordering as defense in depth.
        assert(
            note.settlement_domain == self.storage.settlement_context.read(),
            "mandate is bound to a different settlement domain",
        );

        // Zero-reserved sentinels (§3).
        assert(note.asset_id != 0, "asset_id must be non-zero");
        assert(note.policy_hash != 0, "policy_hash must be non-zero");

        // §4.3-6 temporal validity, platform-substituted: the rollup rejects
        // inclusion in any block with timestamp > expiry - 1, i.e. the
        // transition settles only while current_time < expiry.
        assert_fits_u64(note.expiry);
        self.context.set_expiration_timestamp((note.expiry as u64) - 1);

        note
    }

    /// §6 rebind guard: a rebinding successor must land at a non-zero
    /// address that differs from the current holder. Note this does NOT
    /// establish that anyone controls the target address — see the header's
    /// delegate-key burn hazard.
    #[internal("private")]
    fn _assert_rebinds(owner: AztecAddress, new_holder: AztecAddress) {
        assert(!new_holder.is_zero(), "rebind target must be non-zero");
        assert(new_holder != owner, "rebind target must differ from the current holder");
    }

    /// Deliver a successor mandate note: root_id / settlement_domain /
    /// asset_id / policy_hash / expiry inherited from the consumed input
    /// (§4.3-3 preservation), cap and depth per the kind.
    #[internal("private")]
    fn _deliver_successor(to: AztecAddress, input: ZKMMandateNote, cap: Field, depth: Field) {
        assert_fits_u128(cap);
        assert_fits_u8(depth);
        let successor = ZKMMandateNote::new(
            input.root_id,
            input.settlement_domain,
            input.asset_id,
            cap,
            input.expiry,
            input.policy_hash,
            depth,
        );
        self.storage.mandates.at(to).insert(successor).deliver(
            MessageDelivery::onchain_constrained(),
        );
    }

    /// Build the version-agnostic policy carrier from raw Field args (bounds
    /// asserted before every typed cast).
    #[internal("private")]
    fn _policy_carrier(
        version: Field,
        max_per_spend: Field,
        recipient_restricted: Field,
        recipient_set_root: Field,
        depth_limit: Field,
        blinding: Field,
    ) -> StandardPolicyV2 {
        assert_fits_u128(max_per_spend);
        assert_fits_u8(depth_limit);
        StandardPolicyV2 {
            version,
            max_per_spend: max_per_spend as u128,
            recipient_restricted,
            recipient_set_root,
            depth_limit: depth_limit as u8,
            policy_blinding: blinding,
        }
    }

    // =========================================================================
    // View / Utility Functions
    // =========================================================================

    /// The deployment's settlement context (public state).
    #[external("public")]
    #[view]
    fn get_settlement_context() -> pub Field {
        self.storage.settlement_context.read()
    }

    /// The immutable ZKA settlement target used by every conjoined spend.
    #[external("public")]
    #[view]
    fn get_zka_transfer() -> pub AztecAddress {
        self.storage.zka_transfer.read()
    }

    /// Count an owner's mandate notes for a root_id (utility / off-chain,
    /// used by tests and the benchmark state plans). NoteViewerOptions pages
    /// at MAX_NOTES_PER_PAGE (10) and this view does not page, so it silently
    /// under-reports beyond ten notes per owner — fine for the <=3-note test
    /// and bench states, not a general accounting surface.
    #[external("utility")]
    unconstrained fn get_mandate_count(owner: AztecAddress, root_id: Field) -> pub Field {
        let options = aztec::note::note_viewer_options::NoteViewerOptions::new();
        let notes = self.storage.mandates.at(owner).view_notes(options);
        let mut count: Field = 0;
        for i in 0..notes.len() {
            let note = notes.get_unchecked(i);
            if note.root_id == root_id {
                count += 1;
            }
        }
        count
    }

    /// Sum an owner's remaining caps for a root_id (utility / off-chain).
    /// The §4.1 conservation view: SPLIT/DELEGATE_PARTIAL preserve this sum
    /// across an owner pair; RETIRE and SPEND reduce it. Same ten-note
    /// paging truncation as get_mandate_count above.
    #[external("utility")]
    unconstrained fn get_total_cap(owner: AztecAddress, root_id: Field) -> pub Field {
        let options = aztec::note::note_viewer_options::NoteViewerOptions::new();
        let notes = self.storage.mandates.at(owner).view_notes(options);
        let mut total: Field = 0;
        for i in 0..notes.len() {
            let note = notes.get_unchecked(i);
            if note.root_id == root_id {
                total += note.remaining_cap;
            }
        }
        total
    }
}
