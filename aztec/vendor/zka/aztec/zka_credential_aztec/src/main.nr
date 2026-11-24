// =============================================================================
// ZKA Credential Contract (Aztec.nr) -- aztec-nr v6.0.0
//
// Wraps ZKA's credential binding and selective disclosure as an Aztec contract
// with composable compliance features.
//
// Core credential operations:
//   bind_credential(data, attributes, sig)       -- Bind an issuer-signed credential
//   prove_disclosure(mask, context)              -- Generic selective disclosure
//   disclose_to(recipient, mask, context)        -- Disclose to specific party
//
// Named compliance proofs (composable with transfers in single tx):
//   prove_kyc(context)                           -- Disclose KYC status (attr 0)
//   prove_jurisdiction(context)                  -- Disclose jurisdiction (attr 1)
//   prove_source_of_funds(context)               -- Disclose source of funds (attr 2)
//   aggregate_disclosures(mask_a, mask_b, ctx)   -- Combine two disclosure proofs
//
// Compliance-gated accounts:
//   verify_compliance()                  -- Prove issued credential + register compliant
//   assert_compliant(owner)              -- Private view: gate check, owner not published
//   is_compliant(owner)                  -- Public: check compliance status
//
// Revocation:
//   revoke(cc)                           -- Admin: revoke credential
//   is_revoked(cc)                       -- Public: check revocation status
//
// ISSUER AUTHENTICATION:
//   The constructor pins one issuer key (secp256k1, the ZKC mandatory issuer
//   signature profile); there is no setter, so a new issuer means a new
//   deployment. bind_credential stores a credential only with that issuer's
//   ECDSA signature over zka_aztec_lib::issuance_digest(chain_id, version,
//   this contract, holderCommitment, credential_data, attributes). The
//   contract derives holderCommitment from the caller's own key, so a
//   signature binds one holder in one contract instance on one chain, and the
//   issuer learns holderCommitment but not the holder's Aztec address. Only
//   such originator notes count as credentials: verify_compliance and every
//   disclosure load the caller's note with context == 0 and the caller's own
//   commitment, never a disclose_to note.
//   This is issuer authentication for this contract, not ZKC verification:
//   there is no ZKC proof, presentation profile, issuer registry, accumulator,
//   or validity window here. A credential stays usable until the admin
//   revokes its holderCommitment.
//
// PUBLIC OUTPUTS (ZKA SS5.8):
//   credential_commitment is the ZKC holderCommitment = H("zkc/binding", cbk),
//   the GLOBAL linkable holder anchor that ZKC's scoped and anonymous profiles
//   keep out of presentations. It is NOT a pseudonym. No function that a holder
//   calls may publish it next to the holder's address.
//   - verify_compliance() checks non-revocation PRIVATELY (nullifier
//     non-inclusion at the anchor block) and publishes ONLY the owner address
//     (the enqueued _register_compliance argument). The registry is public by
//     design: is_compliant(owner) reveals that an address registered.
//   - revoke(cc) publishes cc: a revocation is a public statement by the admin
//     about that holder anchor. This contract links it to no holder address
//     (the revoke tx carries only the admin's). Anyone who already knows cc
//     (e.g. from a linkable zkc:proof:v1 presentation) can test is_revoked(cc).
//   - assert_compliant(owner) is a private view for the transfer gate. It reads
//     compliance_set in private, so the recipient is not a public argument.
//   - disclose_to(recipient, ...) delivers a CredNote that carries cc to the
//     recipient. That is not public, but the recipient learns the global
//     anchor, so two recipients can link the holder. Use ZKC scoped
//     presentations where cross-verifier unlinkability matters.
//   - Residual (node): a private read asks the PXE's node for a witness of
//     the queried key. For verify_compliance that is the siloed revocation
//     nullifier, which anyone who knows cc can compute, and the same node
//     usually relays the tx that publishes the owner address. The node can
//     therefore pair cc with the registrant, and on a gated transfer it learns
//     the recipient. Use a node you trust, as for any Aztec private read.
//
// v0.6.0 SS5.2 CONTEXT BINDING (replay protection; canonical model, docs/adr/0001):
//   Every disclosure entry point takes a caller-supplied
//   context = H(verifierId, sessionId, timestamp) computed off-chain, and
//   asserts it is non-zero. context is a SEPARATE, co-equal binding -- it is
//   NOT folded into the disclosed hash. The returned value is the RAW
//   context-INDEPENDENT disclosed hash (compute_disclosed_hash), byte-identical
//   to the standalone circuit's disclosed_attribute_hash (the cross-environment
//   equality guarantee). Replay protection comes from context being a
//   CONSTRAINED ARGUMENT of the proof: a consumer that received a disclosure
//   value from a call made with a given context can trust the correspondence by
//   the call proof. This mirrors the standalone circuit (where context is a
//   public input bound to the proof) and the ZKC claimBinding model. This
//   conforms to the normative SS5.2 specification. verify_compliance() takes no context: it registers
//   compliance in public state (a separate trust boundary), disclosing no
//   attribute values.
//
//   WIRE CONTRACT FOR `disclose_to`: the recipient-delivered CredNote carries
//   the RAW disclosed hash in `credential_data` (context-independent, equal
//   across environments) and the SS5.2 session in the SEPARATE `context` field.
//   Recipients read both: credential_data identifies the disclosure, context
//   identifies the session. This is NOT the originator's secret (that lives only
//   in the bind_credential note, whose context field is 0). The two note shapes
//   are disambiguated by which entry point produced the note. See
//   zka_aztec_lib::CredNote for the type definition.
//
// Aztec-native features:
//   - Encrypted note logs for credential storage (ONCHAIN_CONSTRAINED delivery)
//   - Off-chain decryption via PXE
//   - App-siloed key derivation for credential binding
//   - Compliance registry in DelayedPublicMutable (private reads)
//   - Revocation as contract-siloed nullifiers (private non-inclusion proofs)
//
// v0.6.0 SS1.6 SAFEGUARD 3 CONFORMANCE (reviewed):
//   The only privileged function here is `revoke`; the only admin state is
//   `admin` + the revocation nullifiers. The pinned issuer key is immutable
//   and gates only the creation of new credential notes, never an existing
//   note. Safeguard 3 requires ZKA NOTE
//   validity to depend solely on cryptographic properties -- no admin key may
//   invalidate, freeze, redirect, or force-transfer a note. `revoke` satisfies
//   this: it ONLY emits the revocation nullifier for cc and has NO code path to
//   any credential note's validity -- credential notes live in per-owner
//   PrivateSets and are never read or nullified by revoke. The emitted inner
//   nullifier is revocation_nullifier(cc) = H2("zka/aztec/revocation/v1", cc)
//   (Poseidon2 operational domain zka-aztec-revocation-v1), so the admin can
//   only produce values in that domain: equalling a CredNote nullifier, an
//   initialization nullifier, or any future nullifier of this contract would
//   need a Poseidon2 preimage. Per SS5.6
//   the sole consequence of revocation is COUNTERPARTY REFUSAL: a revoked
//   credential fails verify_compliance / non-revocation checks; it is never
//   note invalidation. There are no pausable or upgradeable paths. These
//   invariants are locked in by the revoke_* tests in src/test.nr.
//
//   verify_compliance() registers compliance in PUBLIC state after a credential
//   proof and deliberately takes no SS5.2 context: it discloses no attribute
//   values (a separate trust boundary from disclosure proofs). Cross-environment
//   binding alignment for disclosure proofs is tracked separately in
//   the standalone disclosure-binding review.
// =============================================================================

mod test;

use aztec::macros::aztec;

#[aztec]
pub contract ZKACredential {
    use aztec::{
        history::nullifier::assert_nullifier_did_not_exist_by,
        keys::getters::get_public_keys,
        macros::{functions::{external, initializer, internal, only_self, view}, storage::storage},
        messages::delivery::MessageDelivery,
        note::{note_getter_options::NoteGetterOptions, note_interface::NoteProperties},
        oracle::nullifiers::check_nullifier_exists,
        protocol::{
            address::AztecAddress, constants::MAX_TX_LIFETIME, hash::compute_siloed_nullifier,
            traits::ToField,
        },
        state_vars::{DelayedPublicMutable, Map, Owned, PrivateSet, PublicImmutable, PublicMutable},
        utils::comparison::Comparator,
    };

    use zka_aztec_lib::{
        aggregate_disclosed_hashes, compute_disclosed_hash, CredNote, derive_zka_cbk,
        issuance_digest, IssuerKey, MASK_JURISDICTION, MASK_KYC, MASK_SOURCE_OF_FUNDS,
        revocation_nullifier, verify_issuer_signature,
    };
    use zka_lib;

    /// Delay before a compliance registration takes effect. With no pending
    /// change, a private read of a DelayedPublicMutable caps the tx expiration
    /// at anchor + delay - 1. With the delay equal to MAX_TX_LIFETIME that is the
    /// same cap the kernel already applies to every private call (the contract
    /// instance registry horizon, DEFAULT_UPDATE_DELAY = MAX_TX_LIFETIME), so a
    /// gated transfer's expiration does not differ from a plain transfer's.
    /// A shorter delay would mark every gated transfer.
    pub global COMPLIANCE_DELAY: u64 = MAX_TX_LIFETIME;

    /// Maximum age of the anchor block of a verify_compliance tx. It bounds the
    /// revocation lag, and it bounds the window in which a registration that
    /// is anchored before a public revoke(cc) but included after it stands out
    /// as a candidate holder of cc. The tx is publicly a registration already
    /// (it enqueues _register_compliance), so the shorter expiration costs no
    /// privacy.
    global REGISTRATION_MAX_ANCHOR_AGE: u64 = 3600;

    // =========================================================================
    // Storage
    // =========================================================================

    #[storage]
    struct Storage<Context> {
        /// Admin address (can revoke credentials)
        admin: PublicMutable<AztecAddress, Context>,
        /// Pinned credential issuer key, set once by the constructor. Read in
        /// private by bind_credential; there is no setter.
        issuer: PublicImmutable<IssuerKey, Context>,
        /// Credential notes per owner. `credentials.at(owner)` yields that
        /// owner's PrivateSet<CredNote>. `CredNote::new` takes no `owner`:
        /// the owner is framework metadata supplied via the storage-slot key
        /// passed to `credentials.at(owner)`.
        credentials: Owned<PrivateSet<CredNote, Context>, Context>,
        /// Compliance registry: address -> compliant (public state, private
        /// reads). Addresses registered here proved, at registration time, that
        /// they held a non-revoked credential. Revocation never removes an
        /// entry. The transfer gate reads it in private via assert_compliant, so
        /// the recipient is not published.
        compliance_set: Map<Field, DelayedPublicMutable<bool, COMPLIANCE_DELAY, Context>, Context>,
        // Revocation has no storage variable: revoke(cc) emits cc as a nullifier
        // siloed to this contract, and verify_compliance proves its
        // non-inclusion in private.
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    #[external("public")]
    #[initializer]
    fn constructor(admin: AztecAddress, issuer: IssuerKey) {
        assert(!issuer.is_zero(), "Issuer key must be set");
        self.storage.admin.write(admin);
        self.storage.issuer.initialize(issuer);
    }

    // =========================================================================
    // Bind Credential -- Store an issuer-signed credential
    //
    // Derives credential_binding_key from the caller's app-siloed nsk,
    // computes credential_commitment = derive_credential_commitment(cbk),
    // verifies the pinned issuer's signature over the issuance transcript of
    // (chain_id, version, this contract, credential_commitment,
    // credential_data, attributes), and stores a CredNote with the credential
    // data and attributes.
    //
    // Issuance flow (off-chain): the holder's wallet derives
    // credential_commitment for this contract and sends it to the issuer; the
    // issuer checks the holder (e.g. KYC), then signs issuance_digest(...) and
    // returns credential_data, attributes and the signature. The issuer never
    // sees the holder's Aztec address. A signature for another holder, another
    // contract instance, another chain, or other values fails here.
    //
    // Attribute convention:
    //   [0] KYC status/level
    //   [1] Jurisdiction code
    //   [2] Source of funds verification
    //   [3] Accreditation/qualification
    // =========================================================================

    #[external("private")]
    fn bind_credential(credential_data: Field, attributes: [Field; 4], issuer_signature: [u8; 64]) {
        let owner = self.msg_sender();

        // Derive credential binding key from app-siloed nsk.
        let owner_npk_m_hash = get_public_keys(owner).npk_m_hash;
        let nsk_app = self.context.request_nhk_app(owner_npk_m_hash);

        // ZKA credential key derivation (matches standalone circuit).
        let cbk = derive_zka_cbk(nsk_app);
        let credential_commitment = zka_lib::derive_credential_commitment(cbk);

        // Issuer authentication: the pinned issuer must have signed exactly
        // this holder commitment and these values for this contract and chain.
        let digest = issuance_digest(
            self.context.chain_id(),
            self.context.version(),
            self.address,
            credential_commitment,
            credential_data,
            attributes,
        );
        assert(
            verify_issuer_signature(self.storage.issuer.read(), issuer_signature, digest),
            "Credential is not signed by the pinned issuer",
        );

        // Create and store the credential note. `notes.at(owner)` supplies the
        // owner to the framework.
        // context = 0: this is the originator credential note, not a session
        // disclosure (docs/adr/0001).
        let cred_note = CredNote::new(credential_commitment, credential_data, 0, attributes);

        self.storage.credentials.at(owner).insert(cred_note).deliver(
            MessageDelivery::onchain_constrained(),
        );
    }

    // =========================================================================
    // Prove Disclosure -- Generic selective disclosure proof
    //
    // The mask is a 4-bit bitmask (big-endian):
    //   bit 0 (MSB) -> attributes[0] (KYC)
    //   bit 1       -> attributes[1] (jurisdiction)
    //   bit 2       -> attributes[2] (source of funds)
    //   bit 3 (LSB) -> attributes[3] (accreditation)
    //
    // `context` is the v0.6.0 SS5.2 session-binding scalar, computed off-chain
    // by the caller as H(verifierId, sessionId, timestamp). It MUST be non-zero
    // (replay protection) and binds the proof as a constrained argument; it is a
    // SEPARATE co-equal binding, NOT folded into the returned hash (docs/adr/0001).
    //
    // Returns the RAW, context-INDEPENDENT disclosed_attribute_hash
    // (compute_disclosed_hash) -- byte-identical to the standalone circuit's
    // public input [1], the cross-environment equality guarantee. The same mask
    // therefore returns the same hash regardless of context; the session binding
    // is carried by the `context` argument (and, for disclose_to, the note's
    // separate context field), not by the hash value.
    // =========================================================================

    #[external("private")]
    fn prove_disclosure(attribute_mask: Field, context: Field) -> Field {
        self.internal._prove_disclosure(self.msg_sender(), attribute_mask, context)
    }

    // =========================================================================
    // Named Compliance Disclosure Functions
    //
    // Convenience wrappers over the disclosure logic with predefined masks.
    // Composable with private transfers in a single Aztec tx -- the kernel
    // proves both the disclosure and the transfer atomically.
    //
    // Usage in an atomic tx:
    //   1. ZKACredential.prove_kyc(context)   -> returns kyc_hash (bound to ctx)
    //   2. ZKATransfer.transfer(to, asset, v) -> transfer executes
    //   Both calls are in the same tx; kernel proves both.
    //
    // These wrappers call the shared `_prove_disclosure` helper directly in the
    // same private frame rather than recursively self-calling
    // ZKACredential::at(this): a self-call is a true cross-contract call and
    // resets msg_sender to this contract, so the helper would load the wrong
    // credential (see `_prove_disclosure`); the in-frame call also avoids the
    // proving overhead of a nested contract call.
    // =========================================================================

    /// Prove KYC compliance -- discloses attributes[0] (KYC status/level).
    #[external("private")]
    fn prove_kyc(context: Field) -> Field {
        self.internal._prove_disclosure(self.msg_sender(), MASK_KYC, context)
    }

    /// Prove jurisdiction -- discloses attributes[1] (jurisdiction code).
    #[external("private")]
    fn prove_jurisdiction(context: Field) -> Field {
        self.internal._prove_disclosure(self.msg_sender(), MASK_JURISDICTION, context)
    }

    /// Prove source of funds -- discloses attributes[2] (SoF verification).
    #[external("private")]
    fn prove_source_of_funds(context: Field) -> Field {
        self.internal._prove_disclosure(self.msg_sender(), MASK_SOURCE_OF_FUNDS, context)
    }

    // =========================================================================
    // Aggregate Disclosures -- Combine two disclosure proofs under one context
    //
    // Produces a single commitment over two separate disclosure hashes.
    // Useful for multi-attribute compliance (e.g., KYC + jurisdiction).
    //
    // Both inner disclosures share the SAME `context` (the caller is proving a
    // combined disclosure for one verifier session); each is asserted non-zero
    // and binds the proof as a constrained argument (docs/adr/0001). The
    // aggregation is over the RAW context-independent halves:
    //   aggregate_disclosed_hashes(
    //       prove_disclosure(mask_a, context),   // raw hash for mask_a
    //       prove_disclosure(mask_b, context),   // raw hash for mask_b
    //   )
    // The aggregate is thus also context-independent in value; the session is
    // bound by the `context` argument, not folded into the hashes.
    // =========================================================================

    #[external("private")]
    fn aggregate_disclosures(mask_a: Field, mask_b: Field, context: Field) -> Field {
        let owner = self.msg_sender();
        let raw_a = self.internal._prove_disclosure(owner, mask_a, context);
        let raw_b = self.internal._prove_disclosure(owner, mask_b, context);
        aggregate_disclosed_hashes(raw_a, raw_b)
    }

    // =========================================================================
    // Disclose To -- Selective disclosure to a specific recipient
    //
    // Same as prove_disclosure but additionally inserts a credential note for
    // the recipient holding the disclosed (masked) attributes and delivers the
    // encrypted log to that recipient. `context` (non-zero) enforces the SS5.2
    // binding here too: the resulting note carries the masked attributes and the
    // RAW disclosed hash in credential_data, with the session in the SEPARATE
    // context field, so the recipient can verify which disclosure was made and
    // for which session (docs/adr/0001).
    // =========================================================================

    #[external("private")]
    fn disclose_to(recipient: AztecAddress, attribute_mask: Field, context: Field) {
        let owner = self.msg_sender();

        assert(context != 0, "Context must be non-zero for replay protection");

        // Load credential + verify commitment (shared with _prove_disclosure /
        // verify_compliance via _verify_credential).
        let cred = self.internal._verify_credential(owner);

        // Decompose mask (big-endian, matching the standalone circuit).
        let mask_bits: [bool; 4] = attribute_mask.to_be_bits::<4>();

        let attributes = cred.get_attributes();
        let disclosed_attrs: [Field; 4] = [
            if mask_bits[0] { attributes[0] } else { 0 },
            if mask_bits[1] { attributes[1] } else { 0 },
            if mask_bits[2] { attributes[2] } else { 0 },
            if mask_bits[3] { attributes[3] } else { 0 },
        ];

        // Compute the RAW (context-independent) disclosed hash and store it in
        // the recipient note's credential_data slot, with `context` carried as a
        // SEPARATE note field (docs/adr/0001, Option A). The raw hash is
        // byte-identical to the standalone circuit's disclosed_attribute_hash
        // (cross-env equality); the session binding lives in the context field,
        // not folded into the hash. See the WIRE CONTRACT block at the top of
        // this file.
        let raw_disclosed_hash =
            compute_disclosed_hash(cred.credential_data, attributes, mask_bits);

        let disclosure_note = CredNote::new(
            cred.credential_commitment,
            raw_disclosed_hash,
            context,
            disclosed_attrs,
        );

        self.storage.credentials.at(recipient).insert(disclosure_note).deliver_to(
            recipient,
            MessageDelivery::onchain_constrained(),
        );
    }

    // =========================================================================
    // Verify Compliance -- Prove credential + register in public compliance set
    //
    // This is the compliance-gated account entry point. The caller proves
    // they hold a non-revoked credential that the pinned issuer signed, and
    // their address is registered in the public compliance set.
    //
    // Transfer contracts check this set to enforce compliance-gated receiving:
    //   1. Recipient calls verify_compliance() once (a repeat call changes no
    //      state; it only publishes the address again)
    //   2. Private: loads the caller's issuer-signed originator credential
    //      (selected by the caller's own commitment), proves that the
    //      revocation nullifier for that commitment did not exist at the
    //      anchor block
    //   3. Enqueues public: schedules compliance_set[owner] = true; it takes
    //      effect after COMPLIANCE_DELAY
    //   4. Transfer contract's private gate calls assert_compliant(recipient)
    //
    // Public outputs: ONLY the owner address (the _register_compliance
    // argument). The credential commitment is the global ZKC holderCommitment,
    // so it never leaves private execution here: publishing it next to the
    // owner would link every linkable zkc:proof:v1 presentation of that holder
    // to this Aztec address.
    //
    // Revocation lag: the non-inclusion proof is against the anchor block, and
    // the tx expires REGISTRATION_MAX_ANCHOR_AGE after it, so a holder can
    // still register up to that long after revocation. Existing registrations
    // are not removed by revoke in any case (see Revocation below).
    // =========================================================================

    #[external("private")]
    fn verify_compliance() {
        let owner = self.msg_sender();

        // Load credential + verify commitment (shared with _prove_disclosure /
        // disclose_to via _verify_credential).
        let cred = self.internal._verify_credential(owner);

        // Private non-revocation: the revocation nullifier of this commitment
        // must not exist at the anchor block. The commitment is never an
        // argument of a public call.
        let inner_nullifier = revocation_nullifier(cred.credential_commitment);
        // Safety: the hint only gives a clear revert message (the witness
        // oracle refuses outright when the nullifier exists). A prover who skips
        // it still fails the constrained non-inclusion proof below. Same pattern
        // as aztec-nr's PublicImmutable::read.
        let revoked_hint = unsafe { check_nullifier_exists(inner_nullifier) };
        assert(!revoked_hint, "Credential has been revoked");
        let anchor = self.context.get_anchor_block_header();
        assert_nullifier_did_not_exist_by(
            anchor,
            compute_siloed_nullifier(self.address, inner_nullifier),
        );
        self.context.set_expiration_timestamp(anchor.timestamp() + REGISTRATION_MAX_ANCHOR_AGE);

        self.enqueue_self._register_compliance(owner);
    }

    /// Public internal: register address as compliant (after COMPLIANCE_DELAY).
    ///
    /// Re-registration does not schedule a new change: a pending true -> true
    /// change would cap the expiration of private reads of this entry at its
    /// timestamp of change, which is public, and so link a gated transfer to
    /// this registration.
    #[external("public")]
    #[only_self]
    fn _register_compliance(owner: AztecAddress) {
        let entry = self.storage.compliance_set.at(owner.to_field());
        let (scheduled, _) = entry.get_scheduled_value();
        if !scheduled {
            entry.schedule_value_change(true);
        }
    }

    // =========================================================================
    // Revocation -- Admin revokes a credential by its commitment
    //
    // revoke(cc) emits revocation_nullifier(cc) as a nullifier siloed to this
    // contract. Once that
    // nullifier is in a block that a verify_compliance tx anchors to, the
    // non-inclusion proof fails. Existing compliance registrations are NOT
    // retroactively removed, and re-verification cannot refresh them (it is a
    // no-op that only republishes the address). Do NOT advise holders to
    // re-verify on a schedule: when cc is revoked their re-verifications stop,
    // and that cadence break links cc to the address. Registration expiry needs
    // its own design.
    //
    // Public outputs: cc (the enqueued _set_revoked argument) and the siloed
    // revocation nullifier, which anyone who knows cc can recompute. A
    // revocation is a public statement about that holder anchor.
    // The admin knows only cc, so a contract-scoped revocation handle that the
    // holder alone can compute would make revocation impossible.
    // =========================================================================

    #[external("private")]
    fn revoke(credential_commitment: Field) {
        assert(credential_commitment != 0, "Credential commitment must be non-zero");
        // Only admin can revoke (asserted in the enqueued public phase, where
        // the admin public state is readable).
        let caller = self.msg_sender();
        self.enqueue_self._assert_admin(caller);
        self.enqueue_self._set_revoked(credential_commitment);
    }

    /// Public internal: verify caller is admin.
    #[external("public")]
    #[only_self]
    fn _assert_admin(caller: AztecAddress) {
        assert(caller == self.storage.admin.read(), "Only admin can revoke credentials");
    }

    /// Public internal: mark credential as revoked by emitting its revocation
    /// nullifier. Idempotent: a repeat revoke emits nothing (a duplicate
    /// nullifier would revert the tx).
    #[external("public")]
    #[only_self]
    fn _set_revoked(credential_commitment: Field) {
        let inner_nullifier = revocation_nullifier(credential_commitment);
        if !self.context.nullifier_exists_unsafe(inner_nullifier, self.address) {
            self.context.push_nullifier_unsafe(inner_nullifier);
        }
    }

    // =========================================================================
    // Compliance gate (private view)
    // =========================================================================

    /// Assert that `owner` is registered as compliant, reading compliance_set
    /// in private. The transfer gate calls this so that the recipient is not an
    /// argument of any public call.
    #[external("private")]
    #[view]
    fn assert_compliant(owner: AztecAddress) {
        let compliant = self.storage.compliance_set.at(owner.to_field()).get_current_value();
        assert(compliant, "Recipient is not compliant");
    }

    // =========================================================================
    // Public View Functions
    // =========================================================================

    /// Check if an address is registered as compliant (public state).
    #[external("public")]
    #[view]
    fn is_compliant(owner: AztecAddress) -> pub bool {
        self.storage.compliance_set.at(owner.to_field()).get_current_value()
    }

    /// Check if a credential commitment has been revoked (public state).
    #[external("public")]
    #[view]
    fn is_revoked(credential_commitment: Field) -> pub bool {
        self.context.nullifier_exists_unsafe(
            revocation_nullifier(credential_commitment),
            self.address,
        )
    }

    // =========================================================================
    // Utility Views (off-chain only)
    // =========================================================================

    /// Check if a credential note exists for the given owner.
    #[external("utility")]
    unconstrained fn has_credential(owner: AztecAddress) -> pub bool {
        let options = aztec::note::note_viewer_options::NoteViewerOptions::new();
        let notes = self.storage.credentials.at(owner).view_notes(options);
        notes.len() > 0
    }

    // =========================================================================
    // Private internal helpers (shared credential/disclosure logic)
    //
    // Both helpers are marked #[internal("private")] so they are only callable
    // from within this contract (via self.internal._verify_credential /
    // self.internal._prove_disclosure).
    // =========================================================================

    /// Load `owner`'s issuer-signed credential: an originator note
    /// (context == 0) whose commitment equals the one derived from `owner`'s
    /// app-siloed key. Both are constrained note selects, so a disclose_to
    /// note (context != 0, or another holder's commitment) is never returned,
    /// and a disclosure note sent to `owner` cannot shadow `owner`'s own
    /// credential. Only bind_credential creates originator notes, after the
    /// issuer signature check. Returns the loaded CredNote.
    ///
    /// Shared by `_prove_disclosure`, `disclose_to`, and `verify_compliance` so
    /// the load + key-derivation + selection exists in exactly one place.
    ///
    /// `owner` is passed explicitly (rather than read from msg_sender) so this
    /// helper is reusable across all three callers. msg_sender is NOT changed
    /// by this call -- #[internal("private")] functions are direct in-frame
    /// calls, so msg_sender here is still the original caller; passing `owner`
    /// explicitly is purely for reuse, not to work around any sender change.
    /// The nsk_app request below uses `owner`'s npk_m_hash, so the prover must
    /// hold owner's key -- only the real owner can produce the disclosure /
    /// compliance proof.
    #[internal("private")]
    fn _verify_credential(owner: AztecAddress) -> CredNote {
        let owner_npk_m_hash = get_public_keys(owner).npk_m_hash;
        let nsk_app = self.context.request_nhk_app(owner_npk_m_hash);
        let cbk = derive_zka_cbk(nsk_app);
        let expected_cc = zka_lib::derive_credential_commitment(cbk);

        let properties = CredNote::properties();
        let options = NoteGetterOptions::new()
            .select(properties.credential_commitment, Comparator.EQ, expected_cc)
            .select(properties.context, Comparator.EQ, 0)
            .set_limit(1);
        let notes = self.storage.credentials.at(owner).get_notes(options);
        assert(notes.len() > 0, "No credential found for caller");

        notes.get_unchecked(0).note
    }

    /// Shared selective-disclosure logic. Loads `owner`'s credential, verifies
    /// its commitment (via `_verify_credential`), folds the masked attributes,
    /// and returns the RAW (context-INDEPENDENT) disclosed hash --
    /// `compute_disclosed_hash(credential_data, attributes, mask)` -- which is
    /// byte-identical to the standalone circuit's `disclosed_attribute_hash`
    /// (the cross-environment equality guarantee; docs/adr/0001, Option A).
    ///
    /// SS5.2 context binding: `session_context` MUST be non-zero. The context is
    /// a CONSTRAINED ARGUMENT of this proof, so the returned hash is bound to it
    /// by the call proof itself (a same-tx consumer that received this value from
    /// a call with a given context can trust the correspondence). The context is
    /// therefore a SEPARATE co-equal binding -- it is deliberately NOT folded
    /// into the returned hash, as required by the normative specification and
    /// ZKC claimBinding model (docs/adr/0001).
    /// The non-zero assert is enforced here so every entry point
    /// (`prove_disclosure`, `prove_kyc`, `prove_jurisdiction`,
    /// `prove_source_of_funds`, `aggregate_disclosures`) inherits it.
    ///
    /// (The parameter is named `session_context` rather than `context` to
    /// avoid colliding with the framework-injected `context: &mut PrivateContext`
    /// that the #[internal("private")] macro prepends to the signature. At the
    /// caller boundary the user-facing name is `context` -- the rename is
    /// internal-helper-only.)
    ///
    /// (A recursive cross-contract self-call,
    /// ZKACredential::at(this).prove_disclosure(...), would reset msg_sender to
    /// this contract and load the wrong credential; the logic lives in this
    /// in-frame internal helper so the caller's msg_sender is preserved.)
    #[internal("private")]
    fn _prove_disclosure(
        owner: AztecAddress,
        attribute_mask: Field,
        session_context: Field,
    ) -> Field {
        // SS5.2 context binding: reject zero. The context binds the proof as a
        // constrained argument (not folded into the return value -- docs/adr/0001).
        assert(session_context != 0, "Context must be non-zero for replay protection");

        let cred = self.internal._verify_credential(owner);

        // Decompose mask into bits (big-endian, matching standalone circuit).
        let mask_bits: [bool; 4] = attribute_mask.to_be_bits::<4>();

        let attributes = cred.get_attributes();

        // Return the RAW context-independent disclosed hash (cross-env identical).
        compute_disclosed_hash(cred.credential_data, attributes, mask_bits)
    }
}
