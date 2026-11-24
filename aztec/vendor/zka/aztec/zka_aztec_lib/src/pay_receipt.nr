// =============================================================================
// ZKA/Pay Aztec-native encrypted receipt body, v1
//
// This is the application plaintext delivered through Aztec's private-event
// transport.  The transport supplies event type metadata and fresh event
// randomness; neither is part of this five-field application body.  Keeping
// this receipt separate from ZKANote deliberately preserves the canonical
// ZKA note commitment used by the other settlement profiles.
// =============================================================================

use aztec::{
    event::event_interface::{compute_private_event_commitment, EventInterface},
    macros::events::event,
    protocol::{address::AztecAddress, traits::{FromField, Serialize, ToField}},
};

/// Exact UTF-8 `zka/aztec/pay/receipt/v1`, right-aligned in one 32-byte field.
/// It is distinct from note-announcement and withdrawal-message domains.
pub global ZKA_PAY_RECEIPT_V1_DOMAIN: Field =
    0x00000000000000007a6b612f617a7465632f7061792f726563656970742f7631;
pub global ZKA_PAY_RECEIPT_V1_VERSION: Field = 1;
pub global ZKA_PAY_RECEIPT_V1_BODY_FIELDS: u32 = 5;

/// The fixed-size plaintext application body of one recipient-encrypted
/// ZKA/Pay receipt.  Its serialized field order is normative:
/// `[domain, version, interaction_context, output_note_hash, contract_instance]`.
///
/// The recipient is intentionally not duplicated.  The conforming `pay`
/// call constrains private-event delivery to the same account that owns the
/// output note whose canonical, unsiloed ZKANote hash appears here.
#[event]
pub struct ZKAPayReceiptV1 {
    pub receipt_domain: Field,
    pub receipt_version: Field,
    pub interaction_context: Field,
    pub output_note_hash: Field,
    pub contract_instance: AztecAddress,
}

impl ZKAPayReceiptV1 {
    pub fn new(
        interaction_context: Field,
        output_note_hash: Field,
        contract_instance: AztecAddress,
    ) -> Self {
        let receipt = ZKAPayReceiptV1 {
            receipt_domain: ZKA_PAY_RECEIPT_V1_DOMAIN,
            receipt_version: ZKA_PAY_RECEIPT_V1_VERSION,
            interaction_context,
            output_note_hash,
            contract_instance,
        };
        receipt.validate();
        receipt
    }

    /// Call this immediately before private-event delivery.  Field values are
    /// canonical by construction; the context and instance must additionally
    /// be nonzero.  A note hash is a full field element and is not artificially
    /// restricted: zero is an admissible hash output.
    pub fn validate(self) {
        assert(
            self.receipt_domain == ZKA_PAY_RECEIPT_V1_DOMAIN,
            "ZKA pay receipt has an unsupported domain",
        );
        assert(
            self.receipt_version == ZKA_PAY_RECEIPT_V1_VERSION,
            "ZKA pay receipt has an unsupported version",
        );
        assert(self.interaction_context != 0, "ZKA pay receipt context must be nonzero");
        assert(
            self.contract_instance.to_field() != 0,
            "ZKA pay receipt contract instance must be nonzero",
        );
    }
}

// =============================================================================
// Pure codec conformance tests.  These cover deterministic body semantics and
// the platform event selector/commitment.  Ciphertext is intentionally absent:
// private-event encryption has fresh platform randomness and is verified with
// the constrained carrier in the ownerless pay-surface requirement.
// =============================================================================

global KAT_INTERACTION_CONTEXT: Field =
    0x15f5d26bbe7c964d97b110edeeda1a6372006043d47bf4e6eb1271aad6078d11;
global KAT_CONTRACT_INSTANCE: Field = 0x1234;
global KAT_RECIPIENT: Field = 0xcafe;
global KAT_ASSET_COMMITMENT: Field = 0x1111;
global KAT_VALUE: Field = 7;
global KAT_NOTE_RANDOMNESS: Field = 0xabcd;
global KAT_EVENT_RANDOMNESS: Field = 0x9876;
global KAT_EVENT_SELECTOR: Field = 0x1f7165ae;
global KAT_EVENT_COMMITMENT_SMALL_INTS: Field =
    0x13188ddd1f843873c23ad425e17745d566d5e1e9bafb3d4d0ec3fa4b01b1d4e3;
global KAT_EVENT_COMMITMENT_ONE_ONE: Field =
    0x2eaf467d9671401665bca6d6524ecb3e3fb5faca10bf1ee1e7798f3f0f211fa4;
global KAT_EVENT_COMMITMENT_MAX_CANONICAL: Field =
    0x2a283866814d97bef8f334dfba7e83a6ea95261aacc25b3f6eb3b3a9e1dfc6b0;
global KAT_EVENT_COMMITMENT_KECCAK_DERIVED_QUOTE: Field =
    0x24b40fde933baba07a81780c500bd6279221f1f032f18029d80bcc22fb91e3ae;
global KAT_EVENT_COMMITMENT_ASYMMETRY_PAIR: Field =
    0x0a62679547545b8cf995c3ab4253c07bba10ee73108148bc8314c84c682155be;

#[test]
fn receipt_body_has_the_normative_fixed_order() {
    let output_note_hash = crate::ZKANote::new(KAT_ASSET_COMMITMENT, KAT_VALUE).zka_note_hash(
        AztecAddress::from_field(KAT_RECIPIENT),
        KAT_NOTE_RANDOMNESS,
    );
    let receipt = ZKAPayReceiptV1::new(
        KAT_INTERACTION_CONTEXT,
        output_note_hash,
        AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    );
    let body = receipt.serialize();

    assert(body.len() == ZKA_PAY_RECEIPT_V1_BODY_FIELDS, "receipt body must have five fields");
    assert(body[0] == ZKA_PAY_RECEIPT_V1_DOMAIN, "domain must be first");
    assert(body[1] == ZKA_PAY_RECEIPT_V1_VERSION, "version must be second");
    assert(body[2] == KAT_INTERACTION_CONTEXT, "context must be third");
    assert(body[3] == output_note_hash, "output note hash must be fourth");
    assert(body[4] == KAT_CONTRACT_INSTANCE, "contract instance must be fifth");
}

#[test]
fn receipt_binds_the_unchanged_canonical_zka_note_hash() {
    let note = crate::ZKANote::new(KAT_ASSET_COMMITMENT, KAT_VALUE);
    let owner = AztecAddress::from_field(KAT_RECIPIENT);
    let expected_output_hash = note.zka_note_hash(owner, KAT_NOTE_RANDOMNESS);
    let receipt = ZKAPayReceiptV1::new(
        KAT_INTERACTION_CONTEXT,
        expected_output_hash,
        AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    );

    assert(receipt.output_note_hash == expected_output_hash, "receipt must bind ZKANote hash");
    assert(
        expected_output_hash
            == zka_lib::compute_note_commitment(
                KAT_ASSET_COMMITMENT,
                KAT_VALUE,
                KAT_RECIPIENT,
                KAT_NOTE_RANDOMNESS,
            ),
        "receipt must not change ZKANote commitment semantics",
    );
}

#[test]
fn receipt_binds_the_note_owner_without_changing_note_semantics() {
    let note = crate::ZKANote::new(KAT_ASSET_COMMITMENT, KAT_VALUE);
    let recipient_hash =
        note.zka_note_hash(AztecAddress::from_field(KAT_RECIPIENT), KAT_NOTE_RANDOMNESS);
    let other_recipient_hash =
        note.zka_note_hash(AztecAddress::from_field(KAT_RECIPIENT + 1), KAT_NOTE_RANDOMNESS);
    let first = ZKAPayReceiptV1::new(
        KAT_INTERACTION_CONTEXT,
        recipient_hash,
        AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    );
    let second = ZKAPayReceiptV1::new(
        KAT_INTERACTION_CONTEXT,
        other_recipient_hash,
        AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    );

    assert(recipient_hash != other_recipient_hash, "the recipient opening changes the note hash");
    assert(
        first.output_note_hash != second.output_note_hash,
        "receipt binds the owned output hash",
    );
}

#[test]
fn context_reuse_is_a_multiset_not_a_uniqueness_key() {
    let first_hash = crate::ZKANote::new(KAT_ASSET_COMMITMENT, KAT_VALUE).zka_note_hash(
        AztecAddress::from_field(KAT_RECIPIENT),
        KAT_NOTE_RANDOMNESS,
    );
    let second_hash = crate::ZKANote::new(KAT_ASSET_COMMITMENT, KAT_VALUE + 1).zka_note_hash(
        AztecAddress::from_field(KAT_RECIPIENT),
        KAT_NOTE_RANDOMNESS + 1,
    );
    let first = ZKAPayReceiptV1::new(
        KAT_INTERACTION_CONTEXT,
        first_hash,
        AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    );
    let second = ZKAPayReceiptV1::new(
        KAT_INTERACTION_CONTEXT,
        second_hash,
        AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    );

    assert(first.interaction_context == second.interaction_context, "context reuse is permitted");
    assert(
        first.output_note_hash != second.output_note_hash,
        "each receipt keeps its output binding",
    );
    assert(first.serialize() != second.serialize(), "reused context must not collapse receipts");
}

#[test]
fn platform_event_identity_is_deterministic_for_the_fixed_body() {
    let receipt = ZKAPayReceiptV1::new(
        KAT_INTERACTION_CONTEXT,
        crate::ZKANote::new(KAT_ASSET_COMMITMENT, KAT_VALUE).zka_note_hash(
            AztecAddress::from_field(KAT_RECIPIENT),
            KAT_NOTE_RANDOMNESS,
        ),
        AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    );
    let selector = ZKAPayReceiptV1::get_event_type_id().to_field();
    let commitment = compute_private_event_commitment(receipt, KAT_EVENT_RANDOMNESS);

    assert(selector == KAT_EVENT_SELECTOR, "receipt event selector KAT must hold");
    assert(commitment == KAT_EVENT_COMMITMENT_SMALL_INTS, "receipt event commitment KAT must hold");
}

#[test]
fn all_frozen_interaction_context_kats_have_distinct_event_commitments() {
    let note_hash = crate::ZKANote::new(KAT_ASSET_COMMITMENT, KAT_VALUE).zka_note_hash(
        AztecAddress::from_field(KAT_RECIPIENT),
        KAT_NOTE_RANDOMNESS,
    );
    let contract_instance = AztecAddress::from_field(KAT_CONTRACT_INSTANCE);
    let one_one: Field = 0x2086c7bbbaf410c4a2765ed3d703456f8a73043dab3b8186b3b46953d5ebd9be;
    let max_canonical: Field = 0x2cc267f42950d336ae3f0878c5f40cb63939fcb666345d26187c3d50075cdf73;
    let keccak_derived_quote: Field =
        0x12ec0693eea9d6b9f1a94cf592c015074975e3be3767008835b259f86db12ae1;
    let asymmetry_pair: Field = 0x301373d6115d9bf9a7fb1c00343e2ada767ca60920635e6df651ba3dbad44a93;

    let one_one_commitment = compute_private_event_commitment(
        ZKAPayReceiptV1::new(one_one, note_hash, contract_instance),
        KAT_EVENT_RANDOMNESS,
    );
    let max_canonical_commitment = compute_private_event_commitment(
        ZKAPayReceiptV1::new(max_canonical, note_hash, contract_instance),
        KAT_EVENT_RANDOMNESS,
    );
    let keccak_derived_quote_commitment = compute_private_event_commitment(
        ZKAPayReceiptV1::new(keccak_derived_quote, note_hash, contract_instance),
        KAT_EVENT_RANDOMNESS,
    );
    let asymmetry_pair_commitment = compute_private_event_commitment(
        ZKAPayReceiptV1::new(asymmetry_pair, note_hash, contract_instance),
        KAT_EVENT_RANDOMNESS,
    );

    assert(one_one_commitment == KAT_EVENT_COMMITMENT_ONE_ONE, "one-one commitment KAT");
    assert(
        max_canonical_commitment == KAT_EVENT_COMMITMENT_MAX_CANONICAL,
        "max-canonical commitment KAT",
    );
    assert(
        keccak_derived_quote_commitment == KAT_EVENT_COMMITMENT_KECCAK_DERIVED_QUOTE,
        "keccak-derived quote commitment KAT",
    );
    assert(
        asymmetry_pair_commitment == KAT_EVENT_COMMITMENT_ASYMMETRY_PAIR,
        "asymmetry-pair commitment KAT",
    );
}

#[test]
fn zero_output_hash_is_valid_receipt_payload() {
    let receipt = ZKAPayReceiptV1::new(
        KAT_INTERACTION_CONTEXT,
        0,
        AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    );
    receipt.validate();
}

#[test(should_fail)]
fn receipt_rejects_wrong_domain() {
    ZKAPayReceiptV1 {
        receipt_domain: ZKA_PAY_RECEIPT_V1_DOMAIN + 1,
        receipt_version: ZKA_PAY_RECEIPT_V1_VERSION,
        interaction_context: KAT_INTERACTION_CONTEXT,
        output_note_hash: 0,
        contract_instance: AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    }
        .validate();
}

#[test(should_fail)]
fn receipt_rejects_wrong_version() {
    ZKAPayReceiptV1 {
        receipt_domain: ZKA_PAY_RECEIPT_V1_DOMAIN,
        receipt_version: ZKA_PAY_RECEIPT_V1_VERSION + 1,
        interaction_context: KAT_INTERACTION_CONTEXT,
        output_note_hash: 0,
        contract_instance: AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    }
        .validate();
}

#[test(should_fail)]
fn receipt_rejects_zero_context() {
    ZKAPayReceiptV1 {
        receipt_domain: ZKA_PAY_RECEIPT_V1_DOMAIN,
        receipt_version: ZKA_PAY_RECEIPT_V1_VERSION,
        interaction_context: 0,
        output_note_hash: 0,
        contract_instance: AztecAddress::from_field(KAT_CONTRACT_INSTANCE),
    }
        .validate();
}

#[test(should_fail)]
fn receipt_rejects_zero_contract_instance() {
    ZKAPayReceiptV1 {
        receipt_domain: ZKA_PAY_RECEIPT_V1_DOMAIN,
        receipt_version: ZKA_PAY_RECEIPT_V1_VERSION,
        interaction_context: KAT_INTERACTION_CONTEXT,
        output_note_hash: 0,
        contract_instance: AztecAddress::zero(),
    }
        .validate();
}
