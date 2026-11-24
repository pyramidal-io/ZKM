use aztec::protocol::{address::AztecAddress, traits::Packable};
use std::meta::derive;

// Compliance-gate configuration. Both fields sit in one DelayedPublicMutable so
// that the private gate does a single historical public storage read. The
// zero value (never written) is "compliance disabled, no credential contract".
#[derive(Eq, Packable)]
pub struct ComplianceConfig {
    pub enabled: bool,
    pub credential_contract: AztecAddress,
}
