use aztec::macros::aztec;

/// Minimal test-only nested caller for ZKATransfer's five-field
/// `transfer_from` interface. Keeping this in the workspace makes `aztec
/// compile` emit the contract artifact required by TXE.
#[aztec]
pub contract AuthwitTestProxy {
    use aztec::{
        macros::functions::external,
        protocol::{abis::function_selector::FunctionSelector, address::AztecAddress},
    };

    #[external("private")]
    fn forward_private_5(target: AztecAddress, selector: FunctionSelector, args: [Field; 5]) {
        let _ = self.context.call_private_function(target, selector, args);
    }
}
