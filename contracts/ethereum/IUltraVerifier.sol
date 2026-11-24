// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title IUltraVerifier
/// @notice The surface a bb-generated UltraHonk Solidity verifier exposes.
/// @dev The generated verifiers in `contracts/ethereum/verifiers/` implement this
///      shape without importing it (bb emits standalone source). Declaring it here
///      lets `ZKMAtomicSettlement` hold a typed reference and lets the gas harness
///      build calldata with `abi.encodeCall`, which is checked against this
///      signature at compile time rather than hand-encoded.
///
///      UltraHonk binds public inputs BY POSITION, not by name. Every caller must
///      therefore build `publicInputs` in the circuit's declared order; see
///      `ZKMAtomicSettlement`'s canonical 14/9-field vector assembly.
interface IUltraVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}
