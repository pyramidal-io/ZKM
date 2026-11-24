// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {IZKMSettlementTarget, ZKMAtomicSettlement} from "./ZKMAtomicSettlement.sol";

/// @title ZKMSettlementTargetStub
/// @notice Measurement-only target with canonical target-owned replay and uniqueness state.
/// @dev Records mandatory mandate/ZKA nullifiers and an append-only mandate
///      leaf journal, plus permanent separate mandate/ZKA commitment ledgers.
///      Returned positions are actual journal positions shared
///      across adapters; this is not a Merkle-root or inclusion implementation.
///      Merkle hashing, balances and asset movement remain omitted. Measured
///      settle* totals include replay, uniqueness and journal work and are reference-dependent lower
///      bounds; a real target must apply every effect atomically as well.
///      This contract MUST NOT be deployed anywhere real: root authorization
///      predicates remain permissive for fixture measurement.
///      The admin models a test driver, not production governance or proof
///      verification.
contract ZKMSettlementTargetStub is IZKMSettlementTarget {
    bytes32 public immutable SETTLEMENT_CONTEXT;
    bytes32 public immutable ASSET_ID;
    uint64 public immutable CURRENT_TIME;
    address public immutable ADMIN;

    mapping(bytes32 => bool) public mandateNullifierSpent;
    mapping(bytes32 => bool) public zkaNullifierSpent;
    mapping(address => bool) public authorizedAdapters;
    mapping(bytes32 => mapping(address => mapping(bytes32 => bool))) internal authorizedVerifiers;
    mapping(uint64 => bytes32) public mandateLeaves;
    uint64 public nextMandateLeafIndex;
    mapping(bytes32 => bool) public mandateCommitmentSeen;
    mapping(bytes32 => bool) public zkaCommitmentSeen;
    uint256 private constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    error UnauthorizedAdmin();
    error UnauthorizedAdapter();
    error MandateNullifierSpent();
    error ZkaNullifierSpent();
    error MandateTreeFull();
    error DuplicateMandateCommitment();
    error DuplicateZkaCommitment();

    modifier onlyAdmin() {
        if (msg.sender != ADMIN) revert UnauthorizedAdmin();
        _;
    }

    constructor(bytes32 settlementContext, bytes32 assetId, uint64 currentTime) {
        SETTLEMENT_CONTEXT = settlementContext;
        ASSET_ID = assetId;
        CURRENT_TIME = currentTime;
        ADMIN = msg.sender;
    }

    function setVerifierAuthorization(bytes32 statementId, address verifier, bytes32 vkHash, bool allowed)
        external
        onlyAdmin
    {
        authorizedVerifiers[statementId][verifier][vkHash] = allowed;
    }

    /// @dev Register only the reviewed adapter code constructed by this factory.
    ///      Arbitrary caller-chosen adapter addresses cannot poison replay state.
    function deployAdapter(
        address spendVerifier,
        bytes32 spendVkHash,
        address mandateVerifier,
        bytes32 mandateVkHash,
        address possessionVerifier,
        bytes32 possessionVkHash
    ) external onlyAdmin returns (ZKMAtomicSettlement adapter) {
        adapter = new ZKMAtomicSettlement(
            address(this),
            spendVerifier,
            spendVkHash,
            mandateVerifier,
            mandateVkHash,
            possessionVerifier,
            possessionVkHash
        );
        authorizedAdapters[address(adapter)] = true;
    }

    function withdrawAdapter(address adapter) external onlyAdmin {
        authorizedAdapters[adapter] = false;
    }

    function zkmSettlementContext() external view returns (bytes32) {
        return SETTLEMENT_CONTEXT;
    }

    function zkmAssetId() external view returns (bytes32) {
        return ASSET_ID;
    }

    function zkmCurrentTime() external view returns (uint64) {
        return CURRENT_TIME;
    }

    /// @dev Fixed example policy in clock units; production targets select and
    /// authenticate their own immutable/versioned liveness window.
    function zkmProofTimeWindow() external pure returns (uint64) {
        return 60;
    }

    function isRecentMandateRoot(bytes32) external pure returns (bool) {
        return true;
    }

    function isRecentZkaNoteRoot(bytes32) external pure returns (bool) {
        return true;
    }

    function isRecognizedRevocationRoot(bytes32) external pure returns (bool) {
        return true;
    }

    function isAuthorizedZkmVerifier(bytes32 statementId, address verifier, bytes32 vkHash)
        external
        view
        returns (bool)
    {
        return authorizedVerifiers[statementId][verifier][vkHash];
    }

    function _requireAdapterLane(bool spendLane) internal view {
        if (!authorizedAdapters[msg.sender]) revert UnauthorizedAdapter();
        ZKMAtomicSettlement adapter = ZKMAtomicSettlement(msg.sender);
        bytes32 statementId = spendLane ? adapter.SPEND_CONJOINED_STATEMENT_ID() : adapter.MANDATE_ONLY_STATEMENT_ID();
        address verifier =
            spendLane ? address(adapter.SPEND_CONJOINED_VERIFIER()) : address(adapter.MANDATE_ONLY_VERIFIER());
        bytes32 vkHash = spendLane ? adapter.SPEND_CONJOINED_VK_HASH() : adapter.MANDATE_ONLY_VK_HASH();
        if (!authorizedVerifiers[statementId][verifier][vkHash]) {
            revert ZKMAtomicSettlement.UnauthorizedVerificationKey();
        }
    }

    function applyZkmSpend(SpendEffects calldata effects) external returns (MandateLeafIndices memory indices) {
        _requireAdapterLane(true);
        if (mandateNullifierSpent[effects.mandateNullifier]) revert MandateNullifierSpent();
        if (zkaNullifierSpent[effects.zkaNullifier]) revert ZkaNullifierSpent();
        mandateNullifierSpent[effects.mandateNullifier] = true;
        zkaNullifierSpent[effects.zkaNullifier] = true;
        indices = MandateLeafIndices(_appendMandateLeaf(effects.mandateSuccessorCommitment), type(uint64).max);
        _recordZkaCommitment(effects.zkaRecipientCommitment);
        _recordZkaCommitment(effects.zkaChangeCommitment);
    }

    function applyZkmMandateTransition(MandateEffects calldata effects)
        external
        returns (MandateLeafIndices memory indices)
    {
        _requireAdapterLane(false);
        if (mandateNullifierSpent[effects.mandateNullifier]) revert MandateNullifierSpent();
        mandateNullifierSpent[effects.mandateNullifier] = true;
        indices = MandateLeafIndices(
            _appendMandateLeaf(effects.mandateSuccessorCommitment),
            _appendMandateLeaf(effects.mandateSecondSuccessorCommitment)
        );
    }

    function _appendMandateLeaf(bytes32 commitment) internal returns (uint64 index) {
        if (commitment == bytes32(0)) return type(uint64).max;
        _requireLiveCommitment(commitment);
        if (mandateCommitmentSeen[commitment]) revert DuplicateMandateCommitment();
        index = nextMandateLeafIndex;
        if (index > type(uint32).max) revert MandateTreeFull();
        mandateCommitmentSeen[commitment] = true;
        mandateLeaves[index] = commitment;
        nextMandateLeafIndex = index + 1;
    }

    function _recordZkaCommitment(bytes32 commitment) internal {
        _requireLiveCommitment(commitment);
        if (zkaCommitmentSeen[commitment]) revert DuplicateZkaCommitment();
        zkaCommitmentSeen[commitment] = true;
    }

    function _requireLiveCommitment(bytes32 commitment) private pure {
        if (commitment == bytes32(0) || uint256(commitment) >= FIELD_MODULUS) {
            revert ZKMAtomicSettlement.InvalidField();
        }
    }

    /// @dev Test-driver hook AFTER issuance proof/VK/domain verification, also
    /// used to model an authenticated historical checkpoint. A known commitment
    /// is a whole-operation no-op: no new position, counter or receipt event.
    /// This is not a permissionless production issuance API.
    function recordVerifiedMandateIssuance(bytes32 commitment) external onlyAdmin returns (bool inserted) {
        _requireLiveCommitment(commitment);
        if (mandateCommitmentSeen[commitment]) return false;
        _appendMandateLeaf(commitment);
        return true;
    }

    /// @dev Test-driver hook AFTER ordinary ZKA output verification, including
    /// complete historical commitment import. It shares the same ever-seen
    /// ledger as ZKM outputs and has no mandate/time/revocation gate. The stub
    /// records uniqueness only, not a ZKA Merkle insertion or value movement.
    function recordVerifiedZkaNote(bytes32 commitment) external onlyAdmin {
        _recordZkaCommitment(commitment);
    }

    /// @dev Test-driver hook for an ALREADY-VERIFIED ordinary transfer/exit.
    ///      It shares ZKA custody but has no mandate, adapter or ZKM-VK gate.
    ///      This is not a permissionless caller-supplied withdrawal API.
    function recordVerifiedExit(bytes32 zkaNullifier) external onlyAdmin {
        if (zkaNullifierSpent[zkaNullifier]) revert ZkaNullifierSpent();
        zkaNullifierSpent[zkaNullifier] = true;
    }
}
