// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {IUltraVerifier} from "./IUltraVerifier.sol";
import {IZKMSettlementTarget} from "./ZKMAtomicSettlement.sol";

/// @notice Reference scheme-2 insertion and root-history implementation.
/// @dev Measurement/reference surface for a NEW target, bootstrapped from the
///      canonical empty tree. A migrated target must instead authenticate its
///      complete activation checkpoint under the migration runbook. This
///      contract provides no arbitrary-root setter or operator publication lane.
///      The target supplies an authenticated clock, context and VK registry;
///      its isRecognizedRevocationRoot implementation can delegate to this one.
///      ZKA owns the settlement boundary. There are no custody or value effects.
contract ZKMRevocationAccumulator {
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 public constant EMPTY_ROOT =
        0x0ec9cf7fbcbffa41bc1b25e7569f1bbc85ee742cbe1c6c6f4c6af987b9773f55;
    bytes32 public constant AUTH_STATEMENT_ID = keccak256("zkm:revocation-auth:v1");
    bytes32 public constant INSERTION_STATEMENT_ID = keccak256("zkm:revocation-insertion:v1");

    struct Insertion {
        bytes32 rootId;
        bytes32 previousRoot;
        bytes32 nextRoot;
        uint8 revocationScheme;
        uint64 epoch;
        bytes32 settlementContext;
    }

    struct RootRecord {
        uint64 epoch;
        bool known;
    }

    IZKMSettlementTarget public immutable TARGET;
    IUltraVerifier public immutable AUTH_VERIFIER;
    IUltraVerifier public immutable INSERTION_VERIFIER;
    bytes32 public immutable AUTH_VK_HASH;
    bytes32 public immutable INSERTION_VK_HASH;
    bytes32 public immutable SETTLEMENT_CONTEXT;
    uint64 public immutable EPOCH_CADENCE;
    uint64 public immutable STALENESS_MAX;
    uint64 public immutable ACTIVATION_EPOCH;

    bytes32 public currentRoot;
    uint64 public insertionCount;
    mapping(bytes32 => bool) public revoked;
    mapping(bytes32 => RootRecord) public roots;

    error InvalidConfiguration();
    error InvalidField();
    error UnauthorizedVerificationKey();
    error ContextMismatch();
    error InvalidEpoch();
    error InvalidRevocationScheme();
    error StaleInsertionRoot();
    error InvalidAuthorizationProof();
    error InvalidInsertionProof();

    event RevocationInserted(
        bytes32 indexed rootId,
        bytes32 indexed previousRoot,
        bytes32 indexed nextRoot,
        uint64 insertionIndex,
        uint64 epoch
    );
    event RevocationAlreadyRecorded(bytes32 indexed rootId);

    constructor(
        address target,
        address authVerifier,
        bytes32 authVkHash,
        address insertionVerifier,
        bytes32 insertionVkHash,
        uint64 epochCadence,
        uint64 stalenessMax
    ) {
        if (
            target.code.length == 0 || authVerifier.code.length == 0
                || insertionVerifier.code.length == 0 || authVkHash == 0
                || insertionVkHash == 0 || epochCadence == 0
        ) revert InvalidConfiguration();
        TARGET = IZKMSettlementTarget(target);
        AUTH_VERIFIER = IUltraVerifier(authVerifier);
        INSERTION_VERIFIER = IUltraVerifier(insertionVerifier);
        AUTH_VK_HASH = authVkHash;
        INSERTION_VK_HASH = insertionVkHash;
        EPOCH_CADENCE = epochCadence;
        STALENESS_MAX = stalenessMax;
        SETTLEMENT_CONTEXT = TARGET.zkmSettlementContext();
        _requireField(SETTLEMENT_CONTEXT);
        _requireVerifiers();
        ACTIVATION_EPOCH = currentEpoch();
        currentRoot = EMPTY_ROOT;
        roots[EMPTY_ROOT] = RootRecord(ACTIVATION_EPOCH, true);
    }

    function currentEpoch() public view returns (uint64) {
        return TARGET.zkmCurrentTime() / EPOCH_CADENCE;
    }

    /// @notice Successful return true means the insertion AND publication committed.
    /// @dev A stale concurrent witness reverts, so it never produces an accepted
    ///      insertion receipt. The caller refreshes and retries. Duplicate replay
    ///      verifies authorization but returns false without updating root history.
    function insert(
        bytes calldata authorizationProof,
        bytes calldata insertionProof,
        Insertion calldata value
    ) external returns (bool) {
        _requireField(value.rootId);
        _requireField(value.previousRoot);
        _requireField(value.nextRoot);
        if (value.revocationScheme != 2) revert InvalidRevocationScheme();
        if (
            value.settlementContext != SETTLEMENT_CONTEXT
                || TARGET.zkmSettlementContext() != SETTLEMENT_CONTEXT
        ) revert ContextMismatch();
        _requireVerifiers();

        bytes32[] memory authInputs = new bytes32[](2);
        authInputs[0] = value.rootId;
        authInputs[1] = value.settlementContext;
        if (!AUTH_VERIFIER.verify(authorizationProof, authInputs)) revert InvalidAuthorizationProof();
        if (revoked[value.rootId]) {
            emit RevocationAlreadyRecorded(value.rootId);
            return false;
        }
        uint64 epoch = currentEpoch();
        if (value.epoch != epoch || epoch < roots[currentRoot].epoch) revert InvalidEpoch();
        if (value.previousRoot != currentRoot) revert StaleInsertionRoot();

        // EXACT circuit order. This proof alone supplies no issuance authority.
        bytes32[] memory updateInputs = new bytes32[](6);
        updateInputs[0] = value.rootId;
        updateInputs[1] = value.previousRoot;
        updateInputs[2] = value.nextRoot;
        updateInputs[3] = bytes32(uint256(value.revocationScheme));
        updateInputs[4] = bytes32(uint256(value.epoch));
        updateInputs[5] = value.settlementContext;
        if (!INSERTION_VERIFIER.verify(insertionProof, updateInputs)) revert InvalidInsertionProof();

        // The former tip was current until THIS epoch, even if no insertion
        // occurred for many epochs. Never refresh a root after it is superseded.
        roots[currentRoot].epoch = epoch;
        roots[value.nextRoot] = RootRecord(epoch, true);
        revoked[value.rootId] = true;
        currentRoot = value.nextRoot;
        insertionCount += 1;
        // Full identifiers plus their canonical order make every accepted root
        // independently reconstructible; no unpublished sibling service is needed.
        emit RevocationInserted(
            value.rootId, value.previousRoot, value.nextRoot, insertionCount, epoch
        );
        return true;
    }

    /// @notice Multiple ordered tips may be recognized within one epoch.
    /// @dev Current tip remains fresh across idle epochs. Historical tips age
    ///      from the epoch in which they were replaced; future epochs fail closed.
    function isRecognizedRevocationRoot(bytes32 root) external view returns (bool) {
        RootRecord memory record = roots[root];
        uint64 epoch = currentEpoch();
        if (
            !record.known || epoch < record.epoch || epoch < ACTIVATION_EPOCH
                || TARGET.zkmSettlementContext() != SETTLEMENT_CONTEXT
        ) return false;
        return root == currentRoot || epoch - record.epoch <= STALENESS_MAX;
    }

    function _requireVerifiers() internal view {
        if (
            !TARGET.isAuthorizedZkmVerifier(AUTH_STATEMENT_ID, address(AUTH_VERIFIER), AUTH_VK_HASH)
                || !TARGET.isAuthorizedZkmVerifier(
                    INSERTION_STATEMENT_ID, address(INSERTION_VERIFIER), INSERTION_VK_HASH
                )
        ) revert UnauthorizedVerificationKey();
    }

    function _requireField(bytes32 value) internal pure {
        if (value == 0 || uint256(value) >= FIELD_MODULUS) revert InvalidField();
    }
}
