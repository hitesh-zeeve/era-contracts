// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import {SafeCast} from "@openzeppelin/contracts-v4/utils/math/SafeCast.sol";

import {ZKChainBase} from "../state-transition/chain-deps/facets/ZKChainBase.sol";
import {VerifierParams} from "../state-transition/chain-interfaces/IVerifier.sol";
import {IVerifier} from "../state-transition/chain-interfaces/IVerifier.sol";
import {L2ContractHelper} from "../common/libraries/L2ContractHelper.sol";
import {TransactionValidator} from "../state-transition/libraries/TransactionValidator.sol";
import {MAX_NEW_FACTORY_DEPS, SYSTEM_UPGRADE_L2_TX_TYPE, MAX_ALLOWED_MINOR_VERSION_DELTA} from "../common/Config.sol";
import {L2CanonicalTransaction} from "../common/Messaging.sol";
import {ProtocolVersionMinorDeltaTooBig, TimeNotReached, InvalidTxType, L2UpgradeNonceNotEqualToNewProtocolVersion, TooManyFactoryDeps, ProtocolVersionTooSmall, PreviousUpgradeNotFinalized, PreviousUpgradeNotCleaned, PatchCantSetUpgradeTxn, PreviousProtocolMajorVersionNotZero, NewProtocolMajorVersionNotZero, PatchUpgradeCantSetDefaultAccount, PatchUpgradeCantSetBootloader} from "./ZkSyncUpgradeErrors.sol";
import {SemVer} from "../common/libraries/SemVer.sol";

/// @notice The struct that represents the upgrade proposal.
/// @param l2ProtocolUpgradeTx The system upgrade transaction.
/// @param bootloaderHash The hash of the new bootloader bytecode. If zero, it will not be updated.
/// @param defaultAccountHash The hash of the new default account bytecode. If zero, it will not be updated.
/// @param verifier The address of the new verifier. If zero, the verifier will not be updated.
/// @param verifierParams The new verifier params. If all of its fields are 0, the params will not be updated.
/// @param l1ContractsUpgradeCalldata Custom calldata for L1 contracts upgrade, it may be interpreted differently
/// in each upgrade. Usually empty.
/// @param postUpgradeCalldata Custom calldata for post upgrade hook, it may be interpreted differently in each
/// upgrade. Usually empty.
/// @param upgradeTimestamp The timestamp after which the upgrade can be executed.
/// @param newProtocolVersion The new version number for the protocol after this upgrade. Should be greater than
/// the previous protocol version.
struct ProposedUpgrade {
    L2CanonicalTransaction l2ProtocolUpgradeTx;
    bytes32 bootloaderHash;
    bytes32 defaultAccountHash;
    address verifier;
    VerifierParams verifierParams;
    bytes l1ContractsUpgradeCalldata;
    bytes postUpgradeCalldata;
    uint256 upgradeTimestamp;
    uint256 newProtocolVersion;
}

/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @notice Interface to which all the upgrade implementations should adhere
abstract contract BaseZkSyncUpgrade is ZKChainBase {
    /// @notice Changes the protocol version
    event NewProtocolVersion(uint256 indexed previousProtocolVersion, uint256 indexed newProtocolVersion);

    /// @notice Сhanges to the bytecode that is used in L2 as a bootloader (start program)
    event NewL2BootloaderBytecodeHash(bytes32 indexed previousBytecodeHash, bytes32 indexed newBytecodeHash);

    /// @notice Сhanges to the bytecode that is used in L2 as a default account
    event NewL2DefaultAccountBytecodeHash(bytes32 indexed previousBytecodeHash, bytes32 indexed newBytecodeHash);

    /// @notice Verifier address changed
    event NewVerifier(address indexed oldVerifier, address indexed newVerifier);

    /// @notice Verifier parameters changed
    event NewVerifierParams(VerifierParams oldVerifierParams, VerifierParams newVerifierParams);

    /// @notice Notifies about complete upgrade
    event UpgradeComplete(uint256 indexed newProtocolVersion, bytes32 indexed l2UpgradeTxHash, ProposedUpgrade upgrade);

    /// @notice The main function that will be delegate-called by the chain.
    /// @dev This is a virtual function and should be overridden by custom upgrade implementations.
    /// @param _proposedUpgrade The upgrade to be executed.
    /// @return txHash The hash of the L2 system contract upgrade transaction.
    function upgrade(ProposedUpgrade calldata _proposedUpgrade) public virtual returns (bytes32 txHash) {
        // Note that due to commitment delay, the timestamp of the L2 upgrade batch may be earlier than the timestamp
        // of the L1 block at which the upgrade occurred. This means that using timestamp as a signifier of "upgraded"
        // on the L2 side would be inaccurate. The effects of this "back-dating" of L2 upgrade batches will be reduced
        // as the permitted delay window is reduced in the future.
        if (block.timestamp < _proposedUpgrade.upgradeTimestamp) {
            revert TimeNotReached(_proposedUpgrade.upgradeTimestamp, block.timestamp);
        }

        (uint32 newMinorVersion, bool isPatchOnly) = _setNewProtocolVersion(_proposedUpgrade.newProtocolVersion);
        _upgradeL1Contract(_proposedUpgrade.l1ContractsUpgradeCalldata);
        _upgradeVerifier(_proposedUpgrade.verifier, _proposedUpgrade.verifierParams);
        _setBaseSystemContracts(_proposedUpgrade.bootloaderHash, _proposedUpgrade.defaultAccountHash, isPatchOnly);

        txHash = _setL2SystemContractUpgrade(_proposedUpgrade.l2ProtocolUpgradeTx, newMinorVersion, isPatchOnly);

        _postUpgrade(_proposedUpgrade.postUpgradeCalldata);

        emit UpgradeComplete(_proposedUpgrade.newProtocolVersion, txHash, _proposedUpgrade);
    }

    /// @notice Change default account bytecode hash, that is used on L2
    /// @param _l2DefaultAccountBytecodeHash The hash of default account L2 bytecode
    /// @param _patchOnly Whether only the patch part of the protocol version semver has changed
    function _setL2DefaultAccountBytecodeHash(bytes32 _l2DefaultAccountBytecodeHash, bool _patchOnly) private {
        if (_l2DefaultAccountBytecodeHash == bytes32(0)) {
            return;
        }

        if (_patchOnly) {
            revert PatchUpgradeCantSetDefaultAccount();
        }

        L2ContractHelper.validateBytecodeHash(_l2DefaultAccountBytecodeHash);

        // Save previous value into the stack to put it into the event later
        bytes32 previousDefaultAccountBytecodeHash = s.l2DefaultAccountBytecodeHash;

        // Change the default account bytecode hash
        s.l2DefaultAccountBytecodeHash = _l2DefaultAccountBytecodeHash;
        emit NewL2DefaultAccountBytecodeHash(previousDefaultAccountBytecodeHash, _l2DefaultAccountBytecodeHash);
    }

    /// @notice Change bootloader bytecode hash, that is used on L2
    /// @param _l2BootloaderBytecodeHash The hash of bootloader L2 bytecode
    /// @param _patchOnly Whether only the patch part of the protocol version semver has changed
    function _setL2BootloaderBytecodeHash(bytes32 _l2BootloaderBytecodeHash, bool _patchOnly) private {
        if (_l2BootloaderBytecodeHash == bytes32(0)) {
            return;
        }

        if (_patchOnly) {
            revert PatchUpgradeCantSetBootloader();
        }

        L2ContractHelper.validateBytecodeHash(_l2BootloaderBytecodeHash);

        // Save previous value into the stack to put it into the event later
        bytes32 previousBootloaderBytecodeHash = s.l2BootloaderBytecodeHash;

        // Change the bootloader bytecode hash
        s.l2BootloaderBytecodeHash = _l2BootloaderBytecodeHash;
        emit NewL2BootloaderBytecodeHash(previousBootloaderBytecodeHash, _l2BootloaderBytecodeHash);
    }

    /// @notice Change the address of the verifier smart contract
    /// @param _newVerifier Verifier smart contract address
    function _setVerifier(IVerifier _newVerifier) private {
        // An upgrade to the verifier must be done carefully to ensure there aren't batches in the committed state
        // during the transition. If verifier is upgraded, it will immediately be used to prove all committed batches.
        // Batches committed expecting the old verifier will fail. Ensure all committed batches are finalized before the
        // verifier is upgraded.
        if (_newVerifier == IVerifier(address(0))) {
            return;
        }

        IVerifier oldVerifier = s.verifier;
        s.verifier = _newVerifier;
        emit NewVerifier(address(oldVerifier), address(_newVerifier));
    }

    /// @notice Change the verifier parameters
    /// @param _newVerifierParams New parameters for the verifier
    function _setVerifierParams(VerifierParams calldata _newVerifierParams) private {
        // An upgrade to the verifier params must be done carefully to ensure there aren't batches in the committed state
        // during the transition. If verifier is upgraded, it will immediately be used to prove all committed batches.
        // Batches committed expecting the old verifier params will fail. Ensure all committed batches are finalized before the
        // verifier is upgraded.
        if (
            _newVerifierParams.recursionNodeLevelVkHash == bytes32(0) &&
            _newVerifierParams.recursionLeafLevelVkHash == bytes32(0) &&
            _newVerifierParams.recursionCircuitsSetVksHash == bytes32(0)
        ) {
            return;
        }

        VerifierParams memory oldVerifierParams = s.__DEPRECATED_verifierParams;
        s.__DEPRECATED_verifierParams = _newVerifierParams;
        emit NewVerifierParams(oldVerifierParams, _newVerifierParams);
    }

    /// @notice Updates the verifier and the verifier params
    /// @param _newVerifier The address of the new verifier. If 0, the verifier will not be updated.
    /// @param _verifierParams The new verifier params. If all of the fields are 0, the params will not be updated.
    function _upgradeVerifier(address _newVerifier, VerifierParams calldata _verifierParams) internal {
        _setVerifier(IVerifier(_newVerifier));
        _setVerifierParams(_verifierParams);
    }

    /// @notice Updates the bootloader hash and the hash of the default account
    /// @param _bootloaderHash The hash of the new bootloader bytecode. If zero, it will not be updated.
    /// @param _defaultAccountHash The hash of the new default account bytecode. If zero, it will not be updated.
    /// @param _patchOnly Whether only the patch part of the protocol version semver has changed.
    function _setBaseSystemContracts(bytes32 _bootloaderHash, bytes32 _defaultAccountHash, bool _patchOnly) internal {
        _setL2BootloaderBytecodeHash(_bootloaderHash, _patchOnly);
        _setL2DefaultAccountBytecodeHash(_defaultAccountHash, _patchOnly);
    }

    /// @notice Sets the hash of the L2 system contract upgrade transaction for the next batch to be committed
    /// @dev If the transaction is noop (i.e. its type is 0) it does nothing and returns 0.
    /// @param _l2ProtocolUpgradeTx The L2 system contract upgrade transaction.
    /// @param _newMinorProtocolVersion The new minor protocol version. It must be used as the `nonce` field
    /// of the `_l2ProtocolUpgradeTx`.
    /// @param _patchOnly Whether only the patch part of the protocol version semver has changed.
    /// @return System contracts upgrade transaction hash. Zero if no upgrade transaction is set.
    function _setL2SystemContractUpgrade(
        L2CanonicalTransaction calldata _l2ProtocolUpgradeTx,
        uint32 _newMinorProtocolVersion,
        bool _patchOnly
    ) internal returns (bytes32) {
        // If the type is 0, it is considered as noop and so will not be required to be executed.
        if (_l2ProtocolUpgradeTx.txType == 0) {
            return bytes32(0);
        }

        if (_l2ProtocolUpgradeTx.txType != SYSTEM_UPGRADE_L2_TX_TYPE) {
            revert InvalidTxType(_l2ProtocolUpgradeTx.txType);
        }
        if (_patchOnly) {
            revert PatchCantSetUpgradeTxn();
        }

        bytes memory encodedTransaction = abi.encode(_l2ProtocolUpgradeTx);

        TransactionValidator.validateL1ToL2Transaction(
            _l2ProtocolUpgradeTx,
            encodedTransaction,
            s.priorityTxMaxGasLimit,
            s.feeParams.priorityTxMaxPubdata
        );

        TransactionValidator.validateUpgradeTransaction(_l2ProtocolUpgradeTx);

        // We want the hashes of l2 system upgrade transactions to be unique.
        // This is why we require that the `nonce` field is unique to each upgrade.
        if (_l2ProtocolUpgradeTx.nonce != _newMinorProtocolVersion) {
            revert L2UpgradeNonceNotEqualToNewProtocolVersion(_l2ProtocolUpgradeTx.nonce, _newMinorProtocolVersion);
        }

        _verifyFactoryDeps(_l2ProtocolUpgradeTx.factoryDeps);

        bytes32 l2ProtocolUpgradeTxHash = keccak256(encodedTransaction);

        s.l2SystemContractsUpgradeTxHash = l2ProtocolUpgradeTxHash;

        return l2ProtocolUpgradeTxHash;
    }

    /// @notice Verifies that the factory deps provided are in the correct format
    /// @param _hashes The list of hashes of factory deps
    /// @dev Note, that unlike normal L1->L2 transactions, factory dependencies for
    /// an upgrade transaction should be made available prior to the upgrade via publishing those
    /// to the `BytecodesSupplier` contract.
    function _verifyFactoryDeps(uint256[] calldata _hashes) private pure {
        if (_hashes.length > MAX_NEW_FACTORY_DEPS) {
            revert TooManyFactoryDeps();
        }
    }

    /// @notice Changes the protocol version
    /// @param _newProtocolVersion The new protocol version
    function _setNewProtocolVersion(
        uint256 _newProtocolVersion
    ) internal virtual returns (uint32 newMinorVersion, bool patchOnly) {
        uint256 previousProtocolVersion = s.protocolVersion;
        if (_newProtocolVersion <= previousProtocolVersion) {
            revert ProtocolVersionTooSmall();
        }
        // slither-disable-next-line unused-return
        (uint32 previousMajorVersion, uint32 previousMinorVersion, ) = SemVer.unpackSemVer(
            SafeCast.toUint96(previousProtocolVersion)
        );
        if (previousMajorVersion != 0) {
            revert PreviousProtocolMajorVersionNotZero();
        }

        uint32 newMajorVersion;
        // slither-disable-next-line unused-return
        (newMajorVersion, newMinorVersion, ) = SemVer.unpackSemVer(SafeCast.toUint96(_newProtocolVersion));
        if (newMajorVersion != 0) {
            revert NewProtocolMajorVersionNotZero();
        }

        // Since `_newProtocolVersion > previousProtocolVersion`, and both old and new major version is 0,
        // the difference between minor versions is >= 0.
        uint256 minorDelta = newMinorVersion - previousMinorVersion;

        if (minorDelta == 0) {
            patchOnly = true;
        }

        // While this is implicitly enforced by other checks above, we still double check just in case
        if (minorDelta > MAX_ALLOWED_MINOR_VERSION_DELTA) {
            revert ProtocolVersionMinorDeltaTooBig(MAX_ALLOWED_MINOR_VERSION_DELTA, minorDelta);
        }

        // If the minor version changes also, we need to ensure that the previous upgrade has been finalized.
        // In case the minor version does not change, we permit to keep the old upgrade transaction in the system, but it
        // must be ensured in the other parts of the upgrade that the upgrade transaction is not overridden.
        if (!patchOnly) {
            // If the previous upgrade had an L2 system upgrade transaction, we require that it is finalized.
            // Note it is important to keep this check, as otherwise ZK chains might skip upgrades by overwriting
            if (s.l2SystemContractsUpgradeTxHash != bytes32(0)) {
                revert PreviousUpgradeNotFinalized(s.l2SystemContractsUpgradeTxHash);
            }
            if (s.l2SystemContractsUpgradeBatchNumber != 0) {
                revert PreviousUpgradeNotCleaned();
            }
        }

        s.protocolVersion = _newProtocolVersion;
        emit NewProtocolVersion(previousProtocolVersion, _newProtocolVersion);
    }

    /// @notice Placeholder function for custom logic for upgrading L1 contract.
    /// Typically this function will never be used.
    /// @param _customCallDataForUpgrade Custom data for an upgrade, which may be interpreted differently for each
    /// upgrade.
    function _upgradeL1Contract(bytes calldata _customCallDataForUpgrade) internal virtual {}

    /// @notice placeholder function for custom logic for post-upgrade logic.
    /// Typically this function will never be used.
    /// @param _customCallDataForUpgrade Custom data for an upgrade, which may be interpreted differently for each
    /// upgrade.
    function _postUpgrade(bytes calldata _customCallDataForUpgrade) internal virtual {}
}
