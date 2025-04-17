// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts@4.9.5/access/Ownable.sol";
import {AccessControl} from "@openzeppelin/contracts@4.9.5/access/AccessControl.sol";
import {AlreadyWhitelisted, InvalidSelector, NonEmptyCalldata, NotWhitelisted, ZeroAddress} from "../common/L1ContractErrors.sol";
import {ITransactionFilterer} from "../state-transition/chain-interfaces/ITransactionFilterer.sol";

/**
 * @title Minimal interface for an NFT asset contract with Ownable
 */
interface INFTAsset {
    function owner() external view returns (address);
    function balanceOf(address owner) external view returns (uint256);
}

/**
 * @title AccessControlledTransactionFilterer
 * @notice Allows transactions based on admin role or NFT ownership + L2 bridge address
 */
contract AccessControlledTransactionFilterer is ITransactionFilterer, AccessControl, Ownable {
    INFTAsset public nftAsset;
    // address public l2BridgeAddress;
    address public immutable L1_ASSET_ROUTER;

    /**
     * This contant is created based on the old finalizeDeposit function in L2 -
     * https://github.com/matter-labs/era-contracts/blob/352e0dd70ca0740ac191ea7d04a9cef9606aa521/l1-contracts/contracts/bridge/asset-router/L2AssetRouter.sol#L244
     * @dev This function is called on the L2 when a deposit is initiated from L1
     */
    bytes4 constant FINALIZE_DEPOSIT_SELECTOR_L2 = bytes4(keccak256("finalizeDeposit(address,address,address,uint256,bytes)"));

    event NFTAssetUpdated(address indexed oldAddress, address indexed newAddress);
    // event L2BridgeAddressUpdated(address indexed oldAddress, address indexed newAddress);
    event TransactionChecked(address indexed sender, bool allowed);

    /**
     * @dev Sets initial config and grants admin role to deployer
     * @param _l1AssetRouter Address of the L1 Asset Router contract
     * @param _nftAssetAddress Address of the NFT Asset contract
     */
    constructor(address _l1AssetRouter, address _nftAssetAddress) {
        require(_l1AssetRouter != address(0), "Invalid L1 Asset Router address");
        require(_nftAssetAddress != address(0), "Invalid NFT Asset address");
        // require(_l2BridgeAddress != address(0), "Invalid L2 Bridge address");

        L1_ASSET_ROUTER = _l1AssetRouter;
        nftAsset = INFTAsset(_nftAssetAddress);
        // l2BridgeAddress = _l2BridgeAddress;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Admin-only function to update the NFT asset contract address
     * @param nftAssetAddress New NFT asset contract address
     */
    function setNFTAsset(address nftAssetAddress) external onlyOwner() {
        if (nftAssetAddress == address(0)) {
            revert ZeroAddress();
        }
        address old = address(nftAsset);
        nftAsset = INFTAsset(nftAssetAddress);
        emit NFTAssetUpdated(old, nftAssetAddress);
    }

    /**
     * @notice Checks whether a transaction should be allowed to proceed to L2.
     * 
     * @dev The function enforces access control for L2 bridge transactions based on:
     *  - The sender's role (admin or NFT holder)
     *  - The L1 sender encoded in the `l2Calldata`
     *  - The transaction type (token bridge or base ETH)
     * 
     * Rules:
     * 1. If `sender == L1_ASSET_ROUTER` (i.e., a token bridge):
     *    - The `l2Calldata` must start with the `finalizeDeposit(address,address,address,uint256,bytes)` selector
     *    - The `l1Sender` decoded from calldata must be:
     *        - An admin (granted `DEFAULT_ADMIN_ROLE`), or
     *        - The owner of the NFT, or hold at least 1 NFT
     *    - The `_l1Token` address must not be zero
     * 
     * 2. If `sender != L1_ASSET_ROUTER` (i.e., base ETH deposit):
     *    - The sender must either be an admin or a valid NFT owner
     *    - The `l2Calldata` must be empty
     *
     * @param sender The address initiating the L1 → L2 transaction
     * @param l2Calldata The calldata to be sent to the L2 contract
     * @return `true` if the transaction is allowed to proceed, otherwise `false`
     */
    function isTransactionAllowed(
        address sender,
        address /* contractL2 */,
        uint256 /* mintValue */,
        uint256 /* l2Value */,
        bytes calldata l2Calldata,
        address /* refundRecipient */
    ) external view override returns (bool) {

        if (sender == L1_ASSET_ROUTER) {
        // This case is for token transfer

            bytes4 l2TxSelector = bytes4(l2Calldata[:4]);
            (address l1Sender, , address l1Token, ,) = abi.decode(l2Calldata[4:], (address, address, address, uint256, bytes));

            // All calls are allowed to the DEFAULT_ADMIN_ROLE
            if (hasRole(DEFAULT_ADMIN_ROLE, l1Sender)) {
                return true;
            }

            // Check for function signature to equal legacy finalizeDeposit functions. modern `finalizeDeposit` and `finalizeDepositLegacyBridge` will not work.
            if (l2TxSelector != FINALIZE_DEPOSIT_SELECTOR_L2) {
                revert InvalidSelector(l2TxSelector);
            }
            if (l1Token == address(0)) {
                revert ZeroAddress();
            }
            // If the call is initiated by NFT owners or NFT contract owner
            if (nftAsset.owner() == l1Sender || nftAsset.balanceOf(l1Sender) > 0) {
                return true;
            }
        } else {
        // This tx is for base ETH token transfer

            // All calls are allowed to the DEFAULT_ADMIN_ROLE
            if (hasRole(DEFAULT_ADMIN_ROLE, sender)) {
                return true;
            }

            if (l2Calldata.length != 0) {
                revert NonEmptyCalldata();
            }
            // If the call is initiated by NFT owners or NFT contract owner
            if (nftAsset.owner() == sender || nftAsset.balanceOf(sender) > 0) {
                return true;
            }
        }

        return false;
    }
}
