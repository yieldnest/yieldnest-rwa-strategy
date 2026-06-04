// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IERC20Metadata} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ISablierFlow, UD21x18} from "@src/interfaces/sablier/ISablierFlow.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {Prompt} from "@script/utils/Prompt.sol";

/// @notice Prints the state of a Sablier Flow stream.
/// @dev Usage:
///      forge script script/commands/PrintFlowState.s.sol:PrintFlowState --rpc-url <RPC_URL>
contract PrintFlowState is Script {
    function run() external {
        uint256 streamId = Prompt.forUint("Stream ID");
        _run(streamId, MainnetKeeperContracts.SABLIER_FLOW);
    }

    function _run(uint256 streamId, address flowAddress) internal view {
        ISablierFlow flow = ISablierFlow(flowAddress);

        console2.log("flow", flowAddress);
        console2.log("streamId", streamId);

        bool exists = flow.isStream(streamId);
        console2.log("exists", exists);

        if (!exists) {
            return;
        }

        _printIdentity(flow, streamId);
        _printStatus(flow, streamId);
        _printDebt(flow, streamId);
    }

    function _printIdentity(ISablierFlow flow, uint256 streamId) internal view {
        IERC20Metadata token = IERC20Metadata(address(flow.getToken(streamId)));
        console2.log("sender", flow.getSender(streamId));
        console2.log("recipient", flow.getRecipient(streamId));
        console2.log("token", address(token));
        console2.log("tokenSymbol", token.symbol());
        console2.log("tokenDecimals", flow.getTokenDecimals(streamId));
    }

    function _printStatus(ISablierFlow flow, uint256 streamId) internal view {
        console2.log("balance", uint256(flow.getBalance(streamId)));
        console2.log("ratePerSecond", uint256(UD21x18.unwrap(flow.getRatePerSecond(streamId))));
        console2.log("snapshotTime", uint256(flow.getSnapshotTime(streamId)));
        try flow.isPaused(streamId) returns (bool paused) {
            console2.log("paused", paused);
        } catch {
            _logUnavailable("paused");
        }
        try flow.isVoided(streamId) returns (bool voided) {
            console2.log("voided", voided);
        } catch {
            _logUnavailable("voided");
        }
        try flow.isTransferable(streamId) returns (bool transferable) {
            console2.log("transferable", transferable);
        } catch {
            _logUnavailable("transferable");
        }
    }

    function _printDebt(ISablierFlow flow, uint256 streamId) internal view {
        try flow.coveredDebtOf(streamId) returns (uint128 coveredDebt) {
            console2.log("coveredDebt", uint256(coveredDebt));
        } catch {
            _logUnavailable("coveredDebt");
        }
        try flow.uncoveredDebtOf(streamId) returns (uint256 uncoveredDebt) {
            console2.log("uncoveredDebt", uncoveredDebt);
        } catch {
            _logUnavailable("uncoveredDebt");
        }
        try flow.totalDebtOf(streamId) returns (uint256 totalDebt) {
            console2.log("totalDebt", totalDebt);
        } catch {
            _logUnavailable("totalDebt");
        }
        try flow.withdrawableAmountOf(streamId) returns (uint128 withdrawable) {
            console2.log("withdrawable", uint256(withdrawable));
        } catch {
            _logUnavailable("withdrawable");
        }
        try flow.refundableAmountOf(streamId) returns (uint128 refundable) {
            console2.log("refundable", uint256(refundable));
        } catch {
            _logUnavailable("refundable");
        }
        try flow.ongoingDebtScaledOf(streamId) returns (uint256 ongoingDebtScaled) {
            console2.log("ongoingDebtScaled", ongoingDebtScaled);
        } catch {
            _logUnavailable("ongoingDebtScaled");
        }
        try flow.depletionTimeOf(streamId) returns (uint256 depletionTime) {
            console2.log("depletionTime", depletionTime);
        } catch {
            _logUnavailable("depletionTime");
        }
    }

    function _logUnavailable(string memory label) internal pure {
        console2.log(string.concat(label, " unavailable"));
    }
}
