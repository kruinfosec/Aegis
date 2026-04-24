// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Aegis Sample Contract: Timestamp Runtime Negative
 * ------------------------------------------------
 * This helper uses block.timestamp in a view-only staleness check.
 * The static detector should still notice it, but runtime validation
 * should not overstate it as a confirmed exploit.
 */
contract MetadataWindow {
    uint256 public lastRefresh;

    constructor() {
        lastRefresh = block.timestamp;
    }

    function isRefreshWindowOpen() external view returns (bool) {
        if (block.timestamp > lastRefresh + 1 days) {
            return true;
        }
        return false;
    }
}
