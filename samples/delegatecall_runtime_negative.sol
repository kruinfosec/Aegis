// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Aegis Sample Contract: Admin-Gated Delegatecall
 * ------------------------------------------------
 * This contract accepts a user-supplied delegatecall target (so the
 * static detector flags it as HIGH severity / user-controlled), but
 * the call is protected by an onlyOwner modifier.
 *
 * Runtime validation should classify this as NOT_CONFIRMED because an
 * unauthorized caller cannot reach the delegatecall path.
 *
 * Purpose: Negative / non-confirming delegatecall fixture for runtime
 * validation testing.
 */
contract AdminGatedProxy {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // Static detector flags this as "Delegatecall to Untrusted Contract"
    // because the target is user-controlled (a function parameter).
    // But the onlyOwner modifier blocks unauthorized callers at runtime.
    function executeLogic(address target, bytes memory data) public onlyOwner {
        (bool success, ) = target.delegatecall(data);
        require(success, "Execution failed");
    }
}
