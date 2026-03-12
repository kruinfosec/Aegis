// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Aegis Sample Contract: Delegatecall to Untrusted Contract
 * ---------------------------------------------------------
 * This contract uses delegatecall with a target address that is 
 * provided by the user. An attacker can set the target to their 
 * own malicious contract and take over this contract's state or drain it.
 *
 * Severity: HIGH
 */
contract ProxyVulnerable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // ⚠️ HIGH: Delegatecall target is user-controlled
    function executeLogic(address target, bytes memory data) public payable {
        // delegatecall executes code from 'target' within the context of THIS contract.
        // It can modify state variables like 'owner' if the attacker provides a malicious payload.
        (bool success, ) = target.delegatecall(data);
        require(success, "Execution failed");
    }
}
