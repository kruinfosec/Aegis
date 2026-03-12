// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Aegis Sample Contract: Missing Access Control
 * ------------------------------------------------
 * This contract modifies critical state variables but fails to 
 * restrict who can call the functions. Anyone can mint tokens 
 * or change the owner.
 *
 * Severity: HIGH
 */
contract UnprotectedToken {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // ⚠️ HIGH: Missing access control modifier. Anyone can mint tokens.
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }

    // ⚠️ HIGH: Missing access control modifier. Anyone can take ownership.
    function transferOwnership(address newOwner) public {
        owner = newOwner;
    }

    // ⚙️ Safe example: This function has access control explicitly added
    function withdrawAdminFees() public {
        require(msg.sender == owner, "Not authorized");
        // withdraw logic...
    }
}
