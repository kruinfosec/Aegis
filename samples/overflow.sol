// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/**
 * Aegis Sample Contract: Integer Overflow / Underflow Vulnerability
 * -----------------------------------------------------------------
 * This contract is INTENTIONALLY VULNERABLE for educational purposes.
 * Solidity < 0.8.0 does NOT have built-in overflow protection.
 *
 * VULNERABILITY: Arithmetic operations on uint types can silently
 * wrap around. uint8 max is 255 — adding 1 gives 0 (overflow).
 * Similarly, subtracting from 0 gives 255 (underflow).
 *
 * An attacker can exploit this to mint unlimited tokens or bypass
 * balance checks.
 */
contract VulnerableToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        totalSupply = initialSupply;
        balances[msg.sender] = initialSupply;
    }

    // ⚠️ VULNERABLE: No SafeMath, no overflow protection
    function transfer(address to, uint256 amount) public {
        // If balances[msg.sender] < amount, this underflows to a huge number!
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    // ⚠️ VULNERABLE: Overflow in reward calculation
    function addReward(address user, uint256 reward) public {
        require(msg.sender == owner, "Not owner");
        // If balances[user] is near max uint256, this overflows to 0
        balances[user] += reward;
        totalSupply += reward;
    }

    // ⚠️ VULNERABLE: Multiplication overflow
    function bulkTransfer(address to, uint256 unitAmount, uint256 units) public {
        uint256 totalAmount = unitAmount * units; // can overflow!
        require(balances[msg.sender] >= totalAmount, "Not enough");
        balances[msg.sender] -= totalAmount;
        balances[to] += totalAmount;
    }
}
