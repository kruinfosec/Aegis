// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/**
 * Aegis Sample Contract: Safe Token with Overflow Guards
 * -------------------------------------------------------
 * This contract uses Solidity < 0.8.0 BUT has explicit require()
 * guards that prevent integer overflow/underflow.
 *
 * Used as a NEGATIVE test case: Aegis's static detector should
 * flag arithmetic in pre-0.8 code, but runtime validation should
 * NOT confirm overflow because the guards prevent it.
 */
contract SafeToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;

    constructor(uint256 initialSupply) public {
        owner = msg.sender;
        totalSupply = initialSupply;
        balances[msg.sender] = initialSupply;
    }

    // Guarded: require prevents underflow
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    // Guarded: require prevents overflow
    function addReward(address user, uint256 reward) public {
        require(msg.sender == owner, "Not owner");
        require(balances[user] + reward >= balances[user], "Overflow check");
        balances[user] += reward;
        totalSupply += reward;
    }

    // Guarded: explicit overflow check on multiplication
    function bulkTransfer(address to, uint256 unitAmount, uint256 units) public {
        require(units == 0 || unitAmount <= type(uint256).max / units, "Mul overflow");
        uint256 totalAmount = unitAmount * units;
        require(balances[msg.sender] >= totalAmount, "Not enough");
        balances[msg.sender] -= totalAmount;
        balances[to] += totalAmount;
    }
}
