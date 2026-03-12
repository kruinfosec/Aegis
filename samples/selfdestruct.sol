// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Aegis Sample Contract: Unprotected Selfdestruct
 * ------------------------------------------------
 * This contract is INTENTIONALLY VULNERABLE for educational purposes.
 * The kill() function can be called by ANYONE — there is no owner check,
 * no modifier, and no require(). A single transaction destroys the
 * contract permanently and drains all ETH to the attacker.
 *
 * This is a CRITICAL severity vulnerability.
 */
contract VulnerableWallet {
    mapping(address => uint256) public balances;

    event Deposited(address indexed from, uint256 amount);

    // Anyone can deposit ETH
    function deposit() external payable {
        require(msg.value > 0, "Send ETH");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // ⚠️ CRITICAL: No access control — any address can call this!
    // One transaction destroys the contract AND sends all ETH to attacker.
    function kill() external {
        selfdestruct(payable(msg.sender));
    }

    // ⚠️ CRITICAL: Another pattern — passing an attacker-controlled address
    function destroy(address payable target) external {
        selfdestruct(target);
    }
}
