// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * Aegis Sample Contract: Reentrancy Vulnerability
 * ------------------------------------------------
 * This contract is INTENTIONALLY VULNERABLE for educational purposes.
 * It demonstrates a classic reentrancy attack pattern.
 *
 * VULNERABILITY: The withdraw() function sends ETH via .call{value:}()
 * BEFORE updating the sender's balance. An attacker contract can
 * recursively call withdraw() to drain all ETH from this contract.
 *
 * This is similar to the 2016 DAO hack ($60M lost).
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    // Users can deposit ETH
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: External call happens BEFORE state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ⚠️ DANGER: Sending ETH BEFORE updating balance
        // An attacker's fallback function can call withdraw() again
        // before balances[msg.sender] is set to 0
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens TOO LATE
        balances[msg.sender] -= amount;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
