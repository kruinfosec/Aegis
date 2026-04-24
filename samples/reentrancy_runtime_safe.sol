// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Aegis Sample Contract: CEI-safe with Post-call Bookkeeping
 * -----------------------------------------------------------
 * This contract follows Checks-Effects-Interactions on the critical
 * balance, but has a harmless post-call event counter update.
 *
 * The static detector will flag the state update (withdrawCount++)
 * after the .call{value:} as a reentrancy risk.  However, the balance
 * is zeroed BEFORE the call, so a re-entrant withdraw() will fail on
 * the require(balances[msg.sender] >= amount) check.
 *
 * Runtime validation should classify this as NOT_CONFIRMED because
 * the attacker's re-entrant withdraw() call will revert.
 *
 * Uses ^0.7.0 pragma for compilation compatibility.
 */
contract SafeBankWithBookkeeping {
    mapping(address => uint256) public balances;
    uint256 public withdrawCount;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Effect: balance zeroed BEFORE call (safe).
        balances[msg.sender] -= amount;

        // Interaction: external call.
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // Post-call bookkeeping: harmless, but triggers static detector.
        withdrawCount++;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
