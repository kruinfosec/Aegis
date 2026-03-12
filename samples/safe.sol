// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Aegis Sample Contract: SAFE Contract (No Vulnerabilities)
 * ----------------------------------------------------------
 * This contract demonstrates security best practices.
 * Aegis should report ZERO vulnerabilities for this file.
 *
 * Good Practices Used:
 *  - Solidity 0.8.x (built-in overflow protection)
 *  - Checks-Effects-Interactions pattern (no reentrancy)
 *  - msg.sender for auth (not tx.origin)
 *  - onlyOwner guard on sensitive functions
 *  - No selfdestruct
 */
contract SafeVault {
    mapping(address => uint256) private balances;
    address private owner;
    bool private locked; // Reentrancy guard

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier noReentrant() {
        require(!locked, "Reentrant call blocked");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    // Safe deposit: just update state
    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // Safe withdraw: Checks-Effects-Interactions + noReentrant
    function withdraw(uint256 amount) external noReentrant {
        require(amount > 0, "Amount must be positive");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ✅ EFFECT: Update state BEFORE external call
        balances[msg.sender] -= amount;

        // ✅ INTERACTION: External call AFTER state is updated
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    // Safe balance query
    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }

    // Owner-only emergency function (no selfdestruct)
    function emergencyWithdraw() external onlyOwner noReentrant {
        uint256 amount = address(this).balance;
        (bool success, ) = payable(owner).call{value: amount}("");
        require(success, "Withdrawal failed");
    }
}
