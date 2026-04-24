// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ProtectedToken {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
