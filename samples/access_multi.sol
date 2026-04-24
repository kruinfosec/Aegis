// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ProtectedMintToken {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }
}

contract ExposedMintToken {
    mapping(address => uint256) public balances;

    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }
}
