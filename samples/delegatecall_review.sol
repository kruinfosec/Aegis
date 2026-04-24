// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UpgradeableExecutor {
    address public owner;
    address public implementation;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address initialImplementation) {
        owner = msg.sender;
        implementation = initialImplementation;
    }

    function setImplementation(address newImplementation) external onlyOwner {
        implementation = newImplementation;
    }

    function execute(bytes memory data) external onlyOwner {
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Execution failed");
    }
}
