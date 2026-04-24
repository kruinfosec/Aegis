// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeDelegateExecutor {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function execute(bytes memory data) external onlyOwner {
        (bool success, ) = address(0x1234567890123456789012345678901234567890).delegatecall(data);
        require(success, "Execution failed");
    }
}
