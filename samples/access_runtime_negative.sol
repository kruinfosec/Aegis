// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract HelperProtectedToken {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) public {
        _requireOwner();
        balances[to] += amount;
    }

    function transferOwnership(address newOwner) public {
        _requireOwner();
        owner = newOwner;
    }

    function _requireOwner() internal view {
        require(msg.sender == owner, "Not owner");
    }
}
