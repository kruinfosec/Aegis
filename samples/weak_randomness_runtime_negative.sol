// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RandomnessPreview {
    function previewNonce() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.number))) % 100;
    }
}
