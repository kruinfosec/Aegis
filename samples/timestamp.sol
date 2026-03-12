// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Aegis Sample Contract: Timestamp Dependence
 * ------------------------------------------------
 * This game incorrectly uses block.timestamp (now) 
 * for critical logic. Miners can manipulate the timestamp
 * to win the game or bypass the logic.
 *
 * Severity: LOW/MEDIUM
 */
contract RouletteGame {
    uint public pastBlockTime; 

    // ⚠️ LOW: Using timestamp for critical randomness/logic
    function spin() public payable {
        require(msg.value == 1 ether, "Requires exactly 1 ether to play");
        
        // Block timestamp should not be used for random generation
        if(block.timestamp % 15 == 0) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }

    // ⚠️ LOW: Using block.timestamp sequentially in conditions without safety margin
    function isWinningTime() public view returns (bool) {
        if(block.timestamp > pastBlockTime + 1 hours) {
            return true;
        }
        return false;
    }
}
