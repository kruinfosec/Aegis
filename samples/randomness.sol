// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Aegis Sample Contract: Weak Randomness Vulnerability
 * -----------------------------------------------------
 * This contract is INTENTIONALLY VULNERABLE for educational purposes.
 * It uses block properties as a source of "randomness" — which miners
 * can influence or predict to win the lottery every time.
 *
 * VULNERABILITY: block.timestamp, block.number, and blockhash are
 * all predictable or manipulable. This is not true randomness.
 *
 * Real-world example: Multiple DeFi lottery contracts have been
 * exploited this way. Always use Chainlink VRF for randomness.
 */
contract WeakLottery {
    address public owner;
    address[] public players;
    uint256 public ticketPrice = 0.01 ether;

    event Winner(address indexed player, uint256 prize);

    constructor() {
        owner = msg.sender;
    }

    // Anyone can buy a ticket
    function buyTicket() external payable {
        require(msg.value == ticketPrice, "Wrong ticket price");
        players.push(msg.sender);
    }

    // ⚠️ VULNERABLE: uses block.timestamp as randomness source
    // A miner can time when they mine this block to pick a favorable timestamp
    function pickWinner() external {
        require(players.length > 0, "No players");
        require(msg.sender == owner, "Not owner");

        // ⚠️ DANGER: block.timestamp is known to miners before block is mined
        uint256 randomIndex = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.number, players.length))
        ) % players.length;

        address winner = players[randomIndex];
        uint256 prize = address(this).balance;

        // Reset
        delete players;

        // Send prize
        (bool sent, ) = payable(winner).call{value: prize}("");
        require(sent, "Transfer failed");

        emit Winner(winner, prize);
    }

    // ⚠️ VULNERABLE: another pattern using blockhash + block.number
    function quickRandom() external view returns (uint256) {
        return uint256(blockhash(block.number - 1)) % 100;
    }
}
