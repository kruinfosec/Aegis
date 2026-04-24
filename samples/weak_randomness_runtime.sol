// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PredictableLottery {
    address[] public players;
    uint256 public ticketPrice = 1 ether;
    address public lastWinner;

    function buyTicket() external payable {
        require(msg.value == ticketPrice, "Wrong ticket price");
        players.push(msg.sender);
    }

    function draw() external {
        require(players.length >= 2, "Need players");

        uint256 randomIndex = block.timestamp % players.length;
        lastWinner = players[randomIndex];

        uint256 prize = address(this).balance;
        (bool sent, ) = payable(lastWinner).call{value: prize}("");
        require(sent, "Transfer failed");

        delete players;
    }
}
