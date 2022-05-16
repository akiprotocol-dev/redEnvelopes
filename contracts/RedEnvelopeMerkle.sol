// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

import "./IEnvelope.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract RedEnvelopeMerkle is IEnvelope {
    using Bits for uint8;

    mapping(string => MerkleEnvelope) private idToEnvelopes;

    function returnEnvelope(string calldata envelopeID) public {
        MerkleEnvelope storage env = idToEnvelopes[envelopeID];
        require(env.balance > 0, "Balance should be larger than zero");
        require(env.creator == msg.sender, "We will only return to the creator!");
        address payable receiver = payable(env.creator);
        receiver.call{value: env.balance}("");
    }

    function addEnvelope(
        string calldata envelopeID,
        uint16 numParticipants,
        uint256 minPerOpen,
        bytes32 hashedMerkelRoot,
        uint32 bitarraySize
    ) payable public {
        require(idToEnvelopes[envelopeID].balance == 0, "balance not zero");
        require(msg.value > 0, "Trying to create zero balance envelope");
        validateMinPerOpen(msg.value, minPerOpen, numParticipants);

        MerkleEnvelope storage envelope = idToEnvelopes[envelopeID];
        envelope.minPerOpen = minPerOpen;
        envelope.numParticipants = numParticipants;
        envelope.creator = msg.sender;
        envelope.unclaimedPasswords = hashedMerkelRoot;
        envelope.balance = msg.value;
        envelope.isPasswordClaimed = new uint8[](bitarraySize/8 + 1);
    }


    function openEnvelope(
        address payable receiver,
        string calldata envelopeID,
        bytes32[] memory proof,
        bytes32 leaf
    ) public {
        require(idToEnvelopes[envelopeID].balance > 0, "Envelope cannot be empty");
        MerkleEnvelope storage currentEnv = idToEnvelopes[envelopeID];

        // First check if the password has been claimed
        uint256 bitarrayLen = currentEnv.isPasswordClaimed.length;
        uint32 idx = uint32(uint256(leaf) % bitarrayLen);
        uint32 bitsetIdx = idx / 8;
        uint8 positionInBitset = uint8(idx % 8);
        uint8 curBitSet = currentEnv.isPasswordClaimed[bitsetIdx];
        uint8 contains = curBitSet.bit(positionInBitset);
        require(contains == 0, "password already used!");

        // Now check if it is a valid password
        bool isUnclaimed = MerkleProof.verify(proof, currentEnv.unclaimedPasswords, leaf);
        require(isUnclaimed, "password need to be valid!");

        // claim the password
        currentEnv.isPasswordClaimed[bitsetIdx].setBit(positionInBitset);

        // currently withdrawl the full balance, turn this into something either true random or psuedorandom
        if (currentEnv.numParticipants == 1) {
            receiver.call{value: currentEnv.balance}("");
            currentEnv.balance = 0;
            return;
        }

        uint256 moneyThisOpen = getMoneyThisOpen(
            receiver,
            currentEnv.balance,
            currentEnv.minPerOpen,
            currentEnv.numParticipants);
        
        currentEnv.numParticipants--;
        receiver.call{value: moneyThisOpen}("");
        currentEnv.balance -= moneyThisOpen;
    }
}